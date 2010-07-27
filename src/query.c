/*
 * $Id$
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h> 
#include <string.h> 
#include <unistd.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <sys/socket.h>
#include <sys/wait.h>
#include <sysexits.h>

#include "sdig.h"
#include "common.h"
#include "snmpget.h"

char
*findmac_at_rtr_ip(const char *ip, const char *rtr_ip, rtype *rtr)
{
	char	query[256], *ret;
	int	ifnum, eqcheck;

	debug(2, "\n\nfindmac_at_rtr_ip: [%s] [%s] [%s] [%s]\n", ip, rtr_ip, rtr->ip, rtr->pw);

	/* find the router's internal interface number */

	snprintf(query, sizeof(query),
		"IP-MIB::ipAdEntIfIndex.%s", rtr_ip);

	ifnum = snmpget_int(rtr->ip, rtr->pw, query);

	if (ifnum == -1)
		return NULL;

	debug(6, "router interface number for %s is %d\n",
		rtr_ip, ifnum);

	/* now look it up in the net to media table relative to the ifnum */

	/* if digging the router itself, use a different OID */

	eqcheck = strcmp(ip, rtr_ip);
	if (!eqcheck)
		snprintf(query, sizeof(query), 
			"interfaces.ifTable.ifEntry.ifPhysAddress.%d",
			ifnum);
	else
		snprintf(query, sizeof(query), 
		"ip.ipNetToMediaTable.ipNetToMediaEntry.ipNetToMediaPhysAddress.%d.%s",
		ifnum, ip);

	ret = snmpget_mac(rtr->ip, rtr->pw, query);

	if (!ret && eqcheck) {
// Avaya's have offset OIDs by 1 (maybe VLAN ID reservation?), i.e.
// RFC1213-MIB::atPhysAddress.1.1.192.168.42.4 = Hex-STRING: 00 1B 4F 0C 79 E1 
		snprintf(query, sizeof(query), 
		"ip.ipNetToMediaTable.ipNetToMediaEntry.ipNetToMediaPhysAddress.%d.1.%s",
		ifnum, ip);

		ret = snmpget_mac(rtr->ip, rtr->pw, query);
	}

        return ret;
}

char 
*findmac(const char *ip, rtype *rtr)
{
	char	query[256], *ret;
	int	ifnum;

	debug(2, "\n\nfindmac: [%s] [%s] [%s]\n", ip, rtr->ip, rtr->pw);

	/* find the router's internal interface number */
	ifnum = -1;
	ret = NULL;

	if (rtr->rtrip) {
		/* we have a user-configured rtr_ip */

		debug(2, "\n\nfindmac: an rtr->rtrip is known as [%s]\n", rtr->rtrip);

		ret = findmac_at_rtr_ip(ip, rtr->rtrip, rtr);
		if ( ret ) {
			return ret;
		}
	}

	if ( (!ret) ) {
		/* an rtr_ip is not previously known, or the known one
		   doesn't work */

		/* for backward compatibility (sdig-0.43 and before),
		   try rtr->ip address (now intended for SNMP contacts) */
		ret = findmac_at_rtr_ip(ip, rtr->ip, rtr);
		if ( ret ) {
			/* Match on first sight! */
			if (rtr->rtrip == NULL) {
				rtr->rtrip = xstrdup(rtr->ip);
			}

	    		return ret;
		};

		if ( !ret ) {
		    /* router's contact IP maybe not in the seeked subnet */
		    /* User may have configured an explicit rtr->rtrip address
		    in the desired subnet; otherwise we'll try to find it
		    and set rtrip value */

		    /* This snmpwalking is a TODO for sdig-0.46 */

			ret = NULL;
		}
	}

	if ( (!ret) ) {
		debug(2, "\n\nfindmac: failed to find a router IP\n");
		return NULL;
	}

	return ret;
}


int
findport(unsigned const char *mac, stype *sw)
{
	char	query[64];

	if (sw->ip == NULL) {
		printf("No switch defined for that network\n");
		exit(1);
	}

	/* build the OID for the mapping of MAC addresses to port numbers */

	snprintf(query, sizeof(query), "SNMPv2-SMI::mib-2.17.4.3.1.2.%u.%u.%u.%u.%u.%u",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	debug(4, "findport: snmpget_int(%s, %s, %s)\n",
		sw->ip, sw->pw, query);

	return snmpget_int(sw->ip, sw->pw, query);
}

char
*getlink(const char *ip, long port)
{
	litype	*tmp;

	tmp = firstli;

	while (tmp) {
		if ((!strcmp(tmp->ip, ip)) && (tmp->port == port))
			return tmp->desc;

		tmp = tmp->next;
	}

	return NULL;
}

char
*getdesc(const char *ip, long port)
{
	pdtype	*tmp;

	tmp = firstpd;

	while (tmp) {
		if ((!strcmp(tmp->ip, ip)) && (tmp->port == port))
			return tmp->desc;

		tmp = tmp->next;
	}

	return NULL;
}

const char
*macmfr(unsigned char *inmac)
{
	FILE	*macdb;
	char	buf[256], *tmp, macfind[16];
	int	i;

	macdb = fopen(mactable, "r");
	if (!macdb)
		return "MAC table file not available";

	/* rewrite the MAC address into something that'll match the table */

	snprintf(macfind, sizeof(macfind), "%02x %02x %02x", 
		inmac[0], inmac[1], inmac[2]);

	while (fgets(buf, sizeof(buf), macdb)) {
		buf[strlen(buf) - 1] = '\0';

		if (!strncasecmp(buf, macfind, 8)) {
			tmp = xstrdup(&buf[9]);
			for (i = strlen(tmp) - 1; i >= 0; i--) {
				if (!isspace(tmp[i])) {
					tmp[i+1] = '\0';
					return tmp;
				}
			}
			return tmp;
		}
	}

	fclose(macdb);
	return "Not available";
}

char
*wins_resolve(const char *host)
{
	char	exec[256], buf[256];
	FILE	*wq;

	if (!wins) {
		fprintf(stderr, "WINS not defined in config file!\n");
		return NULL;
	}

	if (!nmblookup) {
		fprintf(stderr, "NMBLOOKUP not defined in config file!\n");
		return NULL;
	}

	snprintf(exec, sizeof(exec), "%s -U %s -R %s | tail -1 | cut -f 1 -d \" \"",
		nmblookup, wins, host);

	debug(5, "popen: %s\n", exec);
	wq = popen(exec, "r");

	fgets(buf, sizeof(buf), wq);
	pclose(wq);

	buf[strlen(buf) - 1] = '\0';
	debug(7, "read [%s]\n", buf);
	if (!strcmp(buf, "name_query")) {
		fprintf(stderr, "WINS lookup failed\n");
		exit(1);
	}

	printf("  Address: %s (WINS)\n", buf);

	return(xstrdup(buf));
}

char
*dns_resolve(const char *host, int verbose)
{
	struct	hostent	*dns;
	struct	in_addr	addr;

	if ((dns = gethostbyname(host)) == (struct hostent *) NULL)
		return NULL;

	memcpy(&addr, dns->h_addr, dns->h_length);

	if ( verbose )
	   printf("  Address: %s (DNS)\n", inet_ntoa(addr));

	return(xstrdup(inet_ntoa(addr)));
}

void
do_ifdescr(stype *sw, long port)
{
	char	query[256], *ifdescr, *ifname, *ifalias;
	long	ifnum;

	/* first get the switch's ifnum for the port */
	
	snprintf(query, sizeof(query), "SNMPv2-SMI::mib-2.17.1.4.1.2.%ld", port);
	ifnum = snmpget_int(sw->ip, sw->pw, query);

	if (ifnum == -1)
		return;

	snprintf(query, sizeof(query), "IF-MIB::ifName.%ld",
		ifnum);

	ifname = snmpget_str(sw->ip, sw->pw, query);

	/* Unlike previous versions of sdig, we always want an ifAlias:
	   "name" and "desc" fields are nearly the same and almost useless
	   on Cisco Catalyst and HP switches (ifDesc doesn't reflect the
	   switch manager's decription in the switch config, but is just
	   the Switch OS's long version of interface name. */
	snprintf(query, sizeof(query), "IF-MIB::ifAlias.%ld",
		ifnum);

	ifalias = snmpget_str(sw->ip, sw->pw, query);

	snprintf(query, sizeof(query), "IF-MIB::ifDescr.%ld",
		ifnum);

	ifdescr = snmpget_str(sw->ip, sw->pw, query);

	if (ifname) {
		printf(" (%s)", ifname);
		free(ifname);
	}

	if (ifdescr) {
		printf(" [%s]", ifdescr);
		free(ifdescr);
	}

	if (ifalias) {
		printf(" {%s}", ifalias);
		free(ifalias);
	}
}

int
isip(const char *buf)
{
	int	i;

	for (i = 0; i < strlen(buf); i++)
		if ((!isdigit(buf[i])) && (buf[i] != '.'))
			return 0;

	return 1;
}

void
dnsreverse(const char *ip)
{
	struct	hostent	*dns;
	struct	in_addr	addr;

#if HAVE_INET_ATON
	inet_aton(ip, &addr);
#elif HAVE_INET_PTON
	inet_pton(AF_INET, ip, &addr);
#else
#error	Cannot convert address
#endif

	dns = gethostbyaddr((char *)&addr, sizeof(struct in_addr), AF_INET);

	if (dns)
		printf(" Hostname: %s (DNS)\n", dns->h_name);
}

stype
*find_switch(const char *ipaddr, stype *last)
{
	stype	*tmp, *tmpuniq;
	int	addrchk, swchk;

	if (last)
		tmp = last->next;
	else
		tmp = firstsw;

	if ( ipaddr ) {
		while (tmp) {
			/* User requested a specific host/ip */
			addrchk = ntohl(inet_addr(ipaddr)) & tmp->mask;
			swchk = tmp->addr & tmp->mask;

			if (swchk == addrchk)
				return tmp;

			tmp = tmp->next;
		}
	} else {
		/* ipaddr==NULL, check all configured switches */
		/* NOTE: may check same switch many times, i.e.
		    for Cisco Catalysts - different VLANs require
		    different community strings. */
			    
		/* Check uniquity for same switch IP x COMMUNITY */ 

		tmpuniq = firstsw;
		while (tmpuniq != tmp && tmp && tmpuniq) {
			if (
			    strcmp(tmpuniq->pw, tmp->pw) == 0 &&
			    strcmp(tmpuniq->ip, tmp->ip) == 0
			) {
			    /* an earlier switch (tmpuniq) IP x COMMUNITY
			       are the same as our current candidate (tmp)
			       Try next candidate */
				debug (6, "\nfind_switch: Any_IP mode: switch IP x COMMUNITY already checked: [%s] [%s]\n", tmp->ip, tmp->pw);
				tmp = tmp->next;
			}
			tmpuniq = tmpuniq->next;
		}

		/* Here we are. TMPUNIQ==TMP (no matches => tmp is unique)
		   or either one is null (end of list) */

		/* The caller will return soon with "tmp"
		   as next starting point */
		return tmp;
	} //if

	return NULL;
}

int fork_wrapper(unsigned const char *macaddr, stype *sw);

/* ask the switch about where the MAC address is */
void
switchscan(const char *ipaddr, unsigned const char *macaddr)
{
	stype	*sw;
	int	ret, status;

	printf("\n");
	
	if (get_debuglevel() >= 2) {
		debug(2, "switchscan: seeking (%s, ", (ipaddr?ipaddr:"Any_IP"));
		printmac(macaddr);
		printf(")\n");
	}

	sw = find_switch(ipaddr, NULL);

	while (sw) {
		debug(3, "switchscan: matched %s\n", sw->ip);
	
#ifdef SDIG_USE_SEMS
		if ( dofork ) {
			/* fflush is needed to correctly pass output
			 * from children when parent's stdout is piped
			 * to elsewhere (file, sdig.cgi wrapper, etc.)
			 * Must be done BOTH before fork and after child labor
			 */
			fflush(stdout);
			fflush(stderr);
			ret = fork();

			switch (ret) {
			case 0: /* child process */

				ret = fork_wrapper(macaddr, sw);
				// _exit(EX_OK);
				debug(3, "child %d done (%d)\n", getpid(), ret);

				fflush(stdout);
				fflush(stderr);
				_exit(ret);
				break;

			case -1:
				perror("fork");
				exit(EX_SOFTWARE);
				break;

			default: /* parent process */
				debug(3, "child %d started (%s, %s)\n", ret, sw->ip, sw->pw);
				break;
			}
		} else {
#endif
			fork_wrapper(macaddr, sw);
#ifdef SDIG_USE_SEMS
		}
#endif

		sw = find_switch(ipaddr, sw);
	}
	
#ifdef SDIG_USE_SEMS
	if ( dofork ) {
		while ((ret = wait(&status)) != -1)
			debug(3, "child %d exited (%d)\n", ret, WEXITSTATUS(status));

		output_sem_cleanup();
	}
#endif

	exit(EX_OK);
}

int
fork_wrapper(unsigned const char *macaddr, stype *sw)
{
	int port;

	port = findport(macaddr, sw);

	if (port != -1)
		printport(sw, port);

	debug(3, "findport got port %d\n", port);
	return port;
}

rtype
*find_router(const char *ipaddr, rtype *last)
{
	rtype	*tmp;
	int	addrchk, rtchk;

	if (last)
		tmp = last->next;
	else
		tmp = firstrt;

	while (tmp) {
		addrchk = ntohl(inet_addr(ipaddr)) & tmp->mask;
		rtchk = tmp->addr & tmp->mask;

		if (rtchk == addrchk)
			return tmp;

		tmp = tmp->next;
	}

	return NULL;
}

/* run the user's script for extra details about a host */
void
do_hostinfo(const char *ipaddr)
{
	char	exec[256];

	fflush(stdout);

	snprintf(exec, sizeof(exec), "%s %s", hostinfo, ipaddr);
	system(exec);
}

/* walk the list of routers checking for the IP address */
void
routerscan(const char *ipaddr)
{
	unsigned char	*macaddr;
	rtype	*rtr;

	/* spew out some additional info about the IP address */
	if (fastmode == 0) {
		dnsreverse(ipaddr);

		if (hostinfo)
			do_hostinfo(ipaddr);
	}

	printf("\n");

	debug(2, "routerscan: looking for a router for host %s\n", ipaddr);

	/* XXX: ping code for waking up sleeping/inactive hosts */

	/* find the first one that covers this network */
	rtr = find_router(ipaddr, NULL);

	while (rtr) {
		debug(3, "routerscan: matched %s\n", rtr->ip);

		/* try to find the target IP address on this router */
		macaddr = findmac(ipaddr, rtr);

		if (macaddr) {
			printf("   Router: %s - %s\n", rtr->desc, (rtr->rtrip?rtr->rtrip:rtr->ip) );

			printf("   TgtMAC: ");
			printmac(macaddr);
			printf(" (%s)\n", macmfr(macaddr));
			
			switchscan(ipaddr, macaddr);
		}

		rtr = find_router(ipaddr, rtr);
	}

	fprintf(stderr, "Error: no routers found for %s\n", ipaddr);
	exit(1);
}	

/* turn <name> into an IP address and pass it to the router scanner */
void
resolvename(const char *name)
{
	char	*ipaddr;

	/* first try DNS */
	ipaddr = dns_resolve(name, 1);

	if (ipaddr)
		routerscan(ipaddr);

	/* now try WINS */
	ipaddr = wins_resolve(name);

	if (ipaddr)
		routerscan(ipaddr);

	fprintf(stderr, "Can't resolve %s with DNS or WINS!\n", name);
	exit(1);
}

/* Different OSes and switches have several ways to write a MAC address.
   Convert some of these formats to "XX:XX:XX:XX:XX:XX" standard */
char 
*standardize_mac(char *buf)
{
	static	char	mac[256];
	char *ptr;
	char cc, cd, cp, macfmt;
	int i, j, k;

	/* First pass: count separators, determine known format */
	cc = 0;
	cd = 0;
	cp = 0;
	for (i = 0; i < strlen(buf); i++) {
		switch (buf[i]) {
		    case '-':
			/* Possibly a Windows-format MAC XX-XX-XX-XX-XX-XX */
			/* or a Hewlett-Packard format XXXXXX-XXXXXX */
			buf[i] = ':';
			cd++;
			break;
		    case ':':
			cc++;
			break;
		    case '.':
			/* Possibly a Cisco format XXXX.XXXX.XXXX */
			cp++;
			buf[i] = ':';
			break;
		}

		if ((!isxdigit(buf[i])) && (buf[i] != ':')) {
			fprintf(stderr, "Invalid MAC address specified: %s\n", buf);
			fprintf(stderr, "Valid characters are hex digits and [:-.]\n");
			exit(1);
		}
	}

	if ( (cd+cc) == 5 ) {
		/* 6x(0 to 2 hex digits) separated by 5x(dash or doublecolon) */
		// strncpy (mac, buf, 18);
		k = 0;
		for (i = 0, j = 0; i < strlen(buf); i++) {
			if (
				( (i>0 && buf[i-1]==':') || (i==0) ) &&
				(buf[i] == ':' || buf[i] == '\0' || i==strlen(buf))
		        ) {
				/* We have a 0-digit long component */
				mac[j++] = '0'; k++;
				mac[j++] = '0'; k++;
		        } else {
				/* We have a 1-digit long component */
			        if (
					( (i>0 && buf[i-1]==':') || (i==0) ) &&
					(buf[i+1] == ':' || buf[i+1] == '\0' || (i+1)==strlen(buf))
				) {
					mac[j++] = '0';
					k++;
				}
			}

			//printf ("%d=%c ",k, buf[i]);

		        if ( k>3 ) {
    			        mac[j]='\0';
				fprintf(stderr, "Invalid MAC address specified: %s (%s)\n", buf, mac);
			        fprintf(stderr, "A double-hex component is longer than two characters!\n");
				exit(1);
			}

			if ( buf[i] == ':' || buf[i] == '\0' || i==strlen(buf) ) {
			        k=0;
		        }

		        if ( j>=17 ) {
				mac[j]='\0';
				fprintf(stderr, "Invalid MAC address specified: %s (%s)\n", buf, mac);
				fprintf(stderr, "String length exceeded!\n");
				exit(1);
			}

		        mac[j++] = tolower(buf[i]); k++;
		}

		debug (1, "standardize_mac: got a Windows/Linux/Solaris MAC: [%s]\n", mac);
		return mac;
	}

	if ( ((cc+cd+cp) == 0) && (strlen(buf)==12) ) {
		/* xxxxxxxxxxxx */
		for (i = 0, j = 0, k = 0; i < strlen(buf); i++) {
			mac[j++] = tolower(buf[i]); k++;
			if ( k==2 ) {
				if ( i < (strlen(buf)-1) ) {
					k=0;
					mac[j++] = ':';
				} else {
					mac[j++] = '\0';
				}
			}
		}

		debug (1, "standardize_mac: got an unseparated MAC: [%s]\n", mac);
		return mac;
	}

	if ( (cd+cc)==1 && (strlen(buf)==13) && buf[6]==':' ) {
		/* originally Hewlett-Packard: XXXXXX-XXXXXX */
		for (i = 0, j = 0, k = 0; i < strlen(buf); i++) {
			if ( i!= 6 ) {
				mac[j++] = tolower(buf[i]);
				k++;
			}

			if ( k==2 ) {
				if ( i < (strlen(buf)-1) ) {
					k=0;
					mac[j++] = ':';
				} else {
					mac[j++] = '\0';
				}
			}
		}

		debug (1, "standardize_mac: got a HP MAC: [%s]\n", mac);
		return mac;
	}

	if ( (cp+cd+cc)==2 && (strlen(buf)==14) &&
		buf[4]==':' && buf[9]==':' ) {
		/* originally Cisco: XXXX.XXXX.XXXX */
		for (i = 0, j = 0, k = 0; i < strlen(buf); i++) {
			if ( i!= 4 && i!=9 ) {
				mac[j++] = tolower(buf[i]);
				k++;
			}

			if ( k==2 ) {
				if ( i < (strlen(buf)-1) ) {
					k=0;
					mac[j++] = ':';
				} else {
					mac[j++] = '\0';
				}
			}
		}

		debug (1, "standardize_mac: got a Cisco MAC: [%s]\n", mac);
		return mac;
	}


	strncpy (mac, buf, 18);
	debug (1, "standardize_mac: unrecognized format, passed on as is: [%s]\n", mac);
	return mac;
}

/* see if the specified mac address is sane, and make it machine-readable */
char
*pack_mac(char *buf)
{
	int	i, cc, sl, v, mp;
	char	*ptr, *cp; 
	static	char	mac[16];

	cc = 0;
	for (i = 0; i < strlen(buf); i++) {

		if (buf[i] == '-')
			/* Possibly a Windows-format MAC XX-XX-XX-XX-XX-XX */
			buf[i] = ':';

		if (buf[i] == ':')
			cc++;

		if ((!isxdigit(buf[i])) && (buf[i] != ':')) {
			fprintf(stderr, "Invalid MAC address specified: %s\n", buf);
			fprintf(stderr, "Valid characters are hex digits and :\n");
			exit(1);
		}
	}

	if (cc != 5) {
		fprintf(stderr, "Invalid MAC address specified: %s\n", buf);
		fprintf(stderr, "It must contain exactly 5 : separators.\n");
		exit(1);
	}

	strcpy(mac, "");
	ptr = buf;
	sl = strlen(buf);
	mp = 0;

	for (i = 0; i < sl; i++) {
		cp = strchr(ptr, ':');

		if (!cp) {
			v = strtol(ptr, (char **) NULL, 16);

			mac[mp++] = v;
			break;
		}

		*cp++ = '\0';

		v = strtol(ptr, (char **) NULL, 16);
		mac[mp++] = v;

		ptr = cp;
	}	

	return mac;
}
