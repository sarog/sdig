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
#include <sysexits.h>

#include "sdig.h"
#include "common.h"
#include "snmpget.h"

char
*findmac(const char *ip, rtype *rtr)
{
	char	query[256], *ret;
	int	ifnum;

	debug(2, "\n\nfindmac: [%s] [%s] [%s]\n", ip, rtr->ip, rtr->pw);

	/* find the router's internal interface number */

	snprintf(query, sizeof(query),
		"IP-MIB::ipAdEntIfIndex.%s", rtr->ip);

	ifnum = snmpget_int(rtr->ip, rtr->pw, query);

	if (ifnum == -1)
		return NULL;

	debug(6, "router interface number for %s is %d\n",
		rtr->ip, ifnum);

	/* now look it up in the net to media table relative to the ifnum */

	/* if digging the router itself, use a different OID */

	if (!strcmp(ip, rtr->ip))
		snprintf(query, sizeof(query), 
			"interfaces.ifTable.ifEntry.ifPhysAddress.%d",
			ifnum);
	else
		snprintf(query, sizeof(query), 
		"ip.ipNetToMediaTable.ipNetToMediaEntry.ipNetToMediaPhysAddress.%d.%s",
		ifnum, ip);

	ret = snmpget_mac(rtr->ip, rtr->pw, query);

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
*dns_resolve(const char *host)
{
	struct	hostent	*dns;
	struct	in_addr	addr;

	if ((dns = gethostbyname(host)) == (struct hostent *) NULL)
		return NULL;

	memcpy(&addr, dns->h_addr, dns->h_length);

	printf("  Address: %s (DNS)\n", inet_ntoa(addr));

	return(xstrdup(inet_ntoa(addr)));
}

void
do_ifdescr(stype *sw, long port)
{
	char	query[256], *ifdescr, *ifname;
	long	ifnum;

	/* first get the switch's ifnum for the port */
	
	snprintf(query, sizeof(query), "SNMPv2-SMI::mib-2.17.1.4.1.2.%ld", port);
	ifnum = snmpget_int(sw->ip, sw->pw, query);

	if (ifnum == -1)
		return;

	snprintf(query, sizeof(query), "IF-MIB::ifName.%ld",
		ifnum);

	ifname = snmpget_str(sw->ip, sw->pw, query);

	if (!ifname) {
		snprintf(query, sizeof(query), "IF-MIB::ifAlias.%ld", ifnum);
		snmpget_str(sw->ip, sw->pw, query);
	}

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
	stype	*tmp;
	int	addrchk, swchk;

	if (last)
		tmp = last->next;
	else
		tmp = firstsw;

	while (tmp) {
		addrchk = ntohl(inet_addr(ipaddr)) & tmp->mask;
		swchk = tmp->addr & tmp->mask;

		if (swchk == addrchk)
			return tmp;

		tmp = tmp->next;
	}

	return NULL;
}

void fork_wrapper(unsigned const char *macaddr, stype *sw);

/* ask the switch about where the MAC address is */
void
switchscan(const char *ipaddr, unsigned const char *macaddr)
{
	stype	*sw;
	int	ret, status;

	printf("\n");
	
	if (get_debuglevel() >= 2) {
		debug(2, "switchscan: seeking (%s, ", ipaddr);
		printmac(macaddr);
		printf(")\n");
	}

	sw = find_switch(ipaddr, NULL);

	while (sw) {
		debug(3, "switchscan: matched %s\n", sw->ip);
	
		ret = fork();

		switch (ret) {
			case 0: /* child process */
				fork_wrapper(macaddr, sw);
				_exit(EX_OK);
				break;

			case -1:
				perror("fork");
				exit(EX_SOFTWARE);
				break;

			default: /* parent process */
				debug(3, "child %d started\n", ret);
				break;
		}

		sw = find_switch(ipaddr, sw);
	}
	
	while ((ret = wait(&status)) != -1)
		debug(3, "child %d exited\n", ret);

	output_sem_cleanup();

	exit(EX_OK);
}

void
fork_wrapper(unsigned const char *macaddr, stype *sw)
{
	long port;

	port = findport(macaddr, sw);

	if (port != -1)
		printport(sw, port);

	debug(3, "findport got port %d\n", port);
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
			printf("   Router: %s - %s\n", rtr->desc, rtr->ip);

			printf("      MAC: ");
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
	ipaddr = dns_resolve(name);

	if (ipaddr)
		routerscan(ipaddr);

	/* now try WINS */
	ipaddr = wins_resolve(name);

	if (ipaddr)
		routerscan(ipaddr);

	fprintf(stderr, "Can't resolve %s with DNS or WINS!\n", name);
	exit(1);
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
