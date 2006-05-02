/* sdig.c - the Switch Digger main file
 *
 *  Copyright (C) 2000  Russell Kroll <rkroll@exploits.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

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

#include "sdig.h"
#include "common.h"
#include "snmpget.h"
#include "version.h"

#include "../include/config.h"

extern stype	*firstsw = NULL;
extern rtype	*firstrt = NULL;
extern pdtype	*firstpd = NULL;
extern litype	*firstli = NULL;

extern char	*wins = NULL, *nmblookup = NULL, *mactable = NULL,
		*hostinfo = NULL;

extern int	verbose = 0, fastmode = 0;

static void
help(const char *prog)
{
	printf("SNMP-based router and switch probe for locating client systems.\n\n");
	printf("usage: %s [-d] [-f <config>] [-m <MAC>] [-v] [-F] (<IP> | <hostname>)\n", prog);
	printf("\n");
	printf("  -d		- increase debug level\n");
	printf("  -F		- fast mode - no DNS/NetBIOS reverse lookups\n");	
	printf("  -f <config>	- use alternate config <config>\n");
	printf("                  default %s/sdig.conf\n", "CONFPATH");
	printf("  -m <MAC>	- force MAC <MAC>, xx:xx:xx:xx:xx:xx format\n");
	printf("  -v		- be verbose\n");
	printf("  <IP>		- IP address to find\n");
	printf("  <hostname>	- DNS/WINS hostname to find\n");

	exit(0);
}

int
main(int argc, char *argv[])
{
	char	*prog, *query, *conf = NULL, *mac = NULL;
	int	i;

	printf("Switch Digger %s\n\n", VERSION);

	prog = argv[0];

	while ((i = getopt(argc, argv, "+dhf:m:vF")) != EOF) {
		switch (i) {
			case 'd':
				debuglevel++;
				break;

			case 'f':
				conf = optarg;
				break;

			case 'h':
				help(prog);
				break;

			case 'm':
				mac = optarg;
				break;

			case 'v':
				verbose++;
				break;

			case 'F':
				fastmode = 1;
				break;
				
			default:
				help(prog);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1)
		help(prog);

	query = argv[0];

	loadconfig(conf);

	/* split off to resolve things based on what kind of input we got */

	/* hostname (DNS or WINS) given */
	if (!isip(query)) {
		printf("    Query: %s\n", query);
		resolvename(query);

		/* NOTREACHED */
	}

	/* MAC address specified, along with target network */
	if ((mac) && (isip(query))) {
		printf("    Query: %s in network %s\n", 
			mac, query);

		switchscan(query, pack_mac(mac));

		/* NOTREACHED */
	}

	/* just an IP address given */
	if (isip(query)) {
		printf("    Query: %s\n", query);
		routerscan(query);

		/* NOTREACHED */
	}

	/* unknown! */
	fprintf(stderr, "Error: unknown query type!\n");
	exit(1);
}
