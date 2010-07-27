/* sdig.c - the Switch Digger main file
 * Current version is on SourceForge:   http://sdig.sourceforge.net/
 *
 *  Copyright (C) 2000-2003  Russell Kroll <rkroll@exploits.org>
 *	    up till sdig-0.40
 *  Copyright (C) 2005-2006  Russell Jackson <raj@csub.edu>
 *	    sdig-0.41 .. sdig-0.44
 *  Copyright (C) 2010  Jim Klimov <jimklimov@gmail.com>
 *	    sdig-0.45 .. 0.46 (in progress)
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
 *
 *  $Id$
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

/*
 * Flags
 */

int	verbose = 0, fastmode = 0, dofork = 0;

void
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
	printf("  -p / -P	- enable / disable forking children for SNMP queries\n");
#ifdef SDIG_USE_SEMS
	printf("  		  (NOTE: enabled by default)\n");
#else
	printf("  		  (NOTE: feature NOT COMPILED into this binary)\n");
#endif

	exit(EX_OK);
}

int
main(int argc, char *argv[])
{
	char	*prog, *query, *conf = NULL, *mac = NULL, *stdmac = NULL;
	int	i;

	printf("Switch Digger %s", VERSION);
#ifdef SDIG_USE_SEMS
	printf(", query forking capable", VERSION);
	dofork=1;
#else
	dofork=0;
#endif
	printf("\n\n");

	prog = argv[0];

	while ((i = getopt(argc, argv, "+dpPhf:m:vF")) != EOF) {
		switch (i) {
			case 'd':
				inc_debuglevel();
				break;

			case 'p':
#ifdef SDIG_USE_SEMS
				dofork++;
#else
				printf("ERROR: query forking not compiled in, '-p' ignored\n");
#endif
				break;

			case 'P':
#ifdef SDIG_USE_SEMS
				dofork--;
#else
				printf("ERROR: query forking not compiled in, '-P' ignored\n");
#endif
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

	if (argc < 1 && !(mac))
		help(prog);

	if (argc == 0) {
		query = NULL;
	} else {
	query = argv[0];
	}

	loadconfig(conf);
#ifdef SDIG_USE_SEMS
	if ( dofork < 0 ) { dofork = 0; }
	printf("Query forking is currently %s\n\n", (dofork?"enabled":"disabled") );
	if ( dofork ) { output_sem_init(); }
#endif

	/* split off to resolve things based on what kind of input we got */

	/* hostname (DNS or WINS) given */
	if ((query) && !isip(query)) {
		printf("    Query: %s\n", query);
		resolvename(query);

		/* NOTREACHED */
	}

	/* MAC address specified, along with target network */
	if ((mac)) {
		stdmac = standardize_mac(mac);

		if ((query) && (isip(query))) {
			printf("    Query: MAC %s in network %s\n", 
				stdmac, query);

			switchscan(query, pack_mac(stdmac));

		/* NOTREACHED */
		} else {
			/* Only a MAC is provided */
			printf("    Query: MAC %s in any network\n", 
				stdmac);

			switchscan(NULL, pack_mac(stdmac));

			/* NOTREACHED */
		}
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
