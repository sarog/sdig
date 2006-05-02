/*
 *  $Id$
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

#include "../include/config.h"

void
loadconfig(const char *fn)
{
	FILE	*conf;
	char	cfn[256], buf[256], *arg[5];
	int	ln, i;

	if (!fn) {
		snprintf(cfn, sizeof(cfn), "%s/sdig.conf", "CONFPATH");
		conf = fopen(cfn, "r");
	} else {
		conf = fopen(fn, "r");
	}

	if (!conf) {
		fprintf(stderr, "fopen %s: %s\n", cfn, strerror(errno));
		exit(1);
	}

	ln = 0;
	while (fgets(buf, sizeof(buf), conf)) {
		buf[strlen(buf) - 1] = '\0';
		ln++;

		i = parseconf("sdig.conf", ln, buf, arg, 5);

		if (i == 0)
			continue;

		if (!strcmp(arg[0], "ROUTER"))
			addrouter(arg[1], arg[2], arg[3], arg[4]);
		if (!strcmp(arg[0], "SWITCH"))
			addswitch(arg[1], arg[2], arg[3], arg[4]);
		if (!strcmp(arg[0], "LINKINFO"))
			addli(arg[1], arg[2], arg[3]);
		if (!strcmp(arg[0], "PORTDESC"))
			addpd(arg[1], arg[2], arg[3]);
		if (!strcmp(arg[0], "WINS"))
			wins = xstrdup(arg[1]);
		if (!strcmp(arg[0], "NMBLOOKUP"))
			nmblookup = xstrdup(arg[1]);
		if (!strcmp(arg[0], "MACTABLE"))
			mactable = xstrdup(arg[1]);
		if (!strcmp(arg[0], "HOSTINFO"))
			hostinfo = xstrdup(arg[1]);
	}

	fclose(conf);
}

/* split up buf into a number of substrings, returning pointers in arg */
int
parseconf(const char *fn, int ln, char *buf, char **arg, int numargs)
{
	char	*ptr, *ws;
	int	i, buflen, an, state;

	an = state = 0;
	ws = NULL;

	buflen = strlen (buf);
	ptr = buf;

	/* yes, it's a state machine! be afraid! */

	for (i = 0; i < buflen; i++) {
		switch (state) {
			case 0:		/* scan */
				if (*ptr == '"') {
					ws = ptr + 1; 	/* start after quote */
					state = 1;	/* goto quotecollect */
					break;
				}

				if (isspace(*ptr))
					break;		/* loop */

				if (*ptr == '\\') {	/* literal as start */
					if (i == (buflen - 1)) {
						fprintf(stderr, "%s:%d:"
						"\\ at end of line!", 
						fn, ln);
						return 0;	/* failure */
					}

					ws = ptr;

					/* shift string to the left */
					memmove(ptr, ptr+1, buflen-i);

					/* fix length */
					buflen--;

					state = 2;	/* goto collect */
				}

				if (!isspace(*ptr)) {
					ws = ptr;
					state = 2;	/* goto collect */
					break;
				}
			
				break;

			case 1:		/* quotecollect */
				if (*ptr == '"')
					state = 3;	/* goto save */

				if (*ptr == '\\') {	/* literal handling */
					if (i == (buflen - 1)) {
						fprintf(stderr, "%s:%d:"
						"\\ at end of line!", 
						fn, ln);
						return 0;	/* failure */
					}

					/* shift string to the left */
					memmove(ptr, ptr+1, buflen-i);

					/* fix length */
					buflen--;
				}

				break;			/* loop */

			case 2:		/* collect */
				if (*ptr == '\\') {	/* literal handling */
					if (i == (buflen - 1)) {
						fprintf(stderr, "%s:%d:"
						"\\ at end of line!", 
						fn, ln);
						return 0;	/* failure */
					}

					/* shift string to the left */
					memmove(ptr, ptr+1, buflen-i);

					/* fix length */
					buflen--;
					break;		/* loop */
				}

				if (!isspace(*ptr))
					break;		/* loop */

				state = 3;		/* goto save */
		}

		if (state == 3) {		/* save */
			if (an < numargs)
				arg[an++] = ws;
			*ptr = '\0';
			ws = NULL;
			state = 0;
		}

		ptr++;
	}

	if (state == 1) {	/* end-of-string in state 1 == missing quote */
		fprintf(stderr, "%s:%d: Unbalanced \" in line", fn, ln);
		return 0;	/* FAILED */
	}

	if (state == 2) {	/* catch last word when exiting from collect */
		*ptr = '\0';
		if (an < numargs)
			arg[an++] = ws;
	}

	/* zap any leftover pointers */
	for (i = an; i < numargs; i++)
		arg[i] = NULL;

	/* safety catch: don't allow all nulls back as 'success' */
	if (arg[0] == NULL)
		return 0;	/* FAILED (don't parse this) */

	return 1;	/* success */
}

/* ROUTER <netblock> <ip> <pw> <"desc"> */
void
addrouter(char *net, const char *ip, const char *pw, const char *desc)
{
	rtype	*tmp, *last;
	char	*addr, *mask;

	mask = strchr(net, '/');

	if (!mask)
		return;

	*mask++ = '\0';
	addr = net;

	tmp = last = firstrt;

	while (tmp != NULL) {
		last = tmp;
		tmp = tmp->next;
	}

	tmp = xmalloc(sizeof(rtype));
	tmp->addr = ntohl(inet_addr(addr));
	tmp->pw = xstrdup(pw);
	tmp->ip = xstrdup(ip);
	tmp->desc = xstrdup(desc);
	tmp->next = NULL;

	if (strstr(mask, ".") == NULL) { /* must be a /nn CIDR type block */
		if (atoi(mask) != 32)
			tmp->mask = ((unsigned int) ((1 << atoi(mask)) - 1) <<
				(32 - atoi(mask)));
		else
			tmp->mask = 0xffffffff; /* avoid overflow from 2^32 */
	}
	else
		tmp->mask = ntohl(inet_addr(mask));

	if (last != NULL)
		last->next = tmp;
	else
		firstrt = tmp;
}

/* SWITCH <netblock> <ip> <community> ["<desc>"] */
void
addswitch(char *net, const char *ip, const char *pw, const char *desc)
{
	stype	*tmp, *last;
	char	*addr, *mask;

	mask = strchr(net, '/');

	if (!mask)
		return;

	*mask++ = '\0';
	addr = net;

	tmp = last = firstsw;

	while (tmp != NULL) {
		last = tmp;
		tmp = tmp->next;
	}

	tmp = xmalloc(sizeof(stype));
	tmp->addr = ntohl(inet_addr(addr));
	tmp->pw = xstrdup(pw);
	tmp->ip = xstrdup(ip);
	tmp->desc = xstrdup(desc);
	tmp->firstlink = NULL;
	tmp->next = NULL;

	if (strstr(mask, ".") == NULL) {  /* must be a /nn CIDR type block */
		if (atoi(mask) != 32)
			tmp->mask = ((unsigned int) ((1 << atoi(mask)) - 1) <<
				(32 - atoi(mask)));
		else
			tmp->mask = 0xffffffff; /* avoid overflow from 2^32 */
	}
	else
		tmp->mask = ntohl(inet_addr(mask));

	if (last != NULL)
		last->next = tmp;
	else
		firstsw = tmp;
}

/* LINKINFO <ip> <port> "<desc>" */
void
addli(const char *ip, const char *port, const char *desc)
{
	litype	*tmp, *last;

	tmp = last = firstli;

	while (tmp) {
		last = tmp;
		tmp = tmp->next;
	}

	tmp = xmalloc(sizeof(litype));
	tmp->ip = xstrdup(ip);
	tmp->port = strtol(port, (char **) NULL, 10);
	tmp->desc = xstrdup(desc);

	if (last)
		last->next = tmp;
	else
		firstli = tmp;
}

/* PORTDESC <ip> <port> "<desc>" */
void
addpd(const char *ip, const char *port, const char *desc)
{
	pdtype	*last, *tmp;

	tmp = last = firstpd;

	while (tmp) {
		last = tmp;
		tmp = tmp->next;
	}

	tmp = xmalloc(sizeof(pdtype));
	tmp->ip = xstrdup(ip);
	tmp->port = strtol(port, (char **) NULL, 10);
	tmp->desc = xstrdup(desc);

	if (last)
		last->next = tmp;
	else
		firstpd = tmp;
}
