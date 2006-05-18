/* common.c - common useful functions

   Copyright (C) 2000  Russell Kroll <rkroll@exploits.org>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
*/

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>

#include "common.h"

int		debuglevel = 0;
const char	*oom_msg = "Out of memory";

/* debug levels:
 *
 * 2 - function entry messages
 * 3 - function status messages
 * 4 - snmpget calls
 * 5 - popen calls
 * 6 - snmpget results, parsing details
 * 7 - popen reads
 */

void
debug(int level, const char *format, ...)
{
	va_list	args;

	if (debuglevel < level)
		return;

	va_start(args, format);
	vprintf(format, args);
	va_end(args);
}

void
inc_debuglevel(void)
{
	debuglevel++;
}

int
get_debuglevel(void)
{
	return debuglevel;
}

void
fatal(const char *fmt, ...)
{
	va_list va;
	char	msg[LARGEBUF];

	va_start(va, fmt);
	vsnprintf(msg, sizeof(msg), fmt, va);
	va_end(va);

	fprintf(stderr, "Fatal error: %s\n", msg);
        exit(1);
}

int
snprintfcat(char *dst, size_t size, const char *fmt, ...)
{
	va_list ap;
	int len = strlen(dst);
	int ret;

	size--;

	va_start(ap, fmt);
	ret = vsnprintf(dst + len, size - len, fmt, ap);
	va_end(ap);

	dst[size] = '\0';
	return len + ret;
}

void
*xmalloc(size_t size)
{
	void *p = malloc(size);

	if (p == NULL)
		fatal("%s", oom_msg);
	return p;
}

char
*xstrdup(const char *string)
{
	char *p = strdup(string);

	if (p == NULL)
		fatal("%s", oom_msg);
	return p;
}
