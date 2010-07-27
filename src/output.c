/*
 * $Id$
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sysexits.h>

#include "sdig.h"

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "snmpget.h"

#ifdef SDIG_USE_SEMS

enum ops { UNLOCK = (int)1, LOCK = (int)(-1) };
union semun {
    int val;
    struct semid_ds *buf;
    ushort *array;
};

int lock = 0;
// int pad = 0;

/*
 * initialize output locking semaphore
 */
void
output_sem_init()
{
	int ret;
	union semun semarg;

	/*
	 * Create semaphore set with permissions for us to
	 * read and alter it
	 */
	debug(3, "output_sem_init: getting semaphore... sz=%d\n", sizeof(int));
	lock = semget(IPC_PRIVATE, 1, IPC_EXCL | IPC_CREAT | 0600);

/* http://beej.us/guide/bgipc/output/html/singlepage/bgipc.html#semaphores
 * inspired by W. Richard Stevens' UNIX Network Programming 2nd edition,
 *   volume 2, lockvsem.c, page 295
 */
	if (lock < 0) {
		perror("semget");
		goto error;
	}

	debug(3, "output_sem_init: got semid %d\n", lock);
	
	/*
	 * the lock needs to be initialized to un unlocked state
	 */
	debug(7, "ret = semctl (%d, %d, %d)\n", lock, 0, GETVAL);
	ret = semctl(lock, 0, GETVAL);
	debug(7, "ret = %d\n", ret );

	semarg.val = UNLOCK;
	debug(7, "ret = semctl (%d, %d, %d, %d)\n", lock, 0, (int)SETVAL, semarg);
	ret = semctl(lock, 0, SETVAL, semarg);
	debug(7, "ret = %d\n", ret );

	debug(3, "output_sem_init: passed semctl (ret=%d)\n", ret);

	if (ret == -1) {
		perror("semctl");
		goto error;
	}

	debug(3, "output_sem_init: unlocked lock\n");

	return;

	error:
		exit(EX_SOFTWARE);
}

/*
 * deallocate lock semaphore
 */
void
output_sem_cleanup()
{
	int ret;

	ret = semctl(lock, 0, IPC_RMID);

	if (ret == -1) {
		perror("semctl");
		exit(EX_SOFTWARE);
	}
}

/*
 * toggle output lock
 */
void
output_lock(enum ops op)
{
	struct sembuf buf = { 0, 0, SEM_UNDO };
	int ret;

	buf.sem_op = op;
	ret = semop(lock, &buf, 1);

	if (ret == -1) {
		perror("semop");
		exit(EX_SOFTWARE);
	}
}
#endif
// ifdef SDIG_USE_SEMS


/*
 * make the octet string into something nicer for humans
 */
void
printmac(unsigned const char *mac)
{
	int	i;

	for (i = 0; i < 5; i++)
		printf("%02x:", mac[i]);

	printf("%02x", mac[5]);
}


/*
 * make the OID numeric string for debug dumps, etc.
 */
char 
*oid_to_ascii(oid* name, size_t name_length) {
	static char s[MAX_OID_LEN*12];
	size_t i;
	unsigned long j, k;

	j = 0;
	for (i = 0; i < name_length; i++) {
		j += sprintf(s+j, "%u", name[i]);
		s[j++] = '.';
	}
	s[j-1] = '\0';
	return s;
}

void
printport(stype *sw, long port)
{
	char	*ds, *li, *swdesc;
	char	query[256];

#ifdef SDIG_USE_SEMS
	if ( dofork ) { output_lock(LOCK); }
#endif

	/* don't print if it's a switch-switch link unless in verbose mode */

	li = getlink(sw->ip, port);

	if ((li) && (!verbose))
		return;

	snprintf(query, sizeof(query), "SNMPv2-MIB::sysName.0");
	swdesc = snmpget_str(sw->ip, sw->pw, query);

	if (swdesc)
		printf("   Switch: %s (%s) - %s\n",
			sw->desc, swdesc, sw->ip);
	else
		printf("   Switch: %s - %s\n", sw->desc, sw->ip);

	printf("     Port: %ld", port);
	do_ifdescr(sw, port);
	printf("\n");
	
	if (li)
		printf("     Link: %s\n", li);

	ds = getdesc(sw->ip, port);
	if (ds)
		printf("     Info: %s\n", ds);

	printf("\n");

#ifdef SDIG_USE_SEMS
	if ( dofork ) { output_lock(UNLOCK); }
#endif
}
