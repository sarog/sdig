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

enum ops { UNLOCK = 1, LOCK = -1 };
int lock = 0;

/*
 * initialize output locking semaphore
 */
void
output_sem_init()
{
	int ret;
	
	/*
	 * Create semaphore set with permissions for us to
	 * read and alter it
	 */
	lock = semget(IPC_PRIVATE, 1, IPC_EXCL | IPC_CREAT | 0600);

	if (lock == -1) {
		perror("semget");
		goto error;
	}

	debug(3, "output_sem_init: got semid %d\n", lock);
	
	/*
	 * the lock needs to be initialized to un unlocked state
	 */
	ret = semctl(lock, 0, SETVAL, UNLOCK);

	if (ret == -1) {
		perror("semctl");
		goto error;
	}

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

void
printport(stype *sw, long port)
{
	char	*ds, *li, *swdesc;
	char	query[256];

	output_lock(LOCK);

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

	output_lock(UNLOCK);
}
