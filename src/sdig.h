/* sdig.h - switch digger structures */

/* switch information */

typedef struct {
	unsigned int	addr;
	unsigned int	mask;
	char	*ip;
	char	*desc;
	char	*pw;
	void	*firstlink;
	void	*next;
}	stype;

/* router information */

typedef struct {
	unsigned int	addr;
	unsigned int	mask;
	char	*ip;	/* Router's accessible IP for SNMP lookups */
	char	*desc;
	char	*pw;
	void	*next;
	char	*rtrip;	/* Router's IP in the seeked subnet, optional */
}	rtype;

/* switch-switch link information */

typedef struct {
	char    *ip;
	long	port;
	char    *desc;
	void    *next;
}       litype;

/* switch port descriptions */

typedef struct {
	char    *ip;
	long	port;
	char    *desc;
	void    *next;
}       pdtype;

/* holds the results of a matched port */
struct result {
	stype s;
	char *ifIdx;
	char *ifAlias;
	char *ifName;
} result;

/*
 * global data
 */

extern stype	*firstsw;
extern rtype	*firstrt;
extern pdtype	*firstpd;
extern litype	*firstli;

extern char *wins, *nmblookup, *mactable, *hostinfo;

extern int fastmode, verbose, dofork;

/*
 * Function prototypes
 */

void printport(stype *sw, long port);
void printmac(unsigned const char *mac);
char *getdesc(const char *ip, long port);
char *getlink(const char *ip, long port);


char *dns_resolve(const char *host, int verbose);
int isip(const char *buf);
char *standardize_mac(char *buf);

/* At the moment of sdig-0.44-trunk (last checkin in 2006)
 * there is a problem with semaphore support (Bus error in semctl)
 * and as a consequence - with forked SNMP searches
 * For now, don't compile it on Solaris SPARC...
 *
 * No problems on: Solaris 10 x86, OpenSolaris snv_129 x86
 *
 * Below we use a couple of #defines, FORCE_USE_SEMS or FORCE_NOTUSE_SEMS
 * They may be set in Makefile to enforce the feature or to disable it 
 * regardless of platform. Otherwise it depends...
 */
#ifndef SPARC
# ifdef __sparc
#  define SPARC
# endif
# ifdef __sparc__
#  define SPARC
# endif
#endif

/* We used to have "Bus Error" problems on "solaris2/SPARC" due to programming
 * error in SDig semaphore code. Thus it was auto-disabled below (ifdef SPARC).
 * Macro-structure remains just in case some other systems have similar bugs
 * and should be excluded from compiling in Query Forking code.
 */
#ifndef FORCE_USE_SEMS
# define SDIG_USE_SEMS
# ifdef X_SPARC
#  ifdef X_solaris2
#   undef SDIG_USE_SEMS
#  endif
# endif
#else
# define SDIG_USE_SEMS
#endif

#ifdef FORCE_NOTUSE_SEMS
#   undef SDIG_USE_SEMS
#endif
