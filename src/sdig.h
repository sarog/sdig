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
	char	*ip;
	char	*desc;
	char	*pw;
	void	*next;
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

extern int fastmode, verbose;

/*
 * Function prototypes
 */

void printport(stype *sw, long port);
void printmac(unsigned const char *mac);
