%module rpow

%{
#include <fcntl.h>
#include "rpowclient.h"
%}


#define RPOW_VALUE_MIN	20
#define RPOW_VALUE_MAX	50

#  define KEYID_LENGTH	20
#  define CARDID_LENGTH	14

/* Public keys, for communication and rpow signature verification */
typedef struct pubkey {
	gbignum n;
	gbignum e;
	unsigned char keyid[KEYID_LENGTH];
#define PUBKEY_STATE_SIGNING	1
#define PUBKEY_STATE_ACTIVE		2
#define PUBKEY_STATE_INACTIVE	3
	int state;
	unsigned char cardid[CARDID_LENGTH];
} pubkey;


/* Reusable proof of work */
typedef struct rpow {
	unsigned char type;
	int value;
	gbignum bn;
	unsigned char keyid[KEYID_LENGTH];
	unsigned char *id;
	int idlen;
} rpow;


/* File names for keys */
extern char *rpowfile;
extern char *signfile;
extern char *commfile;

/* Host and port for server */
extern char targethost[256];
extern int targetport;

%inline
%{
#define RPOW_VALUE_MIN	20
#define RPOW_VALUE_MAX	50

pubkey signkey;


static void
_dolock (FILE *f)
{
	int err;
	struct flock l;
	extern int errno;
	l.l_start = l.l_len = 0;
	l.l_pid = 0;
	l.l_type = F_WRLCK;
	l.l_whence = SEEK_SET;
	while (fcntl (fileno(f), F_SETLKW, &l) < 0 && errno == EINTR)
		;
}

static void
_dounlock (FILE *f)
{
	struct flock l;
	l.l_start = l.l_len = 0;
	l.l_pid = 0;
	l.l_type = F_UNLCK;
	l.l_whence = SEEK_SET;
	fcntl (fileno(f), F_SETLK, &l);
}

rpow *
gen(int value)
{
	if (value < RPOW_VALUE_MIN || value > RPOW_VALUE_MAX)
		return NULL;
	return rpow_gen(value, signkey.cardid);
}

rpow *
exchange(rpow *rpin)
{
	rpow *rpout = NULL;
	int outval;
	int status;

	if (rpin == NULL)
		return NULL;
	outval = rpin->value;
	status = server_exchange (&rpout, targethost, targetport, 1, &rpin, 1,
		&outval, &signkey);
	if (status != 0)
		return NULL;
	return rpout;
}

rpow *
join2(rpow *rpin1, rpow *rpin2)
{
	rpow *rpout = NULL;
	rpow *rpins[2];
	int outval;
	int status;

	if (rpin1 == NULL || rpin2 == NULL
			|| rpin2->value != rpin1->value)
		return NULL;
	outval = rpin1->value+1;

	rpins[0] = rpin1;
	rpins[1] = rpin2;

	status = server_exchange (&rpout, targethost, targetport, 2, rpins, 1,
		&outval, &signkey);
	if (status != 0)
		return NULL;
	return rpout;
}

rpow *
join4(rpow *rpin1, rpow *rpin2, rpow *rpin3, rpow *rpin4)
{
	rpow *rpout = NULL;
	rpow *rpins[4];
	int outval;
	int status;

	if (rpin1 == NULL || rpin2 == NULL || rpin3 == NULL || rpin4 == NULL
			|| rpin2->value != rpin1->value || rpin3->value != rpin1->value
			|| rpin4->value != rpin1->value)
		return NULL;
	outval = rpin1->value+2;

	rpins[0] = rpin1;
	rpins[1] = rpin2;
	rpins[2] = rpin3;
	rpins[3] = rpin4;

	status = server_exchange (&rpout, targethost, targetport, 4, rpins, 1,
		&outval, &signkey);
	if (status != 0)
		return NULL;
	return rpout;
}

rpow *
join8(rpow *rpin1, rpow *rpin2, rpow *rpin3, rpow *rpin4, rpow *rpin5, rpow *rpin6, rpow *rpin7, rpow *rpin8)
{
	rpow *rpout = NULL;
	rpow *rpins[8];
	int outval;
	int status;

	if (rpin1 == NULL || rpin2 == NULL || rpin3 == NULL || rpin4 == NULL
			|| rpin5 == NULL || rpin6 == NULL || rpin7 == NULL || rpin8 == NULL
			|| rpin2->value != rpin1->value || rpin3->value != rpin1->value
			|| rpin4->value != rpin1->value || rpin5->value != rpin1->value
			|| rpin6->value != rpin1->value || rpin7->value != rpin1->value
			|| rpin8->value != rpin1->value)
		return NULL;
	outval = rpin1->value+3;

	rpins[0] = rpin1;
	rpins[1] = rpin2;
	rpins[2] = rpin3;
	rpins[3] = rpin4;
	rpins[4] = rpin5;
	rpins[5] = rpin6;
	rpins[6] = rpin7;
	rpins[7] = rpin8;

	status = server_exchange (&rpout, targethost, targetport, 8, rpins, 1,
		&outval, &signkey);
	if (status != 0)
		return NULL;
	return rpout;
}

typedef struct rpows {
	rpow *rp1, *rp2, *rp3, *rp4, *rp5, *rp6, *rp7, *rp8;
} rpows;

rpows *
split2(rpow *rpin)
{
	rpows *rpp;
	rpow *rpouts[2];
	int outvals[2];
	int status;

	if (rpin == NULL || rpin->value == RPOW_VALUE_MIN)
		return NULL;

	outvals[0] = outvals[1] = rpin->value-1;
	rpouts[0] = rpouts[1] = NULL;

	status = server_exchange (rpouts, targethost, targetport, 1, &rpin, 2,
		outvals, &signkey);
	if (status != 0)
		return NULL;

	rpp = malloc(sizeof(rpows));
	rpp->rp1 = rpouts[0];
	rpp->rp2 = rpouts[1];
	return rpp;
}

rpows *
split4(rpow *rpin)
{
	rpows *rpp;
	rpow *rpouts[4];
	int outvals[4];
	int status;

	if (rpin == NULL || rpin->value <= RPOW_VALUE_MIN+1)
		return NULL;

	outvals[0] = outvals[1] = outvals[2] = outvals[3] = rpin->value-2;
	rpouts[0] = rpouts[1] = rpouts[2] = rpouts[3] = NULL;

	status = server_exchange (rpouts, targethost, targetport, 1, &rpin, 4,
		outvals, &signkey);
	if (status != 0)
		return NULL;

	rpp = malloc(sizeof(rpows));
	rpp->rp1 = rpouts[0];
	rpp->rp2 = rpouts[1];
	rpp->rp3 = rpouts[2];
	rpp->rp4 = rpouts[3];
	return rpp;
}

rpows *
split8(rpow *rpin)
{
	rpows *rpp;
	rpow *rpouts[8];
	int outvals[8];
	int status;

	if (rpin == NULL || rpin->value <= RPOW_VALUE_MIN+2)
		return NULL;

	outvals[0] = outvals[1] = outvals[2] = outvals[3] = 
		outvals[4] = outvals[5] = outvals[6] = outvals[7] = rpin->value-3;
	rpouts[0] = rpouts[1] = rpouts[2] = rpouts[3] = 
		rpouts[4] = rpouts[5] = rpouts[6] = rpouts[7] = NULL;

	status = server_exchange (rpouts, targethost, targetport, 1, &rpin, 8,
		outvals, &signkey);
	if (status != 0)
		return NULL;

	rpp = malloc(sizeof(rpows));
	rpp->rp1 = rpouts[0];
	rpp->rp2 = rpouts[1];
	rpp->rp3 = rpouts[2];
	rpp->rp4 = rpouts[3];
	rpp->rp5 = rpouts[4];
	rpp->rp6 = rpouts[5];
	rpp->rp7 = rpouts[6];
	rpp->rp8 = rpouts[7];
	return rpp;
}


/* Store the rpow in the rpows file, return 0 on success */
int
store (rpow *rp)
{
	FILE *fout;
	rpowio *rpout;

	fout = fopen (rpowfile, "ab");
	if (fout == NULL)
	{
		fprintf (stderr, "Unable to write rpow to %s\n", rpowfile);
		return -1;
	}
	_dolock (fout);
	rpout = rp_new_from_file (fout);
	rpow_write (rp, rpout);
	_dounlock (fout);
	fclose (fout);
	rp_free (rpout);
	return 0;
}


/* Find an rpow in the rpows file and return it */
static rpow *
rpow_load (int value)
{
	FILE *fin;
	rpowio *rpio;
	rpow *rp = NULL;
	unsigned char *buf;
	long fpos = 0;
	long fposprev = 0;
	int bufsize = 1000;
	int nr;

	fin = fopen (rpowfile, "r+b");
	if (fin == NULL)
	{
		fprintf (stderr, "Unable to open rpow data file %s\n", rpowfile);
		return NULL;
	}
	_dolock (fin);
	rpio = rp_new_from_file (fin);

	for ( ; ; )
	{
		rp = rpow_read (rpio);
		fposprev = fpos;
		fpos = ftell (fin);
		if (rp == NULL || rp->value == value)
			break;
		rpow_free (rp);
	}

	if (rp == NULL)
	{
		_dounlock (fin);
		fclose (fin);
		rp_free (rpio);
		return NULL;
	}

	/* Delete entry from file */
	buf = malloc (bufsize);
	for ( ; ; )
	{
		fseek (fin, fpos, SEEK_SET);
		nr = fread (buf, 1, bufsize, fin);
		if (nr == 0)
			break;
		fseek (fin, fposprev, SEEK_SET);
		fwrite (buf, 1, nr, fin);
		fpos += nr;
		fposprev += nr;
	}
	free (buf);

	ftruncate (fileno(fin), (off_t)fposprev);
	_dounlock (fin);
	fclose (fin);
	rp_free (rpio);

	return rp;
}

/* Helper for load - break num outval items to create numo of size outval */
static int dobreakval (int num, int val, int numo, int outval)
{
	rpow *rp[8];
	rpow *rpnew[8];
	int vals[8];
	int outvals[8];
	int i;
	int err;

	for (i=0; i<num; i++)
	{
		vals[i] = val;
		rp[i] = rpow_load (val);
		if (rp[i] == NULL)
		{
			/* Error, try to fix it as much as we can */
			while (--i >= 0)
				store (rp[i]);
			return -1;
		}
	}

	for (i=0; i<numo; i++)
		outvals[i] = outval;

	err = server_exchange (rpnew, targethost, targetport, num, rp,
		numo, outvals, &signkey);
	if (err != 0)
	{
		for (i=0; i<num; i++)
			store (rp[i]);
		return err;
	}

	for (i=0; i<numo; i++)
		store (rpnew[i]);
	return 0;
}

/* Helper for load - break items to create some of size val */
static int dobreak (int val)
{
	FILE *fin;
	rpowio *rpio;
	int tval;
	int count;
	int maxcount;
	rpow *rp;
	int err;

	rpio = rp_new_from_file (fin);

	for (tval = val+1; tval <= RPOW_VALUE_MAX; tval++)
	{
		/* Count rpows of value */
		fin = fopen (rpowfile, "r+b");
		if (fin == NULL)
		{
			fprintf (stderr, "Unable to open rpow data file %s\n", rpowfile);
			return -1;
		}
		_dolock (fin);
		rpio = rp_new_from_file (fin);
		count = 0;
		for ( ; ; )
		{
			rp = rpow_read (rpio);
			if (rp == NULL)
				break;
			if (rp->value == tval)
				++count;
			rpow_free (rp);
		}
		
		_dounlock (fin);
		fclose (fin);
		rp_free (rpio);

		if (count != 0)
			break;
	}

	if (count == 0)
		return -1;		/* Insufficient rpows */

	while (tval > val + 3)
	{
		if ((err = dobreakval (1, tval, 8, tval-3)) < 0)
			return err;
		tval -= 3;
		count = 8;
	}

	maxcount = 1 << (3 - (tval - val));
	if (count > maxcount)
		count = maxcount;

	err = dobreakval (count, tval, count << (tval-val), val);
	return err;
}

rpow *
load (int value)
{
	rpow *rp;

	if ((rp = rpow_load(value)) == NULL)
	{
		if (dobreak (value) == 0)
			rp = rpow_load(value);
	}
	return rp;
}

/* Count the rpows in the data file */
int
countvals (int val)
{
	FILE *fin = fopen (rpowfile, "rb");
	rpowio *rpio;
	rpow *rp = NULL;
	int count = 0;

	if (val < RPOW_VALUE_MIN || val > RPOW_VALUE_MAX)
		return 0;

	if (fin == NULL)
	{
		fprintf (stderr, "Unable to open rpow data file %s\n", rpowfile);
		return 0;
	}

	_dolock (fin);
	rpio = rp_new_from_file (fin);

	for ( ; ; )
	{
		rp = rpow_read (rpio);
		if (rp == NULL)
			break;
		if (rp->value == val)
			++count;
		rpow_free (rp);
	}

	_dounlock (fin);
	fclose (fin);
	rp_free (rpio);
	return count;
}

char *
to_string (rpow *rpin)
{
	if (rpin == NULL)
		return "";
	return rpow_to_string(rpin);
}

rpow *
from_string (char *str)
{
	return rpow_from_string(str);
}



%}

%init
%{
	gbig_initialize();
	initfilenames();
	pubkey_read (&signkey, signfile);
%}



/* connio.c */

/* Getkeys deletes all of the rpows if firsttime is set! */
extern int getkeys (char *target, int port, int firsttime);
extern int getstat (char *target, int port, FILE *fout);


