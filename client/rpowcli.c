/*
 * rpowcli.c
 *	Reusable proof of work client
 *
 * Copyright (C) 2004 Hal Finney
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <assert.h>
#include <ctype.h>

#include "rpowcli.h"

#if defined(_WIN32)
#define ftruncate chsize
#endif

static pubkey signkey;


static void
rpow_to_file (rpow *rp, const char *fname)
{
	FILE *fout;
	rpowio *rpout;

	fout = fopen (fname, "ab");
	if (fout == NULL)
	{
		fprintf (stderr, "Unable to write rpow to %s\n", fname);
		exit (1);
	}
	rpout = rp_new_from_file (fout);
	rpow_write (rp, rpout);
	fclose (fout);
	rp_free (rpout);
}


static rpow * rpow_from_file (int value, const char *fname)
{
	FILE *fin;
	rpowio *rpio;
	rpow *rp = NULL;
	uchar *buf;
	long fpos = 0;
	long fposprev = 0;
	int bufsize = 1000;
	int nr;

	fin = fopen (fname, "r+b");
	if (fin == NULL)
	{
		fprintf (stderr, "Unable to open rpow data file %s\n", fname);
		exit (1);
	}
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
	fclose (fin);
	rp_free (rpio);

	return rp;
}


static int
dogen (char *target, int port, int value)
{
	rpow *rp;
	rpow *rpnew;
	int err;

	rp = rpow_gen (value, signkey.cardid);
	if (rp == NULL)
	{
		fprintf (stderr, "Unable to generate a coin of value %d\n", value);
		exit (2);
	}

	err = server_exchange (&rpnew, target, port, 1, &rp, 1, &value, &signkey);
	if (err != 0)
		exit (err);

	rpow_free (rp);
	rpow_to_file (rpnew, rpowfile);

	return 0;
}

static int doin (char *target, int port)
{
	int bufsize, buflen;
	char *buf, *buf64;
	int nr;
	BIO *bioin;
	rpowio *rpioin;
	rpow *rp;
	rpow *rpnew;
	int err;

	/* Read from stdin */
	bufsize = 1000;
	buflen = 0;
	buf = malloc (bufsize);
	while ((nr = fread (buf, 1, bufsize-buflen, stdin)) > 0)
	{
		buflen += nr;
		if (buflen == bufsize)
		{
			bufsize *= 2;
			buf = realloc (buf, bufsize);
		}
	}
	if (strncmp (buf, "1:", 2) == 0)
	{
		buf64 = hc_to_buffer (buf, &buflen);
	} else {
		/* De-base64 */
		buf64 = malloc (buflen);
		buflen = dec64 (buf64, buf, buflen);
	}

	/* Parse as a rpow */
	bioin = BIO_new(BIO_s_mem());
	rpioin = rp_new_from_bio (bioin);
	BIO_write (bioin, buf64, buflen);
	rp = rpow_read (rpioin);
	rp_free (rpioin);

	if (rp == NULL)
	{
		fprintf (stderr, "Invalid incoming rpow format\n");
		exit (2);
	}

	err = server_exchange (&rpnew, target, port, 1, &rp,
				1, &rp->value, &signkey);
	if (err != 0)
		exit (err);

	rpow_free (rp);
	rpow_to_file (rpnew, rpowfile);

	printf ("Received rpow item of value %d\n", rpnew->value);
	return 0;
}


static int doout (int value)
{
	rpow *rp;
	char *ptr, *outbuf;
	BIO *bio;
	rpowio *rpio;
	int ptrlen;
	int outlen;

	rp = rpow_from_file (value, rpowfile);
	if (rp == NULL)
	{
		fprintf (stderr, "Unable to find RPOW of value %d\n", value);
		exit (2);
	}

	/* Convert to base64 and output to stdout */
	bio = BIO_new(BIO_s_mem());
	rpio = rp_new_from_bio (bio);
	rpow_write (rp, rpio);
	ptrlen = BIO_get_mem_data (bio, &ptr);
	outbuf = malloc (2*ptrlen);
	outlen = enc64 (outbuf, ptr, ptrlen);
	outbuf[outlen] = '\0';
	puts (outbuf);
	free (outbuf);
	rp_free (rpio);
	return 0;
}


static int doexch (char *target, int port, int nin, int *invals,
			int nout, int *outvals)
{
	rpow **rp;
	rpow **rpnew;
	int err;
	int i;

	rp = malloc (nin * sizeof (rpow *));
	rpnew = malloc (nout * sizeof(rpow *));

	for (i=0; i<nin; i++)
	{
		rp[i] = rpow_from_file (invals[i], rpowfile);
		if (rp[i] == NULL)
		{
			fprintf (stderr, "Unable to find RPOW with value %d\n", invals[i]);
			while (i-- > 0)
				rpow_to_file (rp[i], rpowfile);
			exit (2);
		}
	}

	err = server_exchange (rpnew, target, port, nin, rp,
					nout, outvals, &signkey);
	if (err != 0)
	{
		/* Try putting the ones back we puled out */
		for (i=0; i<nin; i++)
			rpow_to_file (rp[i], rpowfile);
		exit (err);
	}

	for (i=0; i<nout; i++)
	{
		rpow_to_file (rpnew[i], rpowfile);
		rpow_free (rpnew[i]);
	}
	for (i=0; i<nin; i++)
		rpow_free (rp[i]);
	free (rp);
	free (rpnew);

	return 0;
}


static int docount ()
{
	FILE *fin = fopen (rpowfile, "r+b");
	rpowio *rpio;
	rpow *rp = NULL;
	int nexps = RPOW_VALUE_MAX - RPOW_VALUE_MIN + 1;
	int expcounts[RPOW_VALUE_MAX - RPOW_VALUE_MIN + 1];
	int exp;
	int count = 0;

	memset (expcounts, 0, sizeof(expcounts));

	if (fin == NULL)
	{
		fprintf (stderr, "Unable to open rpow data file %s\n", rpowfile);
		exit (1);
	}

	rpio = rp_new_from_file (fin);

	for ( ; ; )
	{
		rp = rpow_read (rpio);
		if (rp == NULL)
			break;
		if (rp->value < RPOW_VALUE_MIN || rp->value > RPOW_VALUE_MAX)
		{
			fprintf (stderr,
				"Skipping rpow with invalid value %d\n", rp->value);
		} else {
			++expcounts[rp->value - RPOW_VALUE_MIN];
			++count;
		}
	}

	printf ("%d rpows in rpow data file %s:\n", count, rpowfile);
	for (exp=0; exp<nexps; ++exp)
	{
		if (expcounts[exp] > 0)
			printf ("  value %2d: %d\n", RPOW_VALUE_MIN+exp, expcounts[exp]);
	}
	rp_free (rpio);
	return 0;
}


static void
userr (char *pname)
{
	fprintf (stderr, "Usage: %s"
		" getkeys <<<<==== (must be done first)\n"
		"\trekey\n"
		"\tstatus\n"
		"\tgen value\n"
		"\texchange cur_val ... 0 new_val ...\n"
		"\tin < rpowdata\n"
		"\tout value > rpowdata\n"
		"\tcount\n",
		pname);
	exit (1);
}

int
main (int ac, char **av)
{
	char *cmd;
	int nsides;
	int cmdgen, cmdout, cmdin, cmdcount, cmdexch, cmdkeys, cmdstat;
	int cmdrekey;
	int value;

	if (ac < 2)
		userr (av[0]);

	cmd = av[1];
	cmdkeys = (strcmp (cmd, "getkeys") == 0);
	cmdgen = (strcmp (cmd, "gen") == 0);
	cmdout = (strcmp (cmd, "out") == 0);
	cmdin = (strcmp (cmd, "in") == 0);
	cmdcount = (strcmp (cmd, "count") == 0);
	cmdexch = (strcmp (cmd, "exchange") == 0);
	cmdrekey = (strcmp (cmd, "rekey") == 0);
	cmdstat = (strcmp (cmd, "status") == 0);
	if (cmdkeys+cmdgen+cmdout+cmdin+cmdcount+cmdexch+cmdrekey+cmdstat != 1)
		userr(av[0]);

	initfilenames ();

	if ((cmdout || cmdgen) && ac != 3)
		userr (av[0]);
	if ((cmdin || cmdcount || cmdkeys || cmdrekey || cmdstat) && ac != 2)
		userr (av[0]);

	gbig_initialize();

	if (cmdout)
	{
		value = atoi(av[2]);
		return doout(value);
	}

	if (cmdcount)
		return docount();

	if (cmdstat)
		return getstat (targethost, targetport, stdout);

	if (cmdkeys || cmdrekey)
	{
		if (getkeys (targethost, targetport, cmdkeys) != 0)
		{
			fprintf (stderr, "Error retrieving and validating keys\n");
			exit (1);
		}
		exit (0);
	}

	pubkey_read (&signkey, signfile);

	if (cmdexch)
	{
		int *invals, *outvals;
		int nin, nout;
		int i;

		if (ac < 5)
			userr(av[0]);
		for (i=3; i<ac-1; i++)
		{
			if (strcmp (av[i], "0") == 0)
				break;
		}
		if (i == ac)
			userr(av[0]);
		nin = i - 2;
		nout = ac - i - 1;
		invals = malloc (nin * sizeof(int));
		outvals = malloc (nout * sizeof(int));
		for (i=0; i<nin; i++)
		{
			invals[i] = atoi(av[i+2]);
			if (invals[i] < RPOW_VALUE_MIN || invals[i] > RPOW_VALUE_MAX)
				userr(av[0]);
		}
		for (i=0; i<nout; i++)
		{
			outvals[i] = atoi(av[ac-nout+i]);
			if (outvals[i] < RPOW_VALUE_MIN || outvals[i] > RPOW_VALUE_MAX)
				userr(av[0]);
		}
		return doexch (targethost, targetport, nin, invals, nout, outvals);
	}

	if (cmdgen)
	{
		value = atoi(av[2]);
		if (value < RPOW_VALUE_MIN || value > RPOW_VALUE_MAX)
		{
			fprintf (stderr, "Illegal work value %d\n", value);
			exit (1);
		}
	}

	if (cmdgen)
		return dogen (targethost, targetport, value);

	if (cmdin)
		return doin (targethost, targetport);
}
