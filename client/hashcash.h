/*
 * hashcash.h
 *	Hashcash v1 minting header file
 *
 * Note: the original version of this module was written by Adam
 * Back and released under a permissive license which granted permission
 * to re-license.  Under those conditions, my modified version of this
 * module is licensed as follows.
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

#if !defined( _hashcash_h )
#define _hashcash_h

#if defined( __cplusplus )
extern "C" {
#endif

#include <time.h>
//#include "utct.h"
//#include "types.h"

extern int verbose_flag;
extern int no_purge_flag;

#define HASHCASH_VERSION 0.32
#define stringify( x ) stringify2( x )
#define stringify2( x ) #x
#define HASHCASH_VERSION_STRING stringify(HASHCASH_VERSION)

#define TYPE_STR 0
#define TYPE_WILD 1
#define TYPE_REGEXP 2

#define MAX_UTC 13
#define MAX_CTR 64
#define MAX_RES 256
#define MAX_STR 256
#define MAX_VER 2
#define MAX_TOK ((MAX_VER)+1+(MAX_RES)+1+(MAX_UTC)+1+(MAX_STR))
#define MAX_UTCTIME 13

#define TIME_MINUTE 60
#define TIME_HOUR (TIME_MINUTE*60)
#define TIME_DAY (TIME_HOUR*24)
#define TIME_YEAR (TIME_DAY*365)
#define TIME_MONTH (TIME_YEAR/12)
#define TIME_AEON (TIME_YEAR*1000000000.0)
#define TIME_MILLI_SECOND (1.0/1000)
#define TIME_MICRO_SECOND (TIME_MILLI_SECOND/1000)
#define TIME_NANO_SECOND (TIME_MICRO_SECOND/1000)

#define HASHCASH_OK 1
#define HASHCASH_FAIL 0
#define HASHCASH_VALID_FOREVER 0
#define HASHCASH_INVALID_TOK_LEN -1
#define HASHCASH_RNG_FAILED -2
#define HASHCASH_INVALID_TIME -3
#define HASHCASH_TOO_MANY_TRIES -4
#define HASHCASH_EXPIRED_ON_CREATION -5
#define HASHCASH_INVALID_VALIDITY_PERIOD -6
#define HASHCASH_INTERNAL_ERROR -7
#define HASHCASH_INVALID_TIME_WIDTH -8
#define HASHCASH_VALID_IN_FUTURE -9
#define HASHCASH_EXPIRED -10
#define HASHCASH_INVALID -11
#define HASHCASH_WRONG_RESOURCE -12
#define HASHCASH_INSUFFICIENT_BITS -13
#define HASHCASH_UNSUPPORTED_VERSION -14
#define HASHCASH_SPENT -15
#define HASHCASH_NO_TOKEN -16
#define HASHCASH_REGEXP_ERROR -17

/* function hashcash_mint calling info:
 *
 * returns HASHCASH_OK on success or one of the error codes above on
 * failure (values < 0)
 * 
 * arguments are:
 *
 * now_time        -- should be time in UTC, use time(2) and local_to_utctime
 *                    from "utct.h"
 *
 * time_width      -- how many chars to abbreviate the time to 
 *                    default 0 is 6 chars YYMMDD
 *
 * resource        -- resource name, unique descriptor for resource you're
 *                    trying to protect
 *
 * bits            -- bits of collision the resource demands
 * 
 * anon_period     -- add (or subtract if negative) a random period
 *                    in seconds between this value and 0
 *                    to get same as mixmaster does set this to -3days
 *                    (default 0)
 * 
 * token           -- the token output
 *
 * tok_len         -- max length of token (excluding trailing 0)
 * 
 * anon_random     -- default NULL, if set to pointer to long
 *                    returns actuall random offset added to time
 *
 * tries_taken     -- default NULL, if set to pointer to double
 *                    returns number of tokens tested before finding
 *                    returned token.
 */

int hashcash_mint1( time_t now_time, int time_width, 
		   const char* resource, unsigned bits, 
		   long anon_period, char* token, int tok_len, 
		   long* anon_random, double* tries_taken, char* ext );


/* return how many seconds the token remains valid for
 * return value HASHCASH_VALID_FOREVER (value 0) means forever
 * return value < 0 is error code
 * codes are: HASHCASH_VALID_IN_FUTURE
 *            HASHCASH_EXPIRED
 */


/* simple function calling hashcash_parse, hashcash_count for convenience */

int hashcash_check1( const char* token, const char* resource, void **compile,
		    char** re_err, int type, time_t now_time, 
		    time_t validity_period, long grace_period, 
		    int required_bits, time_t* token_time );


#define sstrncpy(d,s,l) ((d)[(l)]='\0',strncpy((d),(s),(l)))


#if defined( __cplusplus )
}
#endif

#endif
