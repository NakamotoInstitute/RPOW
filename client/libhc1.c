/*
 * libhc1.c
 *	Hashcash v1 minter, modified from http://www.hashcash.org/
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#if defined( REGEXP_BSD )
    #define _REGEX_RE_COMP
    #include <regex.h>
#elif defined( REGEXP_POSIX )
    #include <sys/types.h>
    #include <regex.h>
#else
/* no regular expression support */
#endif

#include "hashcash.h"
#include "openssl/sha.h"

typedef unsigned int word32;
typedef unsigned char byte;

static time_t round_off( time_t now_time, int digits );
static const char* strtime( time_t* timep, int utc );
static time_t mk_utctime( struct tm* tms );
static time_t from_utctimestr( const char utct[MAX_UTCTIME+1], int utc );
static int to_utctimestr( char utct[MAX_UTCTIME+1], int len, time_t t );
static int validity_to_width( time_t validity_period );
static unsigned hashcash_count( const char* token );
static int hashcash_parse( const char* token, int* vers, int* bits, char* utct, 
		    int utct_max, char* token_resource, int res_max, 
		    char** ext, int ext_max ) ;
static long hashcash_valid_for( time_t token_time, time_t validity_period, 
			 long grace_period, time_t now_time );
static int email_match( const char* pattern, const char* email );
static int resource_match( int type, const char* token_res, const char* res, 
		    void** compile, char** err );
static char* sstrtok( const char* str, const char* delim, char** tok,
		int tok_max, int* tok_len, char** s );

#if DEBUG
/* smaller base for debugging */
#define GROUP_SIZE 255
#define GROUP_DIGITS 2
#define GFFORMAT "%x"
#define GFORMAT "%02x"
#else
#define GROUP_SIZE 0xFFFFFFFFU
#define GROUP_DIGITS 8
#define GFFORMAT "%x"
#define GFORMAT "%08x"
#endif

static word32 find_collision( char utct[ MAX_UTCTIME+1 ], const char* resource, 
		       int bits, char* token, word32 tries, char* rnd_str,
		       char* counter, char* ext );

char *strrstr(char *s1,char *s2) 
{
    char *sc2, *psc1, *ps1;
 
    if ( *s2 == '\0' ) { return s1; }
    ps1 = s1 + strlen(s1);

    while( ps1 != s1 ) {
	--ps1;
	for ( psc1 = ps1, sc2 = s2; ; ) {
	    if (*(psc1++) != *(sc2++)) { break; }
	    else if ( *sc2 == '\0' ) { return ps1; }
	}
    }
    return NULL;
}

int wild_match( char* pat, char* str )
{
    int num = 1, last = 0, first = 1;
    char* term, *prev_term, *ptr = pat, *pos = str, *find;

    do {
	term = ptr; ptr = strchr( ptr, '*' );
	if ( ptr ) { *ptr = '\0'; ptr++; } 
	else { last = 1; }
	
	if ( *term != '\0' ) {
	    if ( first ) {	/* begin */
		if ( strncmp( pos, term, strlen( term ) ) != 0 ) {
		    return 0;
		}
		pos += strlen( term );
	    } else if ( !first ) { /* middle */
		if ( last ) {
		    pos = strrstr( pos, term );
		} else {
		    pos = strstr( pos, term );
		}
		if ( pos == 0 ) { return 0; }
		pos += strlen( term );
	    }
	    if ( last && *pos != '\0' ) {
		return 0; 
	    }
	}

	num++; first = 0;
    } while ( term && !last );
    
    return 1;
}

int email_match( const char* email, const char* pattern )
{
    int len, ret = 0;
    char *pat_user = NULL, *pat_dom = NULL;
    char *em_user = NULL, *em_dom = NULL;
    char *pat_sub, *em_sub, *pat_next, *em_next, *state;
    
    sstrtok( pattern, "@", &pat_user, 0, &len, &state );
    sstrtok( NULL, "@", &pat_dom, 0, &len, &state );

    sstrtok( email, "@", &em_user, 0, &len, &state );
    sstrtok( NULL, "@", &em_dom, 0, &len, &state );

    /* if @ in pattern, must have @ sign in email too */
    if ( pat_dom && em_dom == NULL ) { goto done; } 

    if ( !wild_match( pat_user, em_user ) ) { goto done; }

    if ( !pat_dom && !em_dom ) { ret = 1; goto done; } /* no @ in either, ok */

    pat_next = pat_dom; em_next = em_dom;
    do {
	pat_sub = pat_next; em_sub = em_next;
	pat_next = strchr( pat_next, '.' ); 
	if ( pat_next ) { *pat_next = '\0'; pat_next++; }
	em_next = strchr( em_next, '.' ); 
	if ( em_next ) { *em_next = '\0'; em_next++; }

	if ( !wild_match( pat_sub, em_sub ) ) { goto done; }
	
    } while ( pat_next && em_next );

    /* different numbers of subdomains, fail */
    if ( ( pat_next == NULL && em_next != NULL ) ||
	 ( pat_next != NULL && em_next == NULL ) ) { goto done; }
    
    ret = 1;
 done:
    if ( pat_user ) { free( pat_user ); }
    if ( pat_dom ) { free( pat_dom ); }
    if ( em_user ) { free( em_user ); }
    if ( em_dom ) { free( em_dom ); }
    return ret;
}

int hashcash_mint1( time_t now_time, int time_width, 
		   const char* resource, unsigned bits, 
		   long anon_period, char* token, int tok_len, 
		   long* anon_random, double* tries_taken, char* ext )
{
    word32 i0, i1;
    int i0f, i1f;
    word32 ran0, ran1;
    char counter[ MAX_CTR+1 ];
    word32 found = 0;
    long rnd;
    char now_utime[ MAX_UTCTIME+1 ]; /* current time */
    char rnd_str[GROUP_DIGITS*2+1];
    double tries;

    if ( resource == NULL || token == NULL ) {
	return HASHCASH_INTERNAL_ERROR;
    }

    if ( anon_random == NULL ) { anon_random = &rnd; }
    if ( tries_taken == NULL ) { tries_taken = &tries; }

    *anon_random = 0;

    if ( bits > SHA_DIGEST_LENGTH * 8 ) {
	return HASHCASH_INVALID_TOK_LEN;
    }

    if ( time_width == 0 ) { time_width = 6; } /* default YYMMDD */

    if ( gbig_rand_bytes( &ran0, sizeof( word32 ) ) < sizeof(word32) ||
	 gbig_rand_bytes( &ran1, sizeof( word32 ) ) < sizeof(word32) ) {
	return HASHCASH_RNG_FAILED;
    }
    
    sprintf( rnd_str, "%08x%08x",ran0,ran1);

    if ( now_time < 0 ) {
	return HASHCASH_INVALID_TIME;
    }

#if 0
    if ( anon_period != 0 ) {
	if ( !random_rectangular( (long)anon_period, anon_random ) ) {
	    return HASHCASH_RNG_FAILED;
	}
    }
#endif

    now_time += *anon_random;

    if ( time_width != 12 && time_width != 10 && time_width != 6 ) {
	return HASHCASH_INVALID_TIME_WIDTH;
    }

    now_time = round_off( now_time, 12-time_width );
    to_utctimestr( now_utime, time_width, now_time );

    /* try 32 bit counter */

#if defined( DEBUG )
    fprintf( stderr, "try %d group\n", GROUP_DIGITS );
#endif

    found = find_collision( now_utime, resource, bits, token,
			    GROUP_SIZE, rnd_str, "", ext );
    if ( found ) { goto done; }

    /* if exceed that try 64 bit counter */    

#if defined( DEBUG )
    fprintf( stderr, "try %d group\n", GROUP_DIGITS*2 );
#endif

    for ( i1=0, i1f=1; i1f || i1!=0; i1f=0,i1=(i1+1) & GROUP_SIZE) {
	sprintf( counter, GFFORMAT, i1 & GROUP_SIZE, 0 );
	found = find_collision( now_utime, resource, bits, token,
				GROUP_SIZE, rnd_str, counter, ext );
	if ( found ) { goto done; }
    }

    /* if exceed that try 96 bit counter */

#if defined( DEBUG )
    fprintf( stderr, "try %d group\n", GROUP_DIGITS*3 );
#endif

    for ( i0=0, i0f=1; i0f || i0!=0; i0f=0,i0=(i0+1) & GROUP_SIZE) {
	for ( i1=0, i1f=1; i1f || i1!=0; i1f=0,i1=(i1+1) & GROUP_SIZE) {
	    sprintf( counter, GFFORMAT GFORMAT, 
		     i0 & GROUP_SIZE, i1 & GROUP_SIZE );
	    found = find_collision( now_utime, resource, bits, token,
				    GROUP_SIZE, rnd_str, counter, ext );
	    if ( found ) { goto done; }
	}
    }

    /* shouldn't get here without trying  */
    /* for a very long time, 2^96 operations is a _lot_ of CPU */

    return HASHCASH_TOO_MANY_TRIES;

 done:
    
    *tries_taken = (double)i0 * (double)ULONG_MAX * (double)ULONG_MAX +
	(double)i1 * (double)ULONG_MAX + (double)found ;
    
    return HASHCASH_OK;
}

#define FORMAT_VERSION 1

static word32 find_collision( char utct[ MAX_UTCTIME+1 ], const char* resource, 
		       int bits, char* token, word32 tries, char* rnd_str,
		       char* counter, char *ext )
{
    char* hex = "0123456789abcdef";
    char ctry[ MAX_TOK+1 ];
    char* changing_part_of_try;
    SHA_CTX ctx;
    SHA_CTX precomputed_ctx;
    word32 i;
    int j;
    word32 trial;
    word32 tries2;
    int counter_len;
    int first, try_len, try_strlen;
    byte target_digest[ SHA_DIGEST_LENGTH ];
    byte try_digest[ SHA_DIGEST_LENGTH ];
    int partial_byte = bits & 7;
    int check_bytes;
    int partial_byte_index = 0;	/* suppress dumb warning */
    int partial_byte_mask = 0xFF; /* suppress dumb warning */
    char last_char;
   
    first = strlen( counter ) == 0 ? 1 : 0;
    trial = 0;

    memset( target_digest, 0, SHA_DIGEST_LENGTH );

    if ( partial_byte ) {
	partial_byte_index = bits / 8;
	partial_byte_mask = ~ (( 1 << (8 - (bits & 7))) -1 );
	check_bytes = partial_byte_index + 1;
	target_digest[ partial_byte_index ] &= partial_byte_mask;
    } else {
	check_bytes = bits / 8;
    }

    if ( !ext ) { ext = ""; }
    sprintf( ctry, "%d:%d:%s:%s:%s:%s:%s", 
	     FORMAT_VERSION, bits, utct, resource, ext, rnd_str, counter );

    try_len = (int)strlen( ctry );

/* length of try is fixed, GFORMAT is %08x, so move strlen outside loop */

    changing_part_of_try = ctry + try_len;

/* part of the ctx context can be precomputed as not all of the
   message is changing
*/

    tries2 = (int) ( (double) tries / 16.0 + 0.5 );
    for ( i = 0; i < tries2; i++, trial = (trial + 16) & GROUP_SIZE ) {
/* move precompute closer to the inner loop to precompute more */

	SHA1_Init( &precomputed_ctx );
	sprintf( changing_part_of_try, first ? GFFORMAT : GFORMAT, trial );
	try_strlen = try_len + (int)strlen( changing_part_of_try ); 
	SHA1_Update( &precomputed_ctx, ctry, try_strlen - 1 );

#if defined( DEBUG )
	fprintf( stderr, "try: %s\n", ctry );
#endif
	for ( j = 0; j < 16; j++ ) {
	    memcpy( &ctx, &precomputed_ctx, sizeof( SHA_CTX ) );
	    last_char = hex[ j ];
	    SHA1_Update( &ctx, &last_char, 1 );
	    SHA1_Final( try_digest, &ctx );

	    if ( bits > 7 ) {
		if ( try_digest[ 0 ] != target_digest[ 0 ] ) {
		    continue;
		}
	    }
	    if ( partial_byte ) {
		try_digest[ partial_byte_index ] &= partial_byte_mask;
	    }
	    if ( memcmp( target_digest, try_digest, check_bytes ) == 0 ) {
		ctry[ try_strlen-1 ] = hex[ j ];
		sstrncpy( token, ctry, MAX_TOK );
		return i * 16 + j + 1;
	    }
	}
    }
    return 0;
}

static time_t round_off( time_t now_time, int digits )
{
    struct tm* now;

    if ( digits != 2 && digits != 4 && 
	 digits != 6 && digits != 8 && digits != 10 ) {
	return now_time;
    }
    now = gmtime( &now_time );	/* still in UTC */

    switch ( digits ) {
    case 10: now->tm_mon = 0;
    case 8: now->tm_mday = 1;
    case 6: now->tm_hour = 0;
    case 4: now->tm_min = 0;
    case 2: now->tm_sec = 0;
    }
    return mk_utctime( now );
}

static int validity_to_width( time_t validity_period )
{
    int time_width = 6;		/* default YYMMDD */
    if ( validity_period < 0 ) { return 0; }
    if ( validity_period != 0 ) {
/* YYMMDDhhmmss or YYMMDDhhmm or YYMMDDhh or YYMMDD or YYMM or YY */
	if ( validity_period < 2*TIME_MINUTE ) { time_width = 12; } 
	else if ( validity_period < 2*TIME_HOUR ) { time_width = 10; }
	else if ( validity_period < 2*TIME_DAY ) { time_width = 8; }
	else if ( validity_period < 2*TIME_MONTH ) { time_width = 6; }
	else if ( validity_period < 2*TIME_YEAR ) { time_width = 4; }
	else { time_width = 2; }
    }
    return time_width;
}

/* all chars from ascii(33) to ascii(126) inclusive, minus : */

#define VALID_STR_CHARS "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"\
			"abcdefghijklmnopqrstuvwxyz"

static int hashcash_parse( const char* token, int* vers, int* bits, char* utct, 
		    int utct_max, char* token_resource, int res_max, 
		    char** ext, int ext_max ) 
{
    char ver_arr[MAX_VER+1];
    char bits_arr[3+1];
    char *bits_str = bits_arr, *ver = ver_arr;
    char *rnd = NULL, *cnt = NULL;
    char *str, *pstr, *state, *s;
    int ver_len, utct_len, res_len, bit_len, rnd_len, cnt_len, len;

    /* parse out the resource name component 
     * format:   ver:bits:utctime:resource:ext:rand:counter
     * where utctime is [YYMMDD[hhmm[ss]]] 
     * the resource may NOT include :s, if it needs to include
     * :s some encoding such as URL encoding must be used
     */

    if ( ext != NULL ) { *ext = NULL; }
    if ( !sstrtok( token, ":", &ver, MAX_VER, &ver_len, &state ) || 
	 !sstrtok( NULL, ":", &bits_str, 3, &bit_len, &state ) ||
	 !sstrtok( NULL, ":", &utct, utct_max, &utct_len, &state ) ||
	 !sstrtok( NULL, ":", &token_resource, res_max, &res_len, &state ) ||
	 !sstrtok( NULL, ":", ext, 0, &ext_max, &state ) ||
	 !sstrtok( NULL, ":", &rnd, 0, &rnd_len, &state ) ||
	 !sstrtok( NULL, ":", &cnt, 0, &cnt_len, &state ) ) {
	return 0; 
    }

    *vers = atoi( ver ); if ( *vers < 0 ) { return 0; }
    *bits = atoi( bits_str ); if ( *bits < 0 ) { return 0; }

    if ( strspn( rnd, VALID_STR_CHARS ) != rnd_len ||
	 strspn( cnt, VALID_STR_CHARS ) != cnt_len ) {
	return 0;
    }

    return 1;
}

static unsigned hashcash_count( const char* token )
{
    SHA_CTX ctx;
    byte target_digest[ SHA_DIGEST_LENGTH ];
    byte token_digest[ SHA_DIGEST_LENGTH ];
    char ver[MAX_VER+1];
    int vers;
    char* first_colon;
    char* second_colon;
    int ver_len;
    int i;
    int last;
    int collision_bits;

    first_colon = strchr( token, ':' );
    if ( first_colon == NULL ) { return 0; } /* should really fail */
    ver_len = (int)(first_colon - token);
    if ( ver_len > MAX_VER ) { return 0; }
    sstrncpy( ver, token, ver_len );
    vers = atoi( ver );
    if ( vers < 0 ) { return 0; }
    if ( vers != 1 ) { return 0; } /* unsupported version number */
    second_colon = strchr( first_colon+1, ':' );
    if ( second_colon == NULL ) { return 0; } /* should really fail */

    memset( target_digest, 0, SHA_DIGEST_LENGTH );

    SHA1_Init( &ctx );
    SHA1_Update( &ctx, token, strlen( token ) );
    SHA1_Final( token_digest, &ctx );
   
    for ( i = 0; 
	  i < SHA_DIGEST_LENGTH && token_digest[ i ] == target_digest[ i ]; 
	  i++ ) { 
    }
    
    last = i;
    collision_bits = 8 * i;

#define bit( n, c ) (((c) >> (7 - (n))) & 1)

    for ( i = 0; i < 8; i++ ) 
    {
	if ( bit( i, token_digest[ last ] ) == 
	     bit( i, target_digest[ last ] ) ) { 
	    collision_bits++; 
	} else { 
	    break; 
	}
    }
    return collision_bits;
}

static long hashcash_valid_for( time_t token_time, time_t validity_period, 
			 long grace_period, time_t now_time )
{
    long expiry_time;

    /* for ever -- return infinity */
    if ( validity_period == 0 )	{ return HASHCASH_VALID_FOREVER; }

    /* future date in token */
    if ( token_time > now_time + grace_period ) { 
	return HASHCASH_VALID_IN_FUTURE; 
    }

    expiry_time = token_time + validity_period;
    if ( expiry_time + grace_period > now_time ) {
				/* valid return seconds left */
	return expiry_time + grace_period - now_time;
    }
    return HASHCASH_EXPIRED;	/* otherwise expired */
}

#define REGEXP_DIFF "(|)"
#define REGEXP_UNSUP "{}"
#define REGEXP_SAME "\\.?[]*+^$"

#define MAX_RE_ERR 256

static int regexp_match( const char* str, const char* regexp, 
		  void** compile, char** err ) 
{
#if defined( REGEXP_BSD )
	char* q;
	const char *r;
	char* quoted_regexp = malloc( strlen( regexp ) * 2 + 3 );
	
	*err = NULL;
	
	if ( quoted_regexp == NULL ) { *err = "out of memory"; return 0; }

	q = quoted_regexp;
	r = regexp;

	if ( *r != '^' ) { *q++ = '^'; }
	
	for ( ; *r; *q++ = *r++ ) {
	    if ( *r == '\\' ) { 
		if ( strchr( REGEXP_SAME, *(r+1) ) ) {
		    *q++ = *r++; 	/* copy thru \\ unchanged */
		} else { 
		    r++; 		/* skip \c for any c other than \ */
		} 
	    } else if ( strchr( REGEXP_DIFF, *r ) ) {
		*q++ = '\\';
	    } else if ( strchr( REGEXP_UNSUP, *r ) ) {
		*err = "compiled with BSD regexp, {} not suppored";
		return 0;
	    }
	}
	if ( *(q-1) != '$' ) { *q++ = '$'; }
	*q = '\0';
	if ( ( *err = re_comp( quoted_regexp ) ) != NULL ) { return 0; }
	free( quoted_regexp );
	return re_exec( str );
#elif defined( REGEXP_POSIX )
	regex_t** comp = (regex_t**) compile;
	int re_code;
	char* bound_regexp;
	int re_len, bre_len;
	static char re_err[ MAX_RE_ERR+1 ];
	re_err[0] = '\0';
	
	if ( *comp == NULL ) {
	    *comp = malloc( sizeof(regex_t) );
	    if ( *comp == NULL ) { *err = "out of memory"; return 0; }
	    bre_len = re_len = strlen(regexp);
	    if ( regexp[0] != '^' || regexp[re_len-1] != '$' ) {
		bound_regexp = malloc( re_len+3 );
		if ( regexp[0] != '^' ) { 
		    bound_regexp[0] = '^';
		    sstrncpy( (bound_regexp+1), regexp, re_len );
		    bre_len++;
		} else {
		    sstrncpy( bound_regexp, regexp, re_len );
		}
		if ( regexp[re_len-1] != '$' ) {
		    bound_regexp[bre_len] = '$';
		    bound_regexp[bre_len+1] = '\0';
		}
	    } else {
		bound_regexp = (char*)regexp;
	    }

	    if ( ( re_code = regcomp( *comp, regexp, 
				      REG_EXTENDED | REG_NOSUB ) ) != 0 ) {
		regerror( re_code, *comp, re_err, MAX_RE_ERR );
		*err = re_err;
		if ( bound_regexp != regexp ) { free( bound_regexp ); }
		return 0;
	    }
	    if ( bound_regexp != regexp ) { free( bound_regexp ); }
	}
	return regexec( *comp, str, 0, NULL, 0 ) == 0;
#else
	*err = "regexps not supported on your platform, used -W wildcards";
	return 0;
#endif
}

static int resource_match( int type, const char* token_res, const char* res, 
		    void** compile, char** err ) 
{
    switch ( type ) {
    case TYPE_STR: 
	if ( strcmp( token_res, res ) != 0 ) { return 0; }
	break;
    case TYPE_WILD:
	if ( !email_match( token_res, res  ) ) { return 0; }
	break;
    case TYPE_REGEXP:
	if ( !regexp_match( token_res, res, compile, err ) ) { return 0; }
	break;
    default:
	return 0;
    }
    return 1;
}

int hashcash_check1( const char* token, const char* resource, void **compile,
		    char** re_err, int type, time_t now_time, 
		    time_t validity_period, long grace_period, 
		    int required_bits, time_t* token_time )
{
    time_t token_t;
    char token_utime[ MAX_UTC+1 ];
    char token_res[ MAX_RES+1 ];
    int bits = 0, claimed_bits = 0, vers = 0;
    
    if ( token_time == NULL ) { token_time = &token_t; }

    if ( !hashcash_parse( token, &vers, &claimed_bits, token_utime, 
			  MAX_UTC, token_res, MAX_RES, NULL, 0 ) ) {
	return HASHCASH_INVALID;
    }

    if ( vers != 1 ) {
	return HASHCASH_UNSUPPORTED_VERSION;
    }

    *token_time = from_utctimestr( token_utime, 1 );
    if ( *token_time == -1 ) {
	return HASHCASH_INVALID;
    }
    if ( resource && 
	 !resource_match( type, token_res, resource, compile, re_err ) ) {
	if ( *re_err != NULL ) { 
	    return HASHCASH_REGEXP_ERROR;
	} else {
	    return HASHCASH_WRONG_RESOURCE;
	}
    }
    bits = hashcash_count( token );
    if ( bits >= claimed_bits ) { bits = claimed_bits; }
    if ( bits < required_bits ) {
	return HASHCASH_INSUFFICIENT_BITS;
    }
    return hashcash_valid_for( *token_time, validity_period, 
			       grace_period, now_time );
}

#if 0

long hashcash_per_sec( void )
{
    timer t1, t2;
    double elapsed;
    unsigned long n_collisions = 0;
    char token[ MAX_TOK+1 ];
    word32 step = 100;

    /* wait for start of tick */

    timer_read( &t2 );
    do {
	timer_read( &t1 );
    } while ( timer_usecs( &t1 ) == timer_usecs( &t2 ) &&
	      timer_secs( &t1 ) == timer_secs( &t2 ) );

    /* do computations for next tick */

    do {
	n_collisions += step;
	find_collision( "000101", "flame", 25, token, step, "", "", "" );
	timer_read( &t2 );
    } while ( timer_usecs( &t1 ) == timer_usecs( &t2 ) &&
	      timer_secs( &t1 ) == timer_secs( &t2 ) );

/* see how many us the tick took */
    elapsed = timer_interval( &t1, &t2 );
    return (word32) ( 1000000.0 / elapsed * (double)n_collisions
		      + 0.499999999 );
}

double hashcash_estimate_time( int b )
{
    return hashcash_expected_tries( b ) / (double)hashcash_per_sec();
}

double hashcash_expected_tries( int b )
{
    double expected_tests = 1;
    #define CHUNK ( sizeof( unsigned long )*8 - 1 )
    for ( ; b > CHUNK; b -= CHUNK ) {
	expected_tests *= ((unsigned long)1) << CHUNK;
    }
    expected_tests *= ((unsigned long)1) << b;
    return expected_tests;
}
#endif



/******************************** UTCT **********************************/

static int char_pair_atoi( const char* pair )
{
    char str[3];
    str[0] = pair[0]; str[1] = pair[1]; str[2] = '\0';
    if ( !isdigit( str[0] ) || !isdigit( str[1] ) ) { return -1; }
    return atoi( str );
}

/* deal with 2 char year issue */
static int century_offset_to_year( int century_offset )
{
    time_t time_now = time( 0 ); /* local time */
    struct tm* now = gmtime( &time_now ); /* gmt broken down time */
    int current_year = now->tm_year + 1900;
    int current_century_offset = current_year % 100;
    int current_century = (current_year - current_century_offset) / 100;
    int year = current_century * 100 + century_offset;

    /* assume year is in current century */
    /* unless that leads to very old or very new, then adjust */ 
    if ( year - current_year > 50 ) { year -= 100; }
    else if ( year - current_year < -50 ) { year += 100; }
    return year;
}

#define MAX_DATE 50		/* Sun Mar 10 19:25:06 2002 (EST) */

/* more logical time_t to string conversion */

static const char* strtime( time_t* timep, int utc )
{
    static char str[MAX_DATE];
    struct tm* isdst;
    char date[MAX_DATE];
    char* timestr;
    char* zone;
    if ( utc ) {
	timestr = asctime( gmtime( timep ) );
	zone = "UTC";
    } else {
        isdst = localtime( timep );
	timestr = asctime( isdst );
	zone = tzname[isdst->tm_isdst];
    }
    sstrncpy( date, timestr, MAX_DATE );
    date[strlen(date)-1]='\0';	/* remove trailing \n */
    snprintf( str, MAX_DATE, "%s (%s)", date, zone );
    return str;
}

/* alternate form of mktime, this tm struct is in UTC time */

static time_t mk_utctime( struct tm* tms )
{
    char* tz = getenv( "TZ" );
    time_t res;
    char *set_tz;

    putenv( "TZ=UTC+0" );
    res = mktime( tms );
    if ( tz ) { 
        set_tz = malloc( strlen( tz ) + 3 + 1 );
        sprintf( set_tz, "TZ=%s", tz );
	putenv( set_tz );
	free( set_tz );
    } else { putenv( "TZ" ); }
    return res;
}

static time_t from_utctimestr( const char utct[MAX_UTCTIME+1], int utc )
{
    time_t failed = -1;
    time_t res;
    struct tm tms;
    int tms_hour;
    struct tm* dst;
    int utct_len = strlen( utct );
    int century_offset;

    if ( utct_len > MAX_UTCTIME || utct_len < 2 || ( utct_len % 2 == 1 ) ) {
	return failed;
    }

/* defaults */
    tms.tm_mon = 0; tms.tm_mday = 1;
    tms.tm_hour = 0; tms.tm_min = 0; tms.tm_sec = 0;
    tms.tm_isdst = 0;	/* daylight saving on */
    tms_hour = tms.tm_hour;

/* year */
    century_offset = char_pair_atoi( utct );
    if ( century_offset < 0 ) { return failed; }
    tms.tm_year = century_offset_to_year( century_offset ) - 1900;
/* month -- optional */
    if ( utct_len <= 2 ) { goto convert; }
    tms.tm_mon = char_pair_atoi( utct+2 ) - 1;
    if ( tms.tm_mon < 0 ) { return failed; }
/* day */
    if ( utct_len <= 4 ) { goto convert; }
    tms.tm_mday = char_pair_atoi( utct+4 );
    if ( tms.tm_mday < 0 ) { return failed; }
/* hour -- optional */
    if ( utct_len <= 6 ) { goto convert; }
    tms.tm_hour = char_pair_atoi( utct+6 );
    if ( tms.tm_hour < 0 ) { return failed; }
/* minute -- optional */
    if ( utct_len <= 8 ) { goto convert; }
    tms.tm_min = char_pair_atoi( utct+8 );
    if ( tms.tm_min < 0 ) { return failed; }
    if ( utct_len <= 10 ) { goto convert; }
/* second -- optional */
    tms.tm_sec = char_pair_atoi( utct+10 );
    if ( tms.tm_sec < 0 ) { return failed; }

 convert:
    if ( utc ) {
        return mk_utctime( &tms );
    } else {
    /* note when switching from daylight to standard the last daylight
       hour(s) are ambiguous with the first hour(s) of standard time.  The
       system calls give you the first hour(s) of standard time which is
       as good a choice as any. */

    /* note also the undefined hour(s) between the last hour of
       standard time and the first hour of daylight time (when
       expressed in localtime) are illegal values and have undefined
       conversions, this code will do whatever the system calls do */

        tms_hour = tms.tm_hour;
        res = mktime( &tms );	/* get time without DST adjust */
 	dst = localtime( &res ); /* convert back to get DST adjusted  */
	dst->tm_hour = tms_hour; /* put back in hour to convert */
 	res = mktime( dst ); /* redo conversion with DST adjustment  */
 	return res;
    }
}

static int to_utctimestr( char utct[MAX_UTCTIME+1], int len, time_t t  )
{
    struct tm* tms = gmtime( &t );

    if ( tms == NULL || len > MAX_UTCTIME || len < 2 ) { return 0; }
    sprintf( utct, "%02d", tms->tm_year % 100 );
    if ( len == 2 ) { goto leave; }
    sprintf( utct+2, "%02d", tms->tm_mon+1 );
    if ( len == 4 ) { goto leave; }
    sprintf( utct+4, "%02d", tms->tm_mday );
    if ( len == 6 ) { goto leave; }
    sprintf( utct+6, "%02d", tms->tm_hour );
    if ( len == 8 ) { goto leave; }
    sprintf( utct+8, "%02d", tms->tm_min ); 
    if ( len == 10 ) { goto leave; }
    sprintf( utct+10, "%02d", tms->tm_sec );

 leave:
    return 1;
}



/******************************** SSTRING **********************************/

/* strtok/strtok_r is a disaster, so here's a more sane one */

/* if *tok is NULL space is allocated; if the *tok is not NULL, and
 * the token is too large it is truncated; tok_len returns the length,
 * a pointer to **tok is also returned
 */

static char* sstrtok( const char* str, const char* delim, char** tok,
		int tok_max, int* tok_len, char** s )
{
    char *end;
    int use;

    if ( delim == NULL ) { return NULL; }
    if ( str != NULL ) { *s = (char*)str; }
    if ( **s == '\0' ) { return NULL; } /* consumed last token */
    end = strpbrk( *s, delim );
    if ( end == NULL ) { 
	*tok_len = strlen(*s);
    } else {
	*tok_len = end - *s;
    }

    if ( tok ) {
	if ( tok_max > 0 ) {
	    use = tok_max < *tok_len ? tok_max : *tok_len;
	} else {
	    use = *tok_len; 
	}
	if ( !*tok ) { *tok = malloc( use+1 ); }
	sstrncpy( *tok, *s, use ); 
    }
    *s += *tok_len + ( end == NULL ? 0 : 1 );
    return tok ? *tok : "";
}
