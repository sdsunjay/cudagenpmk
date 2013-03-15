/*
 * coWPAtty - Brute-force dictionary attack against WPA-PSK.
 *
 * Copyright (c) 2004-2005, Joshua Wright <jwright@hasborg.com>
 *
 * $Id: sha1.c,v 4.2 2008-03-20 16:49:38 jwright Exp $
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * coWPAtty is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * Significant code is graciously taken from the following:
 * wpa_supplicant by Jouni Malinen.  This tool would have been MUCH more
 * difficult for me if not for this code.  Thanks Jouni.
 *
 * i386 assembly SHA code taken from the umac.c message auth code by
 * Ted Krovetz (tdk@acm.org):
 * http://www.cs.ucdavis.edu/~rogaway/umac/umac.c
 * (dragorn)
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "common.h"
#include "sha1.h"
	__shared__ SHA1_CTX context[BLOCKSIZE];
   __shared__ SHA1_CACHE cached[BLOCKSIZE];

/* structs */
typedef struct {
   char pass[MAXPASSLEN];
} pw;

typedef struct {
   u8 key[32];
} pmk;

typedef struct {
   unsigned char buff[SHA1_MAC_LEN];
} buffer;

void sha1_mac(unsigned char *key, unsigned int key_len,
	      unsigned char *data, unsigned int data_len, unsigned char *mac)
{
	SHA1_CTX context;
	SHA1Init(&context);
	SHA1Update(&context, key, key_len);
	SHA1Update(&context, data, data_len);
	SHA1Update(&context, key, key_len);
	SHA1Final(&context, mac);
}

   /* hack, hack, hack */
   SHA1_CACHE cached2;

/* HMAC code is based on RFC 2104 
   Modifications (hacks) by Joshua Wright.  Optimized a bit for pbkdf2
   processing by caching values that are repetitive.  There is some repetitive
   code in this function, which I've retained to make it more readable (for my
   sanity's sake).
 */

void hmac_sha1_vector(unsigned char *key, unsigned int key_len,
		      size_t num_elem, unsigned char *addr[],
		      unsigned int *len, unsigned char *mac, int usecached)
{
	SHA1_CTX context;
	unsigned char k_ipad[65];	/* inner padding - key XORd with ipad */
	unsigned char k_opad[65];	/* outer padding - key XORd with opad */
	int i;

	/* the HMAC_SHA1 transform looks like:
	 *
	 * SHA1(K XOR opad, SHA1(K XOR ipad, text))
	 *
	 * where K is an n byte key
	 * ipad is the byte 0x36 repeated 64 times
	 * opad is the byte 0x5c repeated 64 times
	 * and text is the data being protected */

	if (usecached == NOCACHED || !cached2.k_ipad_set || !cached2.k_opad_set) {
		/* We either don't want to cache values, or we do want to cache but
		   haven't cached them yet. */

		/* start out by storing key in pads */
		memset(k_ipad, 0, sizeof(k_ipad));
		memset(k_opad, 0, sizeof(k_opad));
		memcpy(k_ipad, key, key_len);
		memcpy(k_opad, key, key_len);

		/* XOR key with ipad and opad values */
		for (i = 0; i < 64; i++) {
			k_ipad[i] ^= 0x36;
			k_opad[i] ^= 0x5c;
		}

		SHA1Init(&context);	/* init context for 1st pass */
		SHA1Update(&context, k_ipad, 64);	/* start with inner pad */

		if (usecached) {
			/* Cached the context value */
			memcpy(&cached2.k_ipad, &context, sizeof(context));
			cached2.k_ipad_set = 1;
		}

		/* then text of datagram; all fragments */

		for (i = 0; i < num_elem; i++) {
			SHA1Update(&context, addr[i], len[i]);
		}

		SHA1Final(&context, mac);	/* finish up 1st pass */

		/* perform outer SHA1 */
		SHA1Init(&context);	/* init context for 2nd pass */
		SHA1Update(&context, k_opad, 64);	/* start with outer pad */

		if (usecached) {
			/* Cached the context value */
			memcpy(&cached2.k_opad, &context, sizeof(context));
			cached2.k_opad_set = 1;
		}

		SHA1Update(&context, mac, 20);	/* then results of 1st hash */
		SHA1Final(&context, mac);	/* finish up 2nd pass */

		return;

	}

	/* End NOCACHED SHA1 processing */
	/* This code attempts to optimize the hmac-sha1 process by caching
	   values that remain constant for the same key.  This code is called
	   many times by pbkdf2, so all optimizations help. 

	   If we've gotten here, we want to use caching, and have already cached
	   the values for k_ipad and k_opad after SHA1Update. */

	memcpy(&context, &cached2.k_ipad, sizeof(context));
	for (i = 0; i < num_elem; i++) {
		SHA1Update(&context, addr[i], len[i]);
	}
	SHA1Final(&context, mac);

	memcpy(&context, &cached2.k_opad, sizeof(context));
	SHA1Update(&context, mac, 20);
	SHA1Final(&context, mac);
	return;
}

__inline__ __device__ int cudastrlen(char *str) {
   char* count = str;
   while (count[0] != '\0') {
      count++;
   }
   return count-str;
}


__device__ static void pbkdf2_sha1_f(char *passphrase, char *ssid,
			  size_t ssid_len, int count,
			  unsigned char *digest, int idx)
{
	unsigned char tmp[SHA1_MAC_LEN];
	int i, j;
	unsigned char count_buf[4];
	size_t passphrase_len = cudastrlen(passphrase);

	count_buf[0] = 0;
	count_buf[1] = 0;
	count_buf[2] = 0;
	count_buf[3] = count & 0xff;

	unsigned char k_ipad[65];	/* inner padding - key XORd with ipad */
	unsigned char k_opad[65];	/* outer padding - key XORd with opad */

	/* start out by storing key in pads */
	memset(k_ipad, 0, sizeof(k_ipad));
	memset(k_opad, 0, sizeof(k_opad));
	memcpy(k_ipad, passphrase, passphrase_len);
	memcpy(k_opad, passphrase, passphrase_len);

	/* XOR key with ipad and opad values */
	for (i = 0; i < 64; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	/* perform inner SHA1 */
	cuda_sha1_starts(&context[idx]);	/* init context for 1st pass */
	cuda_sha1_update(&context[idx], k_ipad, 64);	/* start with inner pad */

	/* Cached the context value */
	memcpy(&cached[idx].k_ipad, &context[idx], sizeof(context[idx]));

	cuda_sha1_update(&context[idx], (unsigned char *)ssid, ssid_len);
	cuda_sha1_update(&context[idx], count_buf, 4);
	cuda_sha1_finish(&context[idx], tmp);	/* finish up 1st pass */

	/* perform outer SHA1 */
	cuda_sha1_starts(&context[idx]);	/* init context for 2nd pass */
	cuda_sha1_update(&context[idx], k_opad, 64);	/* start with outer pad */

	/* Cached the context value */
	memcpy(&cached[idx].k_opad, &context[idx], sizeof(context[idx]));

	cuda_sha1_update(&context[idx], tmp, 20);	/* then results of 1st hash */
	cuda_sha1_finish(&context[idx], tmp);	/* finish up 2nd pass */
	memcpy(digest, tmp, SHA1_MAC_LEN);

	for (i = 1; i < 4096 ; i++) {
   	memcpy(&context[idx], &cached[idx].k_ipad, sizeof(context[idx]));
      cuda_sha1_update(&context[idx], tmp, SHA1_MAC_LEN);
	   cuda_sha1_finish(&context[idx], tmp);

   	memcpy(&context[idx], &cached[idx].k_opad, sizeof(context[idx]));
	   cuda_sha1_update(&context[idx], tmp, 20);
	   cuda_sha1_finish(&context[idx], tmp);

		for (j = 0; j < SHA1_MAC_LEN; j++)
			digest[j] ^= tmp[j];
	}

	/* clear the cached data set */
	//memset(&cached[idx], 0, sizeof(cached[idx]));
}

__global__ void pbkdf2_sha1(pw *passphrase, char *ssid, size_t ssid_len, pmk *pmks)
{
   int idx = blockIdx.x * blockDim.x + threadIdx.x;
	unsigned char digest[SHA1_MAC_LEN];
	 if(idx==0)
	 {
	 pbkdf2_sha1_f((char *)(passphrase[idx].pass), ssid, ssid_len, 1, digest, threadIdx.x);
	memcpy(pmks[idx].key, digest, SHA1_MAC_LEN);
	pbkdf2_sha1_f((char *)(passphrase[idx].pass), ssid, ssid_len, 2, digest, threadIdx.x);
	memcpy((pmks[idx].key+SHA1_MAC_LEN), digest, 12);
	 }
}

void hmac_sha1(unsigned char *key, unsigned int key_len,
	       unsigned char *data, unsigned int data_len,
	       unsigned char *mac, int usecached)
{
	hmac_sha1_vector(key, key_len, 1, &data, &data_len, mac, usecached);
}

void sha1_prf(unsigned char *key, unsigned int key_len,
	      char *label, unsigned char *data, unsigned int data_len,
	      unsigned char *buf, size_t buf_len)
{
	char zero = 0, counter = 0;
	size_t pos, plen;
	u8 hash[SHA1_MAC_LEN];
	size_t label_len = strlen(label);
	unsigned char *addr[] = { (unsigned char *)label, 
					(unsigned char *)&zero, 
					data,
					(unsigned char *)&counter };
	unsigned int len[] = { label_len, 1, data_len, 1 };

	pos = 0;
	while (pos < buf_len) {
		plen = buf_len - pos;
		if (plen >= SHA1_MAC_LEN) {
			hmac_sha1_vector(key, key_len, 4, addr, len,
					 &buf[pos], NOCACHED);
			pos += SHA1_MAC_LEN;
		} else {
			hmac_sha1_vector(key, key_len, 4, addr, len,
					 hash, NOCACHED);
			memcpy(&buf[pos], hash, plen);
			break;
		}
		counter++;
	}
}
