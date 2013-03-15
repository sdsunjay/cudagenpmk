/*
 * genpmk - Generate a file with precomputed PMK's and words
 *
 * Copyright (c) 2005, Joshua Wright <jwright@hasborg.com>
 *
 * $Id: genpmk.c,v 4.1 2008-03-20 16:49:38 jwright Exp $
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pcap.h>
#include <signal.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>

#include "common.h"
#include "genpmk.h"
//#include "utils.c"
#include "sha1.cu"
#define OUT "OUTPUT"
#define SSID "ATT256"
#define DICT "words"

#define MAGIC_NUMBER 1800

#define PROGNAME "genpmk"
#define VER "1.1"

/* Globals */
int sig = 0;			/* Used for handling signals */
char *words;

/* structs */
/* already declared in sha1.cu
typedef struct {
   char pass[MAXPASSLEN];
} pw;

typedef struct {
   u8 key[32];
} pmk;
*/
/* Prototypes */
void usage(char *message);
int nextword(char *word, FILE * fp);

void usage(char *message)
{

	if (strlen(message) > 0) {
		printf("%s: %s\n", PROGNAME, message);
	}

	printf("Usage: %s [options]\n", PROGNAME);
	printf("\n"
	       "\t-f \tDictionary file\n"
	       "\t-d \tOutput hash file\n"
	       "\t-s \tNetwork SSID\n"
	       "\t-h \tPrint this help information and exit\n"
	       "\t-v \tPrint verbose information (more -v for more verbosity)\n"
	       "\t-V \tPrint program version and exit\n" "\n");
	printf("After precomputing the hash file, run cowpatty with the -d "
		"argument.\n");
}

void cleanup()
{
	/* lame-o-meter++ */
	sig = 1;
}


int nextword(char *word, FILE * fp)
{

	if (fgets(word, MAXPASSLEN + 1, fp) == NULL) {
		return (-1);
	}

	/* Remove newline */
	word[strlen(word) - 1] = '\0';

	if (feof(fp)) {
		return (-1);
	}

	return (strlen(word));
}

int main(int argc, char **argv)
{
	int c, ret;
	unsigned long int wordstested=0;
	float elapsed = 0;
	char passphrase[MAXPASSLEN + 1];
	struct user_opt opt;
	struct hashdb_head hf_header;
	struct stat teststat;
	FILE *fpin = NULL, *fpout = NULL;
	struct timeval start, end;

	printf("%s %s - WPA-PSK precomputation attack. <jwright@hasborg.com>\n",
	       PROGNAME, VER);

	memset(&opt, 0, sizeof(opt));
	memset(&hf_header, 0, sizeof(hf_header));
		
	 fpin = fopen(DICT, "r");


	 /* stat the hashfile, if it exists, print a message and check to
	    ensure specified SSID matches header information.  If so, append
	    new words to the end of the hashdb file.
	    If the file does not exist, populate the hashdb_head record and
	    create the file. */

	 printf("File %s does not exist, creating.\n", OUT);
	 memcpy(hf_header.ssid, SSID, strlen(SSID));
	 hf_header.ssidlen = strlen(SSID);
	 hf_header.magic = GENPMKMAGIC;

	 fpout = fopen(OUT, "wb");
	 if (fpout == NULL) {
	    perror("fopen");
	    exit(-1);
	 }

	 if (fwrite(&hf_header, sizeof(hf_header), 1, fpout) != 1) {
	    perror("fwrite");
	    exit(-1);
	 }

	 /* Populate capdata struct */

	 gettimeofday(&start, 0);

	 int numWords = 0;

	 pw *passphrases = (pw*) calloc(2, sizeof(pw));
	 pmk *pmks = (pmk*) calloc(2, sizeof(pmk));
	 int i;


	 nextword(passphrases[0].pass, fpin);
	 printf("launching kernel\n");
	 pw *pass_d;
	 pmk *pmks_d;
	 char *ssid_d;

	 pw *orig_pass = passphrases;
	 pmk *orig_pmks = pmks;


	 cudaMalloc((void **) &pass_d, sizeof(pw));
	 cudaMalloc((void **) &pmks_d, sizeof(pmk));
	 cudaMalloc((void **) &ssid_d, strlen(SSID)+1);

	    cudaMemcpy(pass_d, passphrases,sizeof(pw), cudaMemcpyHostToDevice);
	    cudaMemcpy(pmks_d, pmks, sizeof(pmk), cudaMemcpyHostToDevice);
	    cudaMemcpy(ssid_d, SSID, strlen(SSID)+1, cudaMemcpyHostToDevice);

	    pbkdf2_sha1 <<< MAGIC_NUMBER/BLOCKSIZE, BLOCKSIZE >>> (pass_d, ssid_d, strlen(SSID), pmks_d);

	    cudaMemcpy(pmks, pmks_d, sizeof(pmk), cudaMemcpyDeviceToHost);

	   // passphrases += ((numWords>MAGIC_NUMBER)?MAGIC_NUMBER:numWords);
	    //pmks += ((numWords>MAGIC_NUMBER)?MAGIC_NUMBER:numWords);
	    //numWords-=MAGIC_NUMBER;
	 //}

	 passphrases = orig_pass;
	 pmks = orig_pmks;

	 //for (i = 0; i < wordstested; i++) {
	    printf("record size:%u, password:\"%s\" pmk:", (uint)(strlen(passphrases[0].pass) + sizeof(pmks[i].key) + 1), passphrases[0].pass);
	    int j;
	    for (j = 0; j < 32; j++) 
	       printf("%02X", pmks[0].key[j]);
	    printf("\n");
	// }

	 /*
	 for (i = 0; i < wordstested; i++) {
	    //Write the record contents to the file 
	    u8 size = strlen(passphrases[i].pass) + sizeof(pmks[i].key) + 1;
	    if (fwrite(&size, 1 , 1, fpout) != 1) {
	       perror("fwrite");
	       break;
	    }
	    if (fwrite(passphrases[i].pass, strlen(passphrases[i].pass), 1, fpout) != 1) {
	       perror("fwrite");
	       break;
	    }
	    if (fwrite(pmks[i].key, sizeof(pmks[i].key), 1, fpout) != 1) {
	       perror("fwrite");
	       break;
	    }
	 }
*/
	 if (fclose(fpin) != 0) {
	    perror("fclose");
	    exit(-1);
	 }
	 if (fclose(fpout) != 0) {
	    perror("fclose");
	    exit(-1);
	 }

	 gettimeofday(&end, 0);

	 /* print time elapsed */
	 if (end.tv_usec < start.tv_usec) {
	    end.tv_sec -= 1;
	    end.tv_usec += 1000000;
	 }
	 end.tv_sec -= start.tv_sec;
	 end.tv_usec -= start.tv_usec;
	 elapsed = end.tv_sec + end.tv_usec / 1000000.0;

	 printf("\n%lu passphrases tested in %.2f seconds:  %.2f passphrases/"
	       "second\n", wordstested, elapsed, 1 / elapsed);

	 return (0);
}
