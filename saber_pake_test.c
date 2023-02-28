#include "api.h"
#include "poly.h"
#include "rng.h"
#include "SABER_indcpa.h"
#include "verify.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

char *showhex(uint8_t a[], int size) {


	char *s = malloc(size * 2 + 1);

	for (int i = 0; i < size; i++)
		sprintf(s + i * 2, "%02x", a[i]);

	return(s);
}

static int test_kem_cca()
{

	srand(time(NULL));

	uint8_t pk[CRYPTO_PUBLICKEYBYTES];
	uint8_t sk[CRYPTO_SECRETKEYBYTES];
	uint8_t ct[CRYPTO_CIPHERTEXTBYTES];	
	uint8_t ss_a[CRYPTO_BYTES], ss_b[CRYPTO_BYTES];

	unsigned char entropy_input[48];
	uint64_t i;
	for (i=0; i<48; i++)
		entropy_input[i] = rand(); 
	
	randombytes_init(entropy_input, NULL, 256);


	//Pake Parametres
	uint8_t pw[SABER_PWBYTES];
	uint8_t cid[SABER_IDBYTES];
	uint8_t sid[SABER_IDBYTES];
	uint8_t send_c0[PAKE_SENDC0];
	uint8_t send_s0[PAKE_SENDS0];
	uint8_t key_a[SABER_KEYBYTES];
	unsigned char state_1[HASH_BYTES+3] ={0};
	unsigned char state_2[HASH_BYTES+3] ={0};
	polyvec gamma;


	uint8_t session_key_c[SABER_KEYBYTES];
	uint8_t session_key_s[SABER_KEYBYTES];
	int8_t k_prime[SABER_KEYBYTES];
	
	for(i = 0 ; i < SABER_IDBYTES ; i++){
		pw[i] = 1;
		cid[i] = 2;
		sid[i] = 3;
	}

	pake_c0(pk, sk,pw,state_1,cid,sid,send_c0,&gamma);

	pake_s0(send_s0, send_c0, &gamma, sid, state_2,ct,key_a,pk);

	pake_c1(session_key_c, k_prime, send_s0, sk , pk , state_1);

	pake_s1(session_key_s, k_prime, state_2);



	printf("Session Key Client: %s\n",showhex(session_key_c,32));
	printf("Session Key Server: %s\n",showhex(session_key_s,32));	


	return 0;
}



int main()
{

	test_kem_cca();
	return 0;
}
