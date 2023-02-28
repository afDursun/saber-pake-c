#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "api.h"
#include "poly.h"
#include "rng.h"
#include "SABER_indcpa.h"
#include "verify.h"
#include "SABER_indcpa.h"
#include "cpucycles.c"
#include "cpucycles1.c"
#include "cpucycles1.h"
#include <sys/time.h>
#include "speed_print.h"
#include "rng.h"
#include "fips202.h"
// void fprintBstr(char *S, unsigned char *A, unsigned long long L)
// {
// 	unsigned long long  i;

// 	printf("%s", S);

// 	for ( i=0; i<L; i++ )
// 		printf("%02X", A[i]);

// 	if ( L == 0 )
// 		printf("00");

// 	printf("\n");
// }

uint64_t clock1,clock2;
uint64_t clock_kp_mv,clock_cl_mv, clock_kp_sm, clock_cl_sm;


#define h1 (1 << (SABER_EQ - SABER_EP - 1))
#define h2 ((1 << (SABER_EP - 2)) - (1 << (SABER_EP - SABER_ET - 1)) + (1 << (SABER_EQ - SABER_EP - 1)))



static int cmp_uint64(const void *a, const void *b) {
	if(*(uint64_t *)a < *(uint64_t *)b) return -1;
	if(*(uint64_t *)a > *(uint64_t *)b) return 1;
	return 0;
}

static uint64_t median(uint64_t *l, size_t llen) {
	qsort(l,llen,sizeof(uint64_t),cmp_uint64);

	if(llen%2) return l[llen/2];
	else return (l[llen/2-1]+l[llen/2])/2;
}

static uint64_t average(uint64_t *t, size_t tlen) {
	size_t i;
	uint64_t acc=0;

	for(i=0;i<tlen;i++)
		acc += t[i];

	return acc/tlen;
}

void print_results(const char *s, uint64_t *t, size_t tlen) {
	size_t i;
	static uint64_t overhead = -1;

	if(tlen < 2) {
		fprintf(stderr, "ERROR: Need a least two cycle counts!\n");
		return;
	}

	if(overhead  == (uint64_t)-1)
		overhead = cpucycles_overhead1();

	tlen--;
	for(i=0;i<tlen;++i)
		t[i] = t[i+1] - t[i] - overhead;

	printf("%s\n", s);
	printf("median: %llu cycles/ticks\n", (unsigned long long)median(t, tlen));
	printf("average: %llu cycles/ticks\n", (unsigned long long)average(t, tlen));
	printf("\n");
}



static int test_kem_cca()
{



	struct timeval timeval_start, timeval_end;
	uint64_t i, j, repeat;
	repeat=1000;	
	uint64_t CLOCK1,CLOCK2;
	uint64_t CLOCK_c0,CLOCK_s0,CLOCK_c1,CLOCK_s1;

	CLOCK1 = 0;
	CLOCK2 = 0;
	CLOCK_c0 = CLOCK_s0 = CLOCK_c1 = CLOCK_s1 = 0;
	clock_kp_mv=clock_cl_mv=0;
	clock_kp_sm = clock_cl_sm = 0;



	srand(time(NULL));

	uint8_t pk[CRYPTO_PUBLICKEYBYTES];
	uint8_t sk[CRYPTO_SECRETKEYBYTES];
	uint8_t ct[CRYPTO_CIPHERTEXTBYTES];	
	uint8_t ss_a[CRYPTO_BYTES], ss_b[CRYPTO_BYTES];

	unsigned char entropy_input[48];

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

	printf("SABER_INDCPA_PUBLICKEYBYTES=%d\n", SABER_INDCPA_PUBLICKEYBYTES);
	printf("SABER_INDCPA_SECRETKEYBYTES=%d\n", SABER_INDCPA_SECRETKEYBYTES);
	printf("SABER_PUBLICKEYBYTES=%d\n", SABER_PUBLICKEYBYTES);
	printf("SABER_SECRETKEYBYTES=%d\n", SABER_SECRETKEYBYTES);
	printf("SABER_KEYBYTES=%d\n", SABER_KEYBYTES);
	printf("SABER_HASHBYTES=%d\n", SABER_HASHBYTES);
	printf("SABER_BYTES_CCA_DEC=%d\n", SABER_BYTES_CCA_DEC);
	printf("\n");
	uint64_t t[repeat];

	uint16_t A[SABER_L][SABER_L][SABER_N];
	uint8_t seed_A[SABER_SEEDBYTES];
	uint8_t seed_s[SABER_NOISE_SEEDBYTES];
	uint16_t s[SABER_L][SABER_N];
	uint16_t b[SABER_L][SABER_N] = {0};
	uint16_t vp[SABER_N] = {0};
	uint8_t nonce = 0;


	randombytes(seed_A, SABER_SEEDBYTES);
	shake128(seed_A, SABER_SEEDBYTES, seed_A, SABER_SEEDBYTES); // for not revealing system RNG state
	randombytes(seed_s, SABER_NOISE_SEEDBYTES);
	

	//c0
	gettimeofday(&timeval_start, NULL);
	for(i=0; i< repeat; i++){
		t[i] = cpucycles();
		GenMatrix(A, seed_A);
	}
	gettimeofday(&timeval_end, NULL);
	printf("The average time of GenMatrix:\t %.3lf us \n", ((timeval_end.tv_usec + timeval_end.tv_sec * 	1000000) - (timeval_start.tv_sec * 1000000 + timeval_start.tv_usec)) / (repeat * 1.0));
	print_results("GenMatrix: ", t, repeat);
	printf("----------------------\n");


  	//s0
	gettimeofday(&timeval_start, NULL);
	for(i=0; i< repeat; i++){
		t[i] = cpucycles();
		GenSecret(s, seed_s);
	}
	gettimeofday(&timeval_end, NULL);
	printf("The average time of GenSecret:\t %.3lf us \n", ((timeval_end.tv_usec + timeval_end.tv_sec * 	1000000) - (timeval_start.tv_sec * 1000000 + timeval_start.tv_usec)) / (repeat * 1.0));
	print_results("GenSecret: ", t, repeat);
	printf("----------------------\n");

	//******************************************************
	gettimeofday(&timeval_start, NULL);
	for(i=0; i< repeat; i++){
		t[i] = cpucycles();
		shake128(seed_A, SABER_SEEDBYTES, seed_A, SABER_SEEDBYTES);
	}
	gettimeofday(&timeval_end, NULL);
	printf("The average time of shake128:\t %.3lf us \n", ((timeval_end.tv_usec + timeval_end.tv_sec * 	1000000) - (timeval_start.tv_sec * 1000000 + timeval_start.tv_usec)) / (repeat * 1.0));
	print_results("shake128: ", t, repeat);
	printf("----------------------\n");
	
	
	//******************************************************
	gettimeofday(&timeval_start, NULL);
	for(i=0; i< repeat; i++){
		t[i] = cpucycles();
		sha3_256(seed_A, seed_A, SABER_SEEDBYTES);
	}
	gettimeofday(&timeval_end, NULL);
	printf("The average time of sha3_256:\t %.3lf us \n", ((timeval_end.tv_usec + timeval_end.tv_sec * 	1000000) - (timeval_start.tv_sec * 1000000 + timeval_start.tv_usec)) / (repeat * 1.0));
	print_results("sha3_256: ", t, repeat);
	printf("----------------------\n");

 	//******************************************************
	gettimeofday(&timeval_start, NULL);
	for(i=0; i< repeat; i++){
		t[i] = cpucycles();
		MatrixVectorMul(A, s, b, 1);
	}
	gettimeofday(&timeval_end, NULL);
	printf("The average time of MatrixVectorMul\t %.3lf us \n", ((timeval_end.tv_usec + timeval_end.tv_sec * 	1000000) - (timeval_start.tv_sec * 1000000 + timeval_start.tv_usec)) / (repeat * 1.0));
	print_results("MatrixVectorMul: ", t, repeat);
	printf("----------------------\n");

	for (i = 0; i < SABER_L; i++)
	{
		for (j = 0; j < SABER_N; j++)
		{
			b[i][j] = (b[i][j] + h1) >> (SABER_EQ - SABER_EP);
		}
	}

	//******************************************************
	gettimeofday(&timeval_start, NULL);
	for(i=0; i< repeat; i++){
		t[i] = cpucycles();
		POLVECq2BS(sk, s);
	}
	gettimeofday(&timeval_end, NULL);
	printf("The average time of POLVECq2BS\t %.3lf us \n", ((timeval_end.tv_usec + timeval_end.tv_sec * 	1000000) - (timeval_start.tv_sec * 1000000 + timeval_start.tv_usec)) / (repeat * 1.0));
	print_results("POLVECq2BS: ", t, repeat);
	printf("----------------------\n");


	//******************************************************
	gettimeofday(&timeval_start, NULL);
	for(i=0; i< repeat; i++){
		t[i] = cpucycles();
		POLVECp2BS(pk, b);
	}
	gettimeofday(&timeval_end, NULL);
	printf("The average time of POLVECp2BS\t %.3lf us \n", ((timeval_end.tv_usec + timeval_end.tv_sec * 	1000000) - (timeval_start.tv_sec * 1000000 + timeval_start.tv_usec)) / (repeat * 1.0));
	print_results("POLVECp2BS: ", t, repeat);
	printf("----------------------\n");



	//******************************************************
	gettimeofday(&timeval_start, NULL);
	for(i=0; i< repeat; i++){
		t[i] = cpucycles();
		InnerProd(b, s, vp);
	}
	gettimeofday(&timeval_end, NULL);
	printf("The average time of InnerProd\t %.3lf us \n", ((timeval_end.tv_usec + timeval_end.tv_sec * 	1000000) - (timeval_start.tv_sec * 1000000 + timeval_start.tv_usec)) / (repeat * 1.0));
	print_results("InnerProd: ", t, repeat);
	printf("----------------------\n");
	

	//******************************************************
	gettimeofday(&timeval_start, NULL);
	for(i=0; i< repeat; i++){
		t[i] = cpucycles();
		InnerProd(b, s, vp);
	}
	gettimeofday(&timeval_end, NULL);
	printf("The average time of InnerProd\t %.3lf us \n", ((timeval_end.tv_usec + timeval_end.tv_sec * 	1000000) - (timeval_start.tv_sec * 1000000 + timeval_start.tv_usec)) / (repeat * 1.0));
	print_results("InnerProd: ", t, repeat);
	printf("----------------------\n");
	
	pake_c0(pk, sk,pw,state_1,cid,sid,send_c0,&gamma);
	//******************************************************
	gettimeofday(&timeval_start, NULL);
	for(i=0; i< repeat; i++){
		t[i] = cpucycles();
		crypto_kem_enc(ct,ss_a,pk);
	}
	gettimeofday(&timeval_end, NULL);
	printf("The average time of crypto_kem_enc\t %.3lf us \n", ((timeval_end.tv_usec + timeval_end.tv_sec * 	1000000) - (timeval_start.tv_sec * 1000000 + timeval_start.tv_usec)) / (repeat * 1.0));
	print_results("crypto_kem_enc: ", t, repeat);
	printf("----------------------\n");


	//******************************************************
	gettimeofday(&timeval_start, NULL);
	for(i=0; i< repeat; i++){
		t[i] = cpucycles();
		crypto_kem_dec(ss_b,ct,sk);
	}
	gettimeofday(&timeval_end, NULL);
	printf("The average time of crypto_kem_enc\t %.3lf us \n", ((timeval_end.tv_usec + timeval_end.tv_sec * 	1000000) - (timeval_start.tv_sec * 1000000 + timeval_start.tv_usec)) / (repeat * 1.0));
	print_results("crypto_kem_enc: ", t, repeat);
	printf("----------------------\n");
	


	return 0;
}

int main()
{
	test_kem_cca();
	return 0;
}
