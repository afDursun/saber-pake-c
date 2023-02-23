#ifndef API_H
#define API_H
#include <stdint.h>
#include "SABER_params.h"
#include "poly.h"

#if SABER_L == 2
	#define CRYPTO_ALGNAME "LightSaber"
#elif SABER_L == 3
	#define CRYPTO_ALGNAME "Saber"
#elif SABER_L == 4
	#define CRYPTO_ALGNAME "FireSaber"
#else
	#error "Unsupported SABER parameter."
#endif

#define CRYPTO_SECRETKEYBYTES SABER_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES SABER_PUBLICKEYBYTES
#define CRYPTO_BYTES SABER_KEYBYTES
#define CRYPTO_CIPHERTEXTBYTES SABER_BYTES_CCA_DEC
//void pake_c0(uint8_t *pk, uint8_t *sk,uint8_t *pw,uint8_t *state,uint8_t *cid, uint8_t *sid, uint8_t *send,polyvec *gamma);

int pake_c0(uint8_t *pk, uint8_t *sk,uint8_t *pw,uint8_t *state,uint8_t *cid, uint8_t *sid, uint8_t *send,polyvec *gamma);
int pake_s0(unsigned char *send, const unsigned char *received, const polyvec *gamma, const unsigned char *sid, unsigned char *state,uint8_t *ct, uint8_t *ss,uint8_t *pkafd);
int pake_c1(unsigned char *sharedkey_c, unsigned char *k_3_c, const unsigned char *received, uint8_t *sk, uint8_t *pk ,unsigned char *state);
int pake_s1(unsigned char *sharedkey_s, const unsigned char *k_3_c, unsigned char *state);

int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#endif /* api_h */
