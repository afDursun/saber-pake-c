#include "SABER_params.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "SABER_indcpa.h"
#include "api.h"
#include "verify.h"
#include "rng.h"
#include "fips202.h"
#include "SABER_indcpa.h"
#include "poly.h"
#include "pack_unpack.h"

#define h1 (1 << (SABER_EQ - SABER_EP - 1))
#define h2 ((1 << (SABER_EP - 2)) - (1 << (SABER_EP - SABER_ET - 1)) + (1 << (SABER_EQ - SABER_EP - 1)))

void printKey(uint8_t *a, int sizeArray){
  int i ;
  printf("\n------------\n");
  for(i = 0 ; i< sizeArray; i++){
    printf("%u,",a[i]);
  }
}
void printArray(uint16_t a[SABER_L][SABER_N], int sizeArray){
  int i ;
  printf("\n------------\n");
  for(i = 0 ; i< sizeArray; i++){
    printf("%u,",a[0][i]);
  }
}

void encode_c0(unsigned char *r, const unsigned char *m, const unsigned char *seed, const unsigned char *cid)
{
  int i;


  for ( i = 0; i < SABER_POLYVECBYTES; i++)
    r[i] = m[i];

  for ( i = 0; i < SABER_SEEDBYTES; i++)
    r[i + SABER_POLYVECBYTES ] = seed[i];

  for ( i = 0; i < SABER_IDBYTES; i++)
    r[SABER_POLYVECBYTES + SABER_SEEDBYTES + i] = cid[i];

}
void decode_c0(uint16_t m[SABER_L][SABER_N], unsigned char *seed, unsigned char *cid, const unsigned char *r)
{
  int i;
  BS2POLVECq(r,m);
  for(i = 0; i<SABER_SEEDBYTES; i++)
    seed[i] = r[i + SABER_POLYVECBYTES];
  for(i = 0; i<SABER_IDBYTES;i++)
    cid[i] = r[i + SABER_POLYVECBYTES + SABER_SEEDBYTES];

}
void encode_s0(unsigned char *r, const unsigned char *y_c, const unsigned char *c,const unsigned char *k)
{ 
  int i;

  for(i = 0; i< SABER_POLYVECBYTES; i++)
    r[i] = y_c[i];
  for(i = 0 ; i < CRYPTO_CIPHERTEXTBYTES ; i++)
    r[i+SABER_POLYVECBYTES] = c[i];

  for(i = 0; i< SABER_KEYBYTES; i++)
    r[i + SABER_POLYVECBYTES + CRYPTO_CIPHERTEXTBYTES] =  k[i];
}
void decode_s0(uint8_t *yc_bytes, uint8_t *c, unsigned char *k, const unsigned char *r)
{
  int i;

  for(i = 0; i <SABER_POLYVECBYTES;i++)
    yc_bytes[i] = r[i];

  for(i = 0; i< CRYPTO_CIPHERTEXTBYTES;i++)
    c[i] = r[i  + SABER_POLYVECBYTES];


  for(i = 0; i< SABER_KEYBYTES;i++)
    k[i] = r[i + SABER_POLYVECBYTES + CRYPTO_CIPHERTEXTBYTES];

}


void hash_pw(uint16_t a[SABER_N], const unsigned char *seed, unsigned char nonce)
{
  unsigned int pos = 0, ctr = 0;
  uint16_t val;
  unsigned int nblocks=4;
  uint8_t buf[SHAKE128_RATE*nblocks];
  int i;
  unsigned char extseed[SABER_SEEDBYTES+1];

  uint64_t state[25];

  for(i=0;i<SABER_SEEDBYTES;i++){
    extseed[i] = seed[i];
  }

  extseed[SABER_SEEDBYTES] = nonce;


  shake128_absorb(state,extseed,SABER_SEEDBYTES+1);
  shake128_squeezeblocks(buf,nblocks,state);

  while(ctr < SABER_N)
  {
    val = (buf[pos] | ((uint16_t) buf[pos+1] << 8)) & 0x1fff;
    if(val < SABER_Q)
    {
      a[ctr++] = val;
    }
    pos += 2;

    if(pos > SHAKE128_RATE*nblocks-2)
    {
      nblocks = 1;
      pos = 0;
    }
  }

}

void hash_vec_frompw(uint16_t gamma[SABER_L][SABER_N], const unsigned char *pw, unsigned char nonce)
{
  int i;
  for(i = 0; i< SABER_L;i++)
  {
    hash_pw(gamma[i], pw, nonce++);
  }
} 


int pake_c0(uint8_t *pk, uint8_t *sk,uint8_t *pw,uint8_t *state,uint8_t *cid, uint8_t *sid, uint8_t *send,polyvec *gamma)
{
  int i,j;
  uint16_t A[SABER_L][SABER_L][SABER_N];
  uint16_t s[SABER_L][SABER_N];

  uint16_t m[SABER_L][SABER_N];
  uint16_t b[SABER_L][SABER_N] = {0};

  uint8_t seed_A[SABER_SEEDBYTES];
  uint8_t seed_s[SABER_NOISE_SEEDBYTES];
  uint8_t nonce = 0;
  uint8_t mbytes[SABER_POLYVECBYTES];
  uint8_t gammabytes[SABER_POLYVECBYTES];

  randombytes(seed_A, SABER_SEEDBYTES);
  shake128(seed_A, SABER_SEEDBYTES, seed_A, SABER_SEEDBYTES); // for not revealing system RNG state
  randombytes(seed_s, SABER_NOISE_SEEDBYTES);

  GenMatrix(A, seed_A);
  GenSecret(s, seed_s);
  MatrixVectorMul(A, s, b, 1);

  for (i = 0; i < SABER_L; i++)
  {
    for (j = 0; j < SABER_N; j++)
    {
      b[i][j] = ((b[i][j] + h1) >> (SABER_EQ - SABER_EP)) ;
    }
  }

  POLVECq2BS(sk, s);
  POLVECp2BS(pk, b);
  memcpy(pk + SABER_POLYVECCOMPRESSEDBYTES, seed_A, sizeof(seed_A));

  hash_vec_frompw(gamma, pw, nonce);

  for (i = 0; i < SABER_L; i++){
    for (j = 0; j < SABER_N; j++){
      m[i][j] = (gamma->vec[i].coeffs[j] + b[i][j]) % SABER_Q;
      gamma->vec[i].coeffs[j] = SABER_Q - gamma->vec[i].coeffs[j];

    }
  }


  for (i = 0; i < SABER_IDBYTES; i++)
  {
    state[i] = cid[i];
    state[i + SABER_IDBYTES] = sid[i];
  }



  POLVECq2BS(mbytes,m);
  for (i = 0; i < SABER_POLYVECBYTES; i++)
    state[i+2*SABER_IDBYTES] = mbytes[i];


  POLVECq2BS(gammabytes,gamma);
  for (i = 0; i < SABER_POLYVECBYTES; i++)
    state[i+2*SABER_IDBYTES+SABER_POLYVECBYTES] = gammabytes[i];


  encode_c0(send, mbytes, seed_A, cid);


  for (i = 0; i < SABER_INDCPA_PUBLICKEYBYTES; i++)
    sk[i + SABER_INDCPA_SECRETKEYBYTES] = pk[i]; 

  sha3_256(sk + SABER_SECRETKEYBYTES - 64, pk, SABER_INDCPA_PUBLICKEYBYTES); // Then hash(pk) is appended.

  randombytes(sk + SABER_SECRETKEYBYTES - SABER_KEYBYTES, SABER_KEYBYTES); // Remaining part of sk contains a pseudo-random number.

}


int pake_s0(unsigned char *send, const unsigned char *received, const polyvec *gamma, const unsigned char *sid, unsigned char *state,uint8_t *ct, uint8_t *ss,uint8_t *pkafd)
{
  uint8_t pk_s0[CRYPTO_PUBLICKEYBYTES];
  uint16_t m[SABER_L][SABER_N];
  uint16_t y_c[SABER_L][SABER_N];
  int i,j,counter = 0;
  unsigned char seed[SABER_SEEDBYTES];
  unsigned char cid[SABER_IDBYTES];
  unsigned char mbytes[SABER_POLYVECBYTES];
  unsigned char gammabytes[SABER_POLYVECBYTES];
  unsigned char yc_bytes[SABER_POLYVECBYTES];
  decode_c0(m, seed, cid, received);


  for (i = 0; i < SABER_L; i++) {
    for (j = 0; j < SABER_N ; j++) {
      if (m[i][j] > SABER_Q) {
        counter++;
      }
    }
  }

  if(counter==0){
    for(i = 0 ; i < SABER_L ; i++){
      for(j = 0 ; j < SABER_N ; j++){
        y_c[i][j] = (m[i][j] + gamma->vec[i].coeffs[j]) % SABER_Q; 
      }
    }

    POLVECp2BS(pk_s0, y_c);
    memcpy(pk_s0 + SABER_POLYVECCOMPRESSEDBYTES, seed, sizeof(seed));
    

    crypto_kem_enc(ct,ss,pkafd);

    for (i = 0; i < SABER_IDBYTES; i++) {
      state[i] = cid[i];
      state[i + SABER_IDBYTES] = sid[i];
    }

    POLVECq2BS(mbytes,m);

    for (i = 0; i < SABER_POLYVECBYTES; i++)
      state[i+2*SABER_IDBYTES] = mbytes[i];

    POLVECq2BS(gammabytes,gamma);
    

    for (i = 0; i < SABER_POLYVECBYTES; i++)
      state[i+2*SABER_IDBYTES+SABER_POLYVECBYTES] = gammabytes[i];

    POLVECp2BS(yc_bytes,y_c);
    for (i = 0; i < SABER_POLYVECBYTES; i++)
      state[i+2*SABER_IDBYTES+(2*SABER_POLYVECBYTES)] = yc_bytes[i];


    for (i = 0; i < SABER_IDBYTES; i++)
      state[i+2*SABER_IDBYTES+(3*SABER_POLYVECBYTES)] = ss[i];


    encode_s0(send, yc_bytes, ct ,ss);
    return (0);
  }
  else{
    return (1);
  }
}


int pake_c1(unsigned char *sharedkey_c, unsigned char *k_prime, const unsigned char *received, uint8_t *sk, uint8_t *pk ,unsigned char *state){
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t yc_bytes[SABER_POLYVECBYTES];
  uint8_t decode_k[SABER_KEYBYTES];
  uint8_t decapsulation_k[SABER_KEYBYTES];

  uint16_t p_key[SABER_L][SABER_N];
  uint16_t p_key_c0[SABER_L][SABER_N];
  int i,j,counter=0;

  decode_s0(yc_bytes,ct,decode_k,received);

  BS2POLVECp(yc_bytes,p_key);
  BS2POLVECp(pk,p_key_c0);


  for (i = 0; i < SABER_L; i++) {
    for (j = 0; j < SABER_N; j++) {
      if (p_key_c0[i][j] != p_key[i][j]) {
        counter++;
      }
    }
  }
  if(counter==0){
    crypto_kem_dec(decapsulation_k,ct,sk);
    
    if(memcmp(decapsulation_k, decode_k, 32) == 0){
      for (i = 0; i < SABER_POLYVECBYTES; i++)
          state[i+2*SABER_IDBYTES+(2*SABER_POLYVECBYTES)] = yc_bytes[i];

      for (i = 0; i < SABER_IDBYTES; i++)
          state[i+2*SABER_IDBYTES+(3*SABER_POLYVECBYTES)] = decapsulation_k[i];


      state[HASH_BYTES] = 0;
      shake128(k_prime, SABER_KEYBYTES, state, HASH_BYTES+1);

      state[HASH_BYTES+1] = 1;
      shake128(sharedkey_c, SABER_KEYBYTES, state, HASH_BYTES+2);
    }
    else{
      return (1);
    }
  }
  else{
    return (1);
  }
  return (0);
}

int pake_s1(unsigned char *sharedkey_s, const unsigned char *k_3_c, unsigned char *state)
{
  uint8_t k_2_prime[SABER_KEYBYTES];
  shake128(k_2_prime, SABER_KEYBYTES, state, HASH_BYTES+1);

  //s0 da üretilen K ve c1 den gelen k karşılaştır
  if(memcmp(k_2_prime, k_3_c, 32) == 0){
    state[HASH_BYTES+1]  = 1;
    shake128(sharedkey_s,SABER_KEYBYTES, state, HASH_BYTES+2);  
    return 0;
  }
  else{
    return 1;
  }
    
}

int crypto_kem_enc(unsigned char *c, unsigned char *k, const unsigned char *pk)
{

  unsigned char kr[64]; // Will contain key, coins
  unsigned char buf[64];

  randombytes(buf, 32);

  sha3_256(buf, buf, 32); // BUF[0:31] <-- random message (will be used as the key for client) Note: hash doesnot release system RNG output

  sha3_256(buf + 32, pk, SABER_INDCPA_PUBLICKEYBYTES); // BUF[32:63] <-- Hash(public key);  Multitarget countermeasure for coins + contributory KEM

  sha3_512(kr, buf, 64);               // kr[0:63] <-- Hash(buf[0:63]);
                                       // K^ <-- kr[0:31]
                                       // noiseseed (r) <-- kr[32:63];
  indcpa_kem_enc(buf, kr + 32, pk, c); // buf[0:31] contains message; kr[32:63] contains randomness r;

  sha3_256(kr + 32, c, SABER_BYTES_CCA_DEC);

  sha3_256(k, kr, 64); // hash concatenation of pre-k and h(c) to k

  return (0);
}

int crypto_kem_dec(unsigned char *k, const unsigned char *c, const unsigned char *sk)
{
  int i, fail;
  unsigned char cmp[SABER_BYTES_CCA_DEC];
  unsigned char buf[64];
  unsigned char kr[64]; // Will contain key, coins
  const unsigned char *pk = sk + SABER_INDCPA_SECRETKEYBYTES;

  indcpa_kem_dec(sk, c, buf); // buf[0:31] <-- message

  // Multitarget countermeasure for coins + contributory KEM
  for (i = 0; i < 32; i++) // Save hash by storing h(pk) in sk
    buf[32 + i] = sk[SABER_SECRETKEYBYTES - 64 + i];

  sha3_512(kr, buf, 64);

  indcpa_kem_enc(buf, kr + 32, pk, cmp);

  fail = verify(c, cmp, SABER_BYTES_CCA_DEC);

  sha3_256(kr + 32, c, SABER_BYTES_CCA_DEC); // overwrite coins in kr with h(c)

  cmov(kr, sk + SABER_SECRETKEYBYTES - SABER_KEYBYTES, SABER_KEYBYTES, fail);

  sha3_256(k, kr, 64); // hash concatenation of pre-k and h(c) to k

  return (0);
}
