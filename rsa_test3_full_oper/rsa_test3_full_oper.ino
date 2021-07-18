#include "build_info.h"

#if defined(MBEDTLS_RSA_C)

#include <stdio.h>
#include "string.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/rsa.h"

char buf[516];
unsigned char buffer1[256];
unsigned char buffer2[256];

//print out the rsa info given the rsa context
static void dump_rsa_key(mbedtls_rsa_context *ctx)
{
  size_t olen;

  printf("\n  +++++++++++++++++ rsa keypair +++++++++++++++++\n\n");
  mbedtls_mpi_write_string(&ctx->N , 16, buf, sizeof(buf), &olen);
  printf("N: %s\n", buf);

  mbedtls_mpi_write_string(&ctx->E , 16, buf, sizeof(buf), &olen);
  printf("E: %s\n", buf);

  mbedtls_mpi_write_string(&ctx->D , 16, buf, sizeof(buf), &olen);
  printf("D: %s\n", buf);

  mbedtls_mpi_write_string(&ctx->P , 16, buf, sizeof(buf), &olen);
  printf("P: %s\n", buf);

  mbedtls_mpi_write_string(&ctx->Q , 16, buf, sizeof(buf), &olen);
  printf("Q: %s\n", buf);

  mbedtls_mpi_write_string(&ctx->DP, 16, buf, sizeof(buf), &olen);
  printf("DP: %s\n", buf);

  mbedtls_mpi_write_string(&ctx->DQ, 16, buf, sizeof(buf), &olen);
  printf("DQ: %s\n", buf);

  mbedtls_mpi_write_string(&ctx->QP, 16, buf, sizeof(buf), &olen);
  printf("QP: %s\n", buf);
  printf("\n  +++++++++++++++++ rsa keypair +++++++++++++++++\n\n");
}

static void dump_buf(uint8_t *buf, uint32_t len)
{
  int i;

  for (i = 0; i < len; i++) {
    printf("%s%02X%s", i % 16 == 0 ? "\r\n\t" : " ",
           buf[i],
           i == len - 1 ? "\r\n" : "");
  }
}


//setup the rsa context --from the context, we can know the rsa key pair, padding scheme, hashing id,etc
int rsa_setup(mbedtls_rsa_context* ctx, mbedtls_entropy_context* entropy, mbedtls_ctr_drbg_context* ctr_drbg) {


  int ret;
  //a custom seed to increase the randomness of the entrophy.NULL is also ok
  const char *pers = "rsa_seed";

  printf("Start setting up the RSA context...");
  /* 1. initialize structure */
  mbedtls_entropy_init(entropy);// use in Deterministic Random Bit Generator (DRBG)
  mbedtls_ctr_drbg_init(ctr_drbg);//use in generating rsa key pair
  mbedtls_rsa_init(ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);//ctx, padding scheme,hashing id

  /* 2. seeding the random bit generator */
  printf( "\n  . Seeding the random bit generator..." );
  ret = mbedtls_ctr_drbg_seed( ctr_drbg, mbedtls_entropy_func, entropy,
                               (const unsigned char *) pers,
                               strlen(pers));
  if (ret != 0) {
    printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d(-0x%04x)\n", ret, -ret);
    goto exit;
  }
  printf( " ok\n" );


  printf( "\n  . Generate RSA keypair..." );
  /* 3. generate an RSA keypair */
  ret = mbedtls_rsa_gen_key(ctx, mbedtls_ctr_drbg_random, ctr_drbg, 2048, 65537);
  if (ret != 0) {
    printf( " failed\n  ! mbedtls_rsa_gen_key returned %d(-0x%04x)\n", ret, -ret);
    goto exit;
  }
  printf( " The RSA context setup is finished successfully. \n" );

exit:
  return ret;
}

int rsa_encrypt(const char* msg, unsigned char *cipher, mbedtls_rsa_context* ctx, mbedtls_ctr_drbg_context* ctr_drbg) {
  int ret;
  size_t olen;
  memset(buffer1, 0, 256);

  /* 1. encrypt */
  printf( "\n  . RSA pkcs1 encrypt..." );

  ret = mbedtls_rsa_pkcs1_encrypt(ctx, mbedtls_ctr_drbg_random, ctr_drbg, MBEDTLS_RSA_PUBLIC,
                                  strlen(msg), (uint8_t *)msg, buffer1);
  if (ret != 0) {
    printf( " failed\n  ! mbedtls_rsa_pkcs1_encrypt returned %d(-0x%04x)\n", ret, -ret);
    goto exit;
  }
  printf( " ok\n" );
  memcpy(cipher, buffer1, 256);

exit:
  memset(buffer1, 0, 256);
  return ret;
}

int rsa_decrypt(unsigned char cipher[], unsigned char plaintext[], mbedtls_rsa_context* ctx, mbedtls_ctr_drbg_context* ctr_drbg) {

  //setup variables
  int ret;
  memset(buffer1, 0, 256);
  memset(buffer2, 0, 256);
  memcpy(buffer1, cipher, 256);
  size_t olen;

  //decryption
  printf( "\n  . RSA pkcs1 decrypt..." );

  ret = mbedtls_rsa_pkcs1_decrypt(ctx, mbedtls_ctr_drbg_random, ctr_drbg, MBEDTLS_RSA_PRIVATE,
                                  &olen, buffer1, buffer2, sizeof(buffer2));
  if (ret != 0) {
    printf( " failed\n  ! mbedtls_rsa_pkcs1_decrypt returned %d(-0x%04x)\n", ret, -ret);
    goto exit;
  }
  printf( " The RSA decryption is finished successfully.\n" );

  buffer2[olen] = '\0';
  memcpy(plaintext, buffer2, 256);

exit:
  memset(buffer1, 0, 256);
  memset(buffer2, 0, 256);

  return ret;
}

//return 0 if verified
int rsa_sign(const char* msg, unsigned char signature[], mbedtls_rsa_context* ctx, mbedtls_ctr_drbg_context* ctr_drbg) {
  int ret;

  printf( "\n  . RSA pkcs1 signing starts..." );

  ret = mbedtls_rsa_pkcs1_sign(ctx, mbedtls_ctr_drbg_random, ctr_drbg, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, strlen(msg), (uint8_t *)msg, buffer1);
  if (ret != 0) {
    printf( " failed\n  ! mbedtls_rsa_pkcs1_sign returned %d(-0x%04x)\n", ret, -ret);
    goto exit;
  }
  printf( " RSA pkcs1 signing completed successfully. \n" );
  memcpy(signature, buffer1, 256);

exit:
  memset(buffer1, 0, 256);
  return ret;

}

int rsa_verify(const char* msg, unsigned char signature[], mbedtls_rsa_context* ctx, mbedtls_ctr_drbg_context* ctr_drbg) {

  int ret;
  /* 5. verify sign*/
  printf( "\n  . RSA pkcs1 verify..." );
  memset(buffer1, 0, 256);
  memcpy(buffer1, signature, 256);
  ret = mbedtls_rsa_pkcs1_verify(ctx, mbedtls_ctr_drbg_random, ctr_drbg, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, strlen(msg), (uint8_t *)msg, buffer1);

  if (ret != 0) {
    printf( " failed\n  ! mbedtls_rsa_pkcs1_encrypt returned %d(-0x%04x)\n", ret, -ret);
    goto exit;
  }
  printf( " the signature is verified ok\n" );

exit:
  memset(buffer1, 0, 256);

  return ret;

}

void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);

  int res;
  mbedtls_rsa_context ctx;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  unsigned char cipher[256];
  unsigned char plaintext[256];
  unsigned char signature[256];

  res = rsa_setup(&ctx, &entropy, &ctr_drbg);
  Serial.println("The result of setting up the rsa context is: " + res );
  /* show RSA keypair */
  dump_rsa_key(&ctx);

  const char* msg = "hello world";

  res = rsa_encrypt(msg, cipher, &ctx, &ctr_drbg);
  //show the cipher
  Serial.println("show the cipher:");
  dump_buf(cipher, sizeof(cipher));

  //rsa decryption
  res = rsa_decrypt(cipher, plaintext, &ctx, &ctr_drbg);
  //show decryption result
  printf("decrypt result:[%s]\r\n", plaintext);

  //do the signing on the msg
  res = rsa_sign(msg, signature, &ctx, &ctr_drbg);
  //show the signature
  dump_buf(signature, sizeof(signature));

  //verify the signature
  res = rsa_verify(msg, signature, &ctx, &ctr_drbg);
  if(res==0){
    printf("The signature is verified.");
  }else{
    printf("The signature is not verified.");
  }



}
#endif /* MBEDTLS_RSA_C */

void loop() {
  // put your main code here, to run repeatedly:

}

//giving credit to: https://blog.csdn.net/mculover666/category_10403120.html
//This code took the blog as reference to build an example of RSA operation in mbedtls  
