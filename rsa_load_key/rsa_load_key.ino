#include "build_info.h"


#include <stdio.h>
#include "string.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"

char buf[516];
unsigned char buffer1[256];
unsigned char buffer2[256];
const char key[] = "-----BEGIN RSA PRIVATE KEY-----\r\n"
                   "MIIEogIBAAKCAQEA0kDpgf98TBktLbdwfiOsbcwT8C5pyNOPmZqExKENUsZmVlyV\r\n"
                   "omGiqrawWG/6/PQDMkxV/ucesp0S9SsG7vKKCL1UY+EdmwmUFKr+hIACmCiO0bEN\r\n"
                   "hzArLwFZaghj8YN0Dsp6R6M0Pw9WWU7F6xwmv7DrWF6hfyYCH9wC7IOWhV2euBMe\r\n"
                   "i4lo3NtTyr/IWDuvBel/GN+spQU6/yjtFSPwnmRfMocZuVD59PGBDIPBWzw8suwb\r\n"
                   "yTsVihYdMfr845noyH0tCZXPne09/nrE0uVKZqmWjNUJLZIaCwjSERwSvQtuk5Mn\r\n"
                   "MELzJrc6gze3AaQxthpOdpt2Z92cIL4kXdSa+QIDAQABAoIBAEsX8g6DIHLRfyhX\r\n"
                   "3y6+MQSaIfjjqtaWcTBsVsUfvHF2+PAZazwu4PlV/I/pltwnjsi1KPW8uGMU5MN5\r\n"
                   "1aUcLR7H+E8gBQHtntzu4a6TRdnwimnscad6FcJZGgVb784/pADwYlIZwTxQjweg\r\n"
                   "seGyEUjfuH68dbPC8HlOjCDLMsR4sJhzLU9GtBo+h9PG+Eoj1vyIRxnNZrFZ7RXN\r\n"
                   "LBU6C/bpW3+NTqZU8SCQGOdLDQ3leWrPWJuCsaI7rC5i0tpFc8T05ZmjnDppUTIE\r\n"
                   "20SsIeTZaTfqnc8vFHOclgW2zF8EI15qy33qSTzfCMALgjLynqjtcjUiQgW0+9x+\r\n"
                   "FahijM0CgYEA9EuugmvqdXai6FCLDlG2zCO520WinAKFaiyi/XVoQfx/ZOobVnEw\r\n"
                   "3nwJJcTirfBzgHrYpxTOQMQVcz79B9+GnNfCxn2MhgmYSYHGrpW6yU5rgCThJ8tn\r\n"
                   "b+HYowDCllorleDFuNgZlv8EOmOKVPM+oVXZBUYveaFc3IfVMRANo4cCgYEA3FOz\r\n"
                   "MbEMd/+zsFf5xqrVacwMAvQTmQgTDe4G1CKaR13dCHJ5t1IatdzsUlF2Q9imgp9K\r\n"
                   "RF2BnBPN6YC780aiTp2LtHHXEQ6qgfwsJiV2HaVK2aMXHHSx6hRaXxhvEwtGc8cR\r\n"
                   "FnKcAoO4JRyJGkiHQQA9I6tTWxWs0WLtD6AQbX8CgYBZ8IMPASwQktznKsAHRY5H\r\n"
                   "GeATGlADn+n+bPCU3+TCZnOAc7Ac4w9a2c+EWDgcUao0YwXgfYhxz78V7tq5S1ID\r\n"
                   "7GuJKC/UKTQn29+J5xYdhwGM7Ab436n1RvC7EkyRjiD9zQL+SpEhRkIIPR1wqR0l\r\n"
                   "yLVde7l+zimiB2A17/MVgQKBgBFfyFGy1HjiARl21ouEDTA6lvfkp2b57Aa9Lmys\r\n"
                   "Dd5y2GtCG7cJEnIk6b3UDq9q9jZ2uTSK6x2Tsjknnaqhd0sbwViJYZxGu8tkR1b6\r\n"
                   "vUW5Mx3Wbowf56e90yKMmrW1veiDWiWbBBJusKa8iVM5RPErQ6b8a6ZTHz2jv23s\r\n"
                   "AV+hAoGAIrMfj1SJ6rZvmj7F+o/STgTlgdptH9dGs8eO8Pv+M8AWx3JczBHy1xsK\r\n"
                   "Lqod8fYbXaJnJ60W1gJ4LJfg/PUJm+XQWf6juALEC2BwY7zHGNlk9oz/iHoh8qR5\r\n"
                   "Lg/3DGwZYfps/ZDEbGSX6H3bTwdL2v30zL/636Ct/vlm8qZj5zg=\r\n"
                   "-----END RSA PRIVATE KEY-----\r\n";

void setup() {
  Serial.begin(115200);
  int ret;
  const char *pers = "rsa_seed";
  mbedtls_pk_context pk;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_ctr_drbg_init( &ctr_drbg );
  mbedtls_entropy_init( &entropy );
  mbedtls_pk_init( &pk );

  printf( "\n  . Seeding the random bit generator..." );
  ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen(pers));
  if (ret != 0) {
    printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d(-0x%04x)\n", ret, -ret);
  }
  printf( " ok\n" );

  ret = mbedtls_pk_parse_key(&pk, (unsigned char *)key, sizeof(key), NULL, 0);

  mbedtls_rsa_context* rsa_private_key_ctx = mbedtls_pk_rsa(pk);
  dump_rsa_key(rsa_private_key_ctx);
  unsigned char cipher[256];
  unsigned char plaintext[256];
  unsigned char signature[256];
  const char* msg="hello world";

  rsa_encrypt(msg, cipher, rsa_private_key_ctx, &ctr_drbg);

  dump_buf(cipher, sizeof(cipher));

  ret = rsa_decrypt(cipher, plaintext, rsa_private_key_ctx, &ctr_drbg);
  //show decryption result
  printf("decrypt result:[%s]\r\n", plaintext);

  //do the signing on the msg
  ret = rsa_sign(msg, signature, rsa_private_key_ctx, &ctr_drbg);
  //show the signature
  dump_buf(signature, sizeof(signature));

  //verify the signature
  ret = rsa_verify(msg, signature, rsa_private_key_ctx, &ctr_drbg);
  if (ret == 0) {
    printf("The signature is verified.");
  } else {
    printf("The signature is not verified.");
  }

  Serial.println("program finished...");

}

void loop() {
  // put your main code here, to run repeatedly:

}

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
