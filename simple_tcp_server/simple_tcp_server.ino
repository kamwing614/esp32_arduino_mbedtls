#include "build_info.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ssl_ciphersuites.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_crl.h"
#include "mbedtls/dhm.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/platform_time.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
#include "tls_server_cert.h"
#include "mbedtls/ssl.h"
#include <stddef.h>
#include <stdint.h>
#include "mbedtls/net_sockets.h"
#include "WiFi.h"



char buf[4096];
const char* PORT = "443";
mbedtls_net_context client_ctx;
mbedtls_net_context listening_ctx;
mbedtls_rsa_context* rsa_private_key_ctx;
mbedtls_pk_context pk;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_x509_crt server_cert, ca_cert;


void setup() {
  Serial.begin(115200);
  const char* ssid = "";//wifi ssid
  const char* password =  "";//wifi password

  String ip_str;
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.println("Connecting to WiFi..");
  }
  int ret;
  //Load your certificate and your private RSA key (X.509 interface)
  const char *pers = "rsa_seed";

  //initialize context
  mbedtls_x509_crt_init(&server_cert);
  mbedtls_x509_crt_init(&ca_cert);
  /* 2. Parse CA cert */
  printf( "\n  . Parse cacert..." );

  ret = mbedtls_x509_crt_parse(&ca_cert, (unsigned char *)ca_cert_buf, sizeof(ca_cert_buf));
  if (ret != 0) {
    printf( " failed\n  ! mbedtls_x509_crt_parse cacert returned % d(-0x % 04x)\n", ret, -ret);
    goto exit;
  }
  printf( " ok\n" );

  /* 2. Parsing result */
  printf( "\n  . CA Cert Information: " );

  ret = mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "      ", &ca_cert);
  if (ret < 0) {
    printf("fail! mbedtls_x509_crt_info return % d(-0x % 04x)\n", ret, -ret);
    goto exit;
  } else {
    buf[ret] = '\0';
    printf("ok!\r\n");
    printf("crt info has % d chars\r\n", strlen(buf));
    printf(" % s\r\n", buf);
  }

  /* 2. Parse server cert */
  ret = mbedtls_x509_crt_parse(&server_cert, (unsigned char *)server_cert_buf, sizeof(server_cert_buf));
  if (ret != 0) {
    printf( " failed\n  ! mbedtls_x509_crt_parse cacert returned % d(-0x % 04x)\n", ret, -ret);
    goto exit;
  }
  printf( " ok\n" );

  /* 2. Cacert parser result */
  printf( "\n  . Server Cert Information: " );

  ret = mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "      ", &server_cert);
  if (ret < 0) {
    printf("fail! mbedtls_x509_crt_info return % d(-0x % 04x)\n", ret, -ret);
    goto exit;
  } else {
    buf[ret] = '\0';
    printf("ok!\r\n");
    printf("crt info has % d chars\r\n", strlen(buf));
    printf(" % s\r\n", buf);
  }

  //Parsing RSA key

  mbedtls_ctr_drbg_init( &ctr_drbg );
  mbedtls_entropy_init( &entropy );
  mbedtls_pk_init( &pk );

  printf( "\n  . Seeding the random bit generator..." );
  ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen(pers));
  if (ret != 0) {
    printf( " failed\n  ! mbedtls_ctr_drbg_seed returned % d(-0x % 04x)\n", ret, -ret);
  }
  printf( " ok\n" );

  ret = mbedtls_pk_parse_key(&pk, (unsigned char *)server_rsa_key_buf, sizeof(server_rsa_key_buf), NULL, 0);
  if (ret != 0) {
    printf("failed parsing rsa key, the error code is: % d(-0x % 04x)\n", ret, -ret);
    goto exit;
  }

  rsa_private_key_ctx = mbedtls_pk_rsa(pk);
  dump_rsa_key(rsa_private_key_ctx);


  //Setup the listening TCP socket (TCP/IP interface)

  mbedtls_net_init(&listening_ctx);
  mbedtls_net_init(&client_ctx);
  ip_str = WiFi.localIP().toString();
  Serial.println(ip_str);


  printf("Now Creating the Listening Socket... \n");
  ret = mbedtls_net_bind(&listening_ctx, ip_str.c_str(), PORT, MBEDTLS_NET_PROTO_TCP);


  if (ret != 0) {
    Serial.printf("Socket Creation Failed!...the error code is: % d(-0x % 04x)\n", ret, -ret);
  } else {
    Serial.printf("Socket Created at IP: %s, PORT %s", ip_str, PORT);
    goto exit;
  }





exit:
  /* 3. release structure */
  mbedtls_x509_crt_free(&server_cert);
  mbedtls_x509_crt_free(&ca_cert);
  printf("Program Finished");


}

unsigned char msg_buf[4096];
void loop() {
  int ret;

  //accept connection from client
  ret = mbedtls_net_accept(&listening_ctx, &client_ctx, NULL, sizeof(NULL), NULL);
  while (true) {
    //send a hello msg to client after connection
    ret = mbedtls_net_send(&client_ctx, (unsigned char*)"hello", sizeof("hello"));
    ret = mbedtls_net_recv(&client_ctx, msg_buf, 4096);
    for (int i = 0; i < ret; i++) {
      Serial.print((char)msg_buf[i]);
    }
    Serial.println();
  }


}

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




//Accept incoming client connection (TCP/IP interface)
//Initialise as an SSL-server (SSL/TLS interface)
//Set parameters, e.g. authentication, ciphers, CA-chain, key exchange
//Set callback functions RNG, IO, session handling
//Perform an SSL-handshake (SSL/TLS interface)
//Read/write data (SSL/TLS interface)
//Close and cleanup (all interfaces)
