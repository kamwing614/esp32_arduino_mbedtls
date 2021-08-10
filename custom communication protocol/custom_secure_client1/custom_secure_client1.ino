#include "WiFi.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
#include "tls_server_cert.h"
#include "aes.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/md.h"

unsigned char cipher[257];
unsigned char signature[257];
char peer_cert_buf[2048];
void setup() {

  const char* ssid = "";
  const char* password =  "";
  String ip_str;

  int ret;

  Serial.begin(115200);
  Serial.println("Custom Secure Communication Channel Starts\n"); \
  //set Wifi

  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.println("Connecting to WiFi..");
  }
  ip_str = WiFi.localIP().toString();
  Serial.print("The ip address of this device is:");
  Serial.println(ip_str);



  //Load trusted CA cert
  mbedtls_x509_crt ca_cert;
  mbedtls_x509_crt_init(&ca_cert);
  //Load the trusted CA cert
  printf( "\n  . Parse cacert..." );

  ret = mbedtls_x509_crt_parse(&ca_cert, (unsigned char *)ca_cert_buf, sizeof(ca_cert_buf));
  if (ret != 0) {
    printf( " failed\n  ! mbedtls_x509_crt_parse cacert returned % d(-0x % 04x)\n", ret, -ret);
  } else {
    printf( " Successfully Parsed the CA cert \n" );
  }

  // load own cert

  //initialize context
  mbedtls_x509_crt own_cert;
  mbedtls_x509_crt_init(&own_cert);
  //Load the own cert
  printf( "\n  . Loading Own Cert..." );

  ret = mbedtls_x509_crt_parse(&own_cert, (unsigned char *)server_cert_buf, sizeof(server_cert_buf));
  if (ret != 0) {
    printf( " failed\n  ! mbedtls_x509_crt_parse own cert returned % d(-0x % 04x)\n", ret, -ret);
  } else {
    printf( " Successfully Parsed the own cert \n" );
  }

  //Load the RSA key pair from your own key pair, so that you can get the private key
  mbedtls_pk_context pk;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_pk_init( &pk );
  mbedtls_ctr_drbg_init( &ctr_drbg );
  mbedtls_entropy_init( &entropy );

  const char *pers = "rsa_seed";

  printf( "\n  . Seeding the random bit generator..." );
  ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen(pers));
  if (ret != 0) {
    printf( " failed\n  ! mbedtls_ctr_drbg_seed returned % d(-0x % 04x)\n", ret, -ret);
  } else {
    printf( " Random Bit Generator is Seeded. \n" );
  }

  ret = mbedtls_pk_parse_key(&pk, (unsigned char *)server_rsa_key_buf, sizeof(server_rsa_key_buf), (unsigned char *)"mbedtls", sizeof("mbedtls") - 1);
  if (ret != 0) {
    printf("failed parsing rsa key, the error code is: % d(-0x % 04x)\n", ret, -ret);
  } else {
    Serial.println("The RSA Key is Parsed from the Server Cert.");
  }

  //after parsed into a pk structure, load it into an RSA structurre



  mbedtls_rsa_context *rsa_own = (mbedtls_pk_rsa(pk));

  // cannot free the context of pk now, because rsa_own is actully pointing to pk's context
  // mbedtls_pk_free( &pk );


  //Start TCP Connection
  mbedtls_net_context peer_ctx;
  mbedtls_net_context listening_ctx;
  mbedtls_net_init(&listening_ctx);
  mbedtls_net_init(&peer_ctx);


  // set up socket for listening
  printf("Now Creating the Listening Socket... \n");
  ret = mbedtls_net_bind(&listening_ctx, "127.0.0.1", "80", MBEDTLS_NET_PROTO_TCP);


  if (ret != 0) {
    Serial.printf("Socket Creation Failed!...the error code is: % d(-0x % 04x)\n", ret, -ret);
  } else {
    Serial.printf("Socket Created at IP: %s, PORT 80", ip_str);

  }
  Serial.println("Waiting for connection...");
  //accept connection from client
  ret = mbedtls_net_accept(&listening_ctx, &peer_ctx, NULL, sizeof(NULL), NULL);
  if (ret != 0) {
    Serial.println("Connection Failed!");
  } else {
    Serial.println("A client has connected!");
  }



  //-------------Authentication&&Handshake&&Key Establishment--------------//



  //1.receive the cert & RB (plaintext form)


  unsigned char  rb[9];
  ret = mbedtls_net_recv(&peer_ctx, (unsigned char*)peer_cert_buf, sizeof(peer_cert_buf));// this ought to be the cert
  Serial.println("Received the Peer's cert.");
  ret = mbedtls_net_recv(&peer_ctx, rb, sizeof(rb));
  Serial.println("Received the RB.");

  Serial.println("RB is:");
  for (int i = 0; i < sizeof(rb); i++) {
    Serial.printf("%d.", rb[i]);
  }
  Serial.println();

  //2.verify the peer's cert, is it signed by trusted CA?
  //2.1 load the cert_buf into cert context
  mbedtls_x509_crt peer_cert;
  mbedtls_x509_crt_init(&peer_cert);
  ret = mbedtls_x509_crt_parse(&peer_cert, (unsigned char *)peer_cert_buf, sizeof(peer_cert_buf));
  if (ret != 0) {
    printf( " failed\n  ! mbedtls_x509_crt_parse PEER's Cert returned % d(-0x % 04x)\n", ret, -ret);
  } else {
    printf( " Successfully Parsed PEER's cert \n" );
  }

  //2.2 verify the cert. Is it signed by trusted CA?
  uint32_t flags;
  bool peer_cert_ok = false;
  ret = mbedtls_x509_crt_verify  ( &peer_cert, &ca_cert, NULL, NULL, &flags, NULL, NULL);
  if (ret == 0) {
    Serial.println("PEER's cert is verified");
    peer_cert_ok = true;
  } else {
    Serial.println("PEER's cert is not verified.");
    Serial.printf("ERROR CODE return: %d (%x)", ret, ret);
    Serial.printf("ERROR CODE flag: %d (%x)", flags, flags);
  }

  //3.send the cert( AF1||AF2||RA||RB )encrypted by peer's cert && ( AF1||AF2||RA||RB )signed by own cert
  //3.1 extract the public key from peer's cert
  mbedtls_rsa_context* rsa_peer_cert = mbedtls_pk_rsa(peer_cert.pk);

  //3.2generate af1,af2,ra
  unsigned char ra[9], af1[9], af2[9] ;
  //af1
  ret = mbedtls_ctr_drbg_random(&ctr_drbg, af1, 8);
  if (ret != 0) {
    Serial.println("AF1 Generation Failed");
  } else {
    Serial.println("AF1 is generated!");
  }

  Serial.println("AF1 is:");
  for (int i = 0; i < sizeof(af1); i++) {
    Serial.printf("%d.", af1[i]);
  }
  Serial.println();
  //af2
  ret = mbedtls_ctr_drbg_random(&ctr_drbg, af2, 8);
  if (ret != 0) {
    Serial.println("AF2 Generation Failed");
  } else {
    Serial.println("AF2 is generated!");
  }
  Serial.println("AF2 is:");
  for (int i = 0; i < sizeof(af2); i++) {
    Serial.printf("%d.", af2[i]);
  }
  Serial.println();
  //ra
  ret = mbedtls_ctr_drbg_random(&ctr_drbg, ra, 8);
  if (ret != 0) {
    Serial.println("RA Generation Failed");
  } else {
    Serial.println("RA is generated!");
  }
  Serial.println("RA is:");
  for (int i = 0; i < sizeof(ra); i++) {
    Serial.printf("%d.", ra[i]);
  }
  Serial.println();
  //3.3concatengate af1,af2,ra,rb in the form of (8bytes||8bytes||8bytes||8bytes)
  unsigned char msg[256];
  memset(msg, 0, sizeof(msg));
  memcpy(&msg[0], af1, 8);
  memcpy(&msg[8], af2, 8);
  memcpy(&msg[16], ra, 8);
  memcpy(&msg[24], rb, 8);
  Serial.println("The msg ( AF1||AF2||RA||RB ) being encrypted and then sent is:");
  for (int i = 0; i < sizeof(msg); i++) {
    Serial.printf("%d.", msg[i]);
  }
  Serial.println();

  //3.4 encrypt the msg


  ret = mbedtls_rsa_pkcs1_encrypt(rsa_peer_cert, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, strlen((const char*)msg), msg, cipher);
  if (ret == 0) {
    Serial.println("\nEncryption of (AF1||AF2||RA||RB) is successful.");
  } else {
    Serial.printf("\nEncryption of (AF1||AF2||RA||RB) is failed. Return code is: %d(-0x%04x)\n", ret, -ret);
  }
  //3.5 sign the message
  //rsa_own represents own rsa key pairs. It is loaded above


  ret = mbedtls_rsa_pkcs1_sign(rsa_own, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, strlen((const char*)msg), msg, signature);
  if (ret != 0) {
    Serial.printf( "\n  Signing Failed mbedtls_rsa_pkcs1_sign returned %d(-0x%04x)\n", ret, -ret);
  } else {
    Serial.println("Successfully signed (AF1||AF2||RA||RB)");
  }

  //3.6 send the cert, cipher, signature
  ret = mbedtls_net_send(&peer_ctx, (const unsigned char*)server_cert_buf, sizeof(server_cert_buf));
  Serial.println("sent my cert");
  ret = mbedtls_net_send(&peer_ctx, (const unsigned char*)cipher, sizeof(cipher));
  Serial.println("sent cipher");
  ret = mbedtls_net_send(&peer_ctx, (const unsigned char*)signature, sizeof(signature));
  Serial.println("sent signature");
  //4.receive  ( BF1 || BF2 || RA ) encrypted using my cert || (BF1||BF2||RA) sign with peer cert
  //4.1 decrypt the message to get (BF1||BF2||RA)
  //4.2 verify the signature
  //5. Key establishment using AF&BF
  //5.1 KC = SHA256(AF1||BF1)
  //5.2 KI = SHA256(AF2||BF2)
  //ret = mbedtls_net_send(&peer_ctx, (unsigned char*)"hello I am the client", sizeof("hello I am the client"));
  //ret = mbedtls_net_recv(&peer_ctx, msg_buf, 4096);

  //-------------End of Authentication&&Handshake&&Key Establishment--------------//
}




void loop() {

}

