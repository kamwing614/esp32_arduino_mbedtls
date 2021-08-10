#include "WiFi.h"
#include "build_info.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
#include "tls_server_cert.h"
#include "mbedtls/aes.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/md.h"


char peer_cert_buf[2048];

void setup() {
  Serial.begin(115200);
  Serial.println("Custom Secure Communication Channel Starts\n");

  //set Wifi
  const char* ssid = "";
  const char* password =  "

  String ip_str;
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.println("Connecting to WiFi..");
  }
  ip_str = WiFi.localIP().toString();
  Serial.print("The ip address of this device is:");
  Serial.println(ip_str);
  int ret;


  //Load trusted CA cert
  mbedtls_x509_crt ca_cert;
  //initialize context
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
  mbedtls_x509_crt  own_cert;
  mbedtls_x509_crt_init(&own_cert);
  //Load the own cert
  printf( "\n  . Loading Own Cert..." );

  ret = mbedtls_x509_crt_parse(&own_cert, (unsigned char *)node_b_cert_buf, sizeof(node_b_cert_buf));
  if (ret != 0) {
    printf( " failed\n  ! mbedtls_x509_crt_parse own cert returned % d(-0x % 04x)\n", ret, -ret);

  } else {
    printf( " Successfully Parsed the own cert \n" );
  }

  //Load the RSA key pair from your own key pair, so that you can get the private key
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
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
  mbedtls_pk_context pk;
  mbedtls_pk_init( &pk );


  ret = mbedtls_pk_parse_key(&pk, (unsigned char *)node_b_key_buf, sizeof(node_b_key_buf), (unsigned char *)"mbedtls", sizeof("mbedtls") - 1);
  if (ret != 0) {
    printf("failed parsing rsa key, the error code is: % d(-0x % 04x)\n", ret, -ret);

  } else {
    Serial.println("The RSA Key is Parsed from the Node B Cert.");
  }

  //after parsed into a pk structure, load it into an RSA structurre
  mbedtls_rsa_context *rsa_own = (mbedtls_pk_rsa(pk));
  //mbedtls_pk_free( &pk );

  // Initiate TCP connection
  mbedtls_net_context peer_ctx;
  mbedtls_net_init(&peer_ctx);

  Serial.println("Connecting to 192.168.0.130:80");
  //connect to peer
  ret = mbedtls_net_connect(&peer_ctx, "192.168.0.130", "80", MBEDTLS_NET_PROTO_TCP);
  if (ret != 0) {
    Serial.println("Connection Failed!");
  } else {
    Serial.println("Connected to 192.168.0.130:80");
  }

  //-------------Authentication&&Handshake&&Key Establishment--------------//


  unsigned char ra[9], rb[9] , af1[9], af2[9], bf1[9], bf2[9];

  int offset;
  bool peer_cert_ok = false;
  //1.send over the cert & RB (plaintext form)
  //1.1 generate RB
  ret = mbedtls_ctr_drbg_random(&ctr_drbg, rb, 8);
  if (ret != 0) {
    Serial.println("RB Generation Failed");
  } else {
    Serial.printf("RB is generated! \n");
  }
  Serial.println("RB is:");
  for (int i = 0; i < sizeof(rb); i++) {
    Serial.printf("%d.", rb[i]);
  }
  Serial.println();
  //1.2 send cert and RB
  ret = mbedtls_net_send(&peer_ctx, (const unsigned char*)node_b_cert_buf, sizeof(node_b_cert_buf));
  ret = mbedtls_net_send(&peer_ctx, (const unsigned char*)rb, sizeof(rb));


  //2.receive msg from peer, contains:
  //i) peer's cert

  ret = mbedtls_net_recv(&peer_ctx, (unsigned char*)peer_cert_buf, sizeof(peer_cert_buf));

  //ii) ( AF1||AF2||RA||RB )encrypted by own cert's rsa public key
  unsigned char cipher[257];
  ret = mbedtls_net_recv(&peer_ctx, cipher, sizeof(cipher));// receive encrypted (AF1||AF2||RA||RB)
  Serial.printf("received cipher:\n %s", cipher);
  Serial.println();

  //iii) (cert || AF1||AF2||RA||RB ) signed by peer's cert
  unsigned char signature[257];
  ret = mbedtls_net_recv(&peer_ctx, signature, sizeof(signature) ); // receive signature of (AF1||AF2||RA||RB)
  Serial.printf("received signature:\n ");


  //3 Handle the Received Message (load PEER's cert & decrypt/verify message)
  //3.1 load PEER's cert & verify message
  mbedtls_x509_crt peer_cert;
  mbedtls_x509_crt_init(&peer_cert);
  ret = mbedtls_x509_crt_parse(&peer_cert, (unsigned char *)peer_cert_buf, sizeof(peer_cert_buf));
  if (ret != 0) {
    printf( " failed\n  ! mbedtls_x509_crt_parse PEER's Cert returned % d(-0x % 04x)\n", ret, -ret);
  } else {
    printf( " Successfully Parsed PEER's cert \n" );
  }

  //3.2.1 verify the cert. Is it signed by trusted CA?
  uint32_t flags;
  ret = mbedtls_x509_crt_verify  ( &peer_cert, &ca_cert, NULL, NULL, &flags, NULL, NULL);
  if (ret == 0) {
    Serial.println("PEER's cert is verified");
    peer_cert_ok = true;
  } else {
    Serial.println("PEER's cert is not verified.");
    Serial.printf("ERROR CODE return: %d (%x)", ret, ret);
    Serial.printf("ERROR CODE flag: %d (%x)", flags, flags);
  }

  //3.2.2 Obtain the public key in the cert for verifying signature
  mbedtls_rsa_context* rsa_peer_cert = mbedtls_pk_rsa(peer_cert.pk);

  //3.3 decrypt message to get ( AF1||AF2||RA||RB )


  //memset(plain_text, 0, sizeof(plain_text));
  Serial.println("Decryption Starts...");
  size_t olen; //store the length of the plaintext
  unsigned char plain_text[256];
  ret = mbedtls_rsa_pkcs1_decrypt(rsa_own, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, &olen, cipher, plain_text, sizeof(plain_text));
  if (ret != 0) {
    Serial.printf( "failed\n  ! mbedtls_rsa_pkcs1_decrypt returned %d(-0x%04x)\n", ret, -ret);

  } else {
    Serial.printf( "The RSA decryption is finished successfully.\n %s", plain_text );
  }
  Serial.println("The decrypted ( AF1||AF2||RA||RB ) is:");
  for (int i = 0; i < sizeof(plain_text); i++) {
    Serial.printf("%d.", plain_text[i]);
  }
  Serial.println();


  //3.4 verify the signature to validate msg ( AF1||AF2||RA||RB )

  ret = mbedtls_rsa_pkcs1_verify(rsa_peer_cert, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, strlen((const char*)plain_text), plain_text, signature);

  if (ret != 0) {
    Serial.printf( " failed\n  ! mbedtls_rsa_pkcs1_verify returned %d(-0x%04x)\n", ret, -ret);
  } else {
    Serial.printf( " the signature of ENC( AF1||AF2||RA||RB )is verified ok\n" );
  }

  //3.5 verify RB
  //3.5.1 extracted all the tokens first
  unsigned char received_rb[9];
  Serial.println("Separating ( AF1||AF2||RA||RB ) into individuals...");
  ret = settle_token(plain_text, af1, af2, ra, received_rb);
  Serial.println("Separated!");
  Serial.println("AF1 is:");
  for (int i = 0; i < sizeof(af1); i++) {
    Serial.printf("%d.", af1[i]);
  }
  Serial.println();
  Serial.println("AF2 is:");
  for (int i = 0; i < sizeof(af2); i++) {
    Serial.printf("%d.", af2[i]);
  }
  Serial.println();
  Serial.println("RA is:");
  for (int i = 0; i < sizeof(ra); i++) {
    Serial.printf("%d.", ra[i]);
  }
  Serial.println();
  Serial.println("Received RB is:");
  for (int i = 0; i < sizeof(received_rb); i++) {
    Serial.printf("%d.", received_rb[i]);
  }
  Serial.println("--------");
  Serial.println("Sent RB was:");
  for (int i = 0; i < sizeof(rb); i++) {
    Serial.printf("%d.", rb[i]);
  }
  Serial.println();


  Serial.println("Checking the received RB is the same as we sent...");
  ret = is_same(rb, received_rb, 8);
  if (ret == 0) {
    Serial.println("The RB received is wrong!") ;
  } else {
    Serial.println("The RB received is correct!");
  }
  //4. send  ( BF1 || BF2 || RA ) encrypted using A's cert || (BF1||BF2||RA) sign with own cert
  //5. Key establishment using AF&BF
  //5.1 KC = SHA256(AF1||BF1)
  //5.2 KI = SHA256(AF2||BF2)


  //-------------End of Authentication&&Handshake&&Key Establishment--------------//
}



void loop() {

}

int settle_token(unsigned char* msg, unsigned char *a, unsigned char *b, unsigned char *c, unsigned char* d) {
  int offset = 0;

  for (int i = 0; i < 8; i++) {
    a[i] = msg[offset];
    offset++;
  }
  for (int i = 0; i < 8; i++) {
    b[i] = msg[offset];
    offset++;
  }
  for (int i = 0; i < 8; i++) {
    c[i] = msg[offset];
    offset++;
  }
  for (int i = 0; i < 8; i++) {
    d[i] = msg[offset];
    offset++;
  }

  return 0;
}

//check two buffer the same. 0 for true,1 for false
int is_same(unsigned char *buf1, unsigned char *buf2, int len) {
  for (int i = 0; i < len; i++) {
    if (buf1[i] != buf2[i])
      return 0;
  }
  return 1;
}
