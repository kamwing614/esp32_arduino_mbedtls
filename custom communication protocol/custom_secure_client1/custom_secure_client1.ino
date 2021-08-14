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

unsigned char ki[33], kc[33], iv[33];
unsigned char secure_msg[1024];
mbedtls_aes_context aes_ctx;
char peer_cert_buf[2000];

void setup() {


  const char* ssid = "TP-Link_82F4";
  const char* password =  "31208499";
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
  printf( "\nParsing cacert...\n" );

  ret = mbedtls_x509_crt_parse(&ca_cert, (unsigned char *)ca_cert_buf, sizeof(ca_cert_buf));
  if (ret != 0) {
    printf( " failed\n  ! mbedtls_x509_crt_parse cacert returned % d(-0x % 04x)\n", ret, -ret);
  } else {
    printf( "Successfully Parsed the CA cert \n" );
  }

  // load own cert
  //initialize context
  mbedtls_x509_crt own_cert;
  mbedtls_x509_crt_init(&own_cert);
  //Load the own cert
  printf( "\nLoading Own Cert...\n" );

  ret = mbedtls_x509_crt_parse(&own_cert, (unsigned char *)server_cert_buf, sizeof(server_cert_buf));
  if (ret != 0) {
    printf( "\nFailed! mbedtls_x509_crt_parse own cert returned % d(-0x % 04x)\n", ret, -ret);
  } else {
    printf( "\nSuccessfully Parsed the own cert \n" );
  }

  //Load the RSA key pair from your own key pair, so that you can get the private key
  mbedtls_pk_context pk;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_pk_init( &pk );
  mbedtls_ctr_drbg_init( &ctr_drbg );
  mbedtls_entropy_init( &entropy );

  const char *pers = "rsa_seed";

  printf( "\nSeeding the random bit generator...\n" );
  ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen(pers));
  if (ret != 0) {
    printf( "\nFailed! mbedtls_ctr_drbg_seed returned % d(-0x % 04x)\n", ret, -ret);
  } else {
    printf( "\nRandom Bit Generator is Seeded. \n" );
  }

  ret = mbedtls_pk_parse_key(&pk, (unsigned char *)server_rsa_key_buf, sizeof(server_rsa_key_buf), (unsigned char *)"mbedtls", sizeof("mbedtls") - 1);
  if (ret != 0) {
    printf("\nfailed parsing rsa key, the error code is: % d(-0x % 04x)\n", ret, -ret);
  } else {
    Serial.println("\nThe RSA Key is Parsed from the Server Cert.");
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
  printf("\nNow Creating the Listening Socket... \n");
  ret = mbedtls_net_bind(&listening_ctx, "127.0.0.1", "80", MBEDTLS_NET_PROTO_TCP);


  if (ret != 0) {
    Serial.printf("Socket Creation Failed!...\nthe error code is: % d(-0x % 04x)\n", ret, -ret);
  } else {
    Serial.printf("Socket Created at IP: %s, PORT 80\n", ip_str);
  }
  Serial.println("Waiting for connection...\n");
  //accept connection from client
  ret = mbedtls_net_accept(&listening_ctx, &peer_ctx, NULL, sizeof(NULL), NULL);
  if (ret != 0) {
    Serial.println("Connection Failed!");
  } else {
    Serial.println("A client has connected!");
  }
  Serial.println();

  //handshake
  ret = handshake_nodeA(&peer_ctx, &ca_cert , &ctr_drbg, rsa_own, ki, kc, iv);


  //hanshake done
  //show the KEY Establishment Result//
  Serial.println("The KC is:");
  for (int i = 0; i < 32; i++) {
    Serial.printf("%03d.", kc[i]);
  }
  Serial.println();
  Serial.println();
  Serial.println("The KI is:");
  for (int i = 0; i < 32; i++) {
    Serial.printf("%03d.", ki[i]);
  }
  Serial.println();
  Serial.println();
  Serial.println("The IV is:");
  for (int i = 0; i < 16; i++) {
    Serial.printf("%03d.", iv[i]);
  }
  Serial.println();
  Serial.println();

  //show the KEY Establishment Result//
  unsigned char hmac[33];
  ret = mbedtls_net_recv(&peer_ctx, secure_msg, sizeof(secure_msg));
  ret = mbedtls_net_recv(&peer_ctx, hmac, sizeof(hmac));

  mbedtls_aes_init(&aes_ctx);
  //create buffer to contain the decrypted message
  unsigned char decrypt_data[16];

  Serial.println("Decrypting the message...");
  //set the key for decryption
  mbedtls_aes_setkey_dec( &aes_ctx, kc, 256 );
  //start of decryption
  mbedtls_aes_crypt_cbc( &aes_ctx, MBEDTLS_AES_DECRYPT, sizeof(secure_msg), iv, secure_msg, secure_msg );

  Serial.println("Message is decrypted, it is as below:");
  for (int i = 0; i < sizeof(secure_msg); i++) {
    Serial.printf("%d.", secure_msg[i]);
  }
  Serial.println();

  Serial.println("\nVerifying the HMAC of the message...");
  unsigned char hmac_check[33];
  mbedtls_md_context_t md_ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

  mbedtls_md_init(&md_ctx);
  mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(md_type), 1);
  ret = mbedtls_md_hmac_starts(&md_ctx, ki, sizeof(ki) - 1);
  if (ret != 0) {
    Serial.println("Failed to Start the HMAC context working!");
  } else {
    Serial.println("HMAC context running...");
  }
  ret = mbedtls_md_hmac_update(&md_ctx, secure_msg, sizeof(secure_msg));
  if (ret != 0) {
    Serial.println("Failed to load the payload into HMAC context for calculation");
  } else {
    Serial.println("Loaded Payload into the HMAC context for calculation");
  }
  ret = mbedtls_md_hmac_finish(&md_ctx, hmac_check);
  if (ret != 0) {
    Serial.println("Failed to obtain the HMAC value from the HMAC context!");
  } else {
    Serial.println("Obtained the HMAC value from the HMAC context successfully!");
  }

  //verifying the HMAC
  ret = is_same(hmac_check, hmac, sizeof(hmac));
  if (ret == 0) {
    Serial.println("The HMAC is not match!");
  } else {
    Serial.println("The HMAC is match!");
  }

  Serial.println("\nFYI: The HMAC calculated based on the received msg is:");
  for (int i = 0; i < sizeof(hmac_check); i++) {
    Serial.printf("%d.", hmac_check[i]);
  }
}


void loop() {

}

int settle_token(unsigned char* msg, unsigned char *a, unsigned char *b, unsigned char *c) {
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

  return 0;
}

int handshake_nodeA(mbedtls_net_context *peer_ctx, mbedtls_x509_crt* ca_cert,  mbedtls_ctr_drbg_context* ctr_drbg, mbedtls_rsa_context *rsa_own, unsigned char *ki, unsigned char *kc, unsigned char *iv) {

  //-------------Authentication&&Handshake&&Key Establishment--------------//
  //1.receive the cert & RB (plaintext form)

  int ret;
  unsigned char  rb[9];
  memset(&rb[8], 165, 1);
  ret = mbedtls_net_recv(peer_ctx, (unsigned char*)peer_cert_buf, sizeof(peer_cert_buf));// this ought to be the cert
  Serial.println("Received the Peer's cert.");
  ret = mbedtls_net_recv(peer_ctx, rb, sizeof(rb));
  Serial.println("Received the RB.");
  Serial.println();

  Serial.println("RB is:");
  for (int i = 0; i < sizeof(rb); i++) {
    Serial.printf("%d.", rb[i]);
  }
  Serial.println();
  Serial.println();

  //2.verify the peer's cert, is it signed by trusted CA?
  //2.1 load the cert_buf into cert context
  mbedtls_x509_crt peer_cert;
  mbedtls_x509_crt_init(&peer_cert);
  ret = mbedtls_x509_crt_parse(&peer_cert, (unsigned char *)peer_cert_buf, sizeof(peer_cert_buf));
  if (ret != 0) {
    printf( "\nFailed! mbedtls_x509_crt_parse PEER's Cert returned % d(-0x % 04x)\n", ret, -ret);
  } else {
    printf( "Successfully Parsed PEER's cert \n" );
  }

  //2.2 verify the cert. Is it signed by trusted CA?
  uint32_t flags;
  bool peer_cert_ok = false;
  ret = mbedtls_x509_crt_verify  ( &peer_cert, ca_cert, NULL, NULL, &flags, NULL, NULL);
  if (ret == 0) {
    Serial.println("PEER's cert is verified");
    peer_cert_ok = true;
  } else {
    Serial.println("PEER's cert is not verified.");
    Serial.printf("ERROR CODE return: %d (%x)", ret, ret);
    Serial.printf("ERROR CODE flag: %d (%x)", flags, flags);
  }
  Serial.println();

  //3.send the cert( AF1||AF2||RA||RB )encrypted by peer's cert && ( AF1||AF2||RA||RB )signed by own cert
  //3.1 extract the public key from peer's cert
  mbedtls_rsa_context* rsa_peer_cert = mbedtls_pk_rsa(peer_cert.pk);

  //3.2generate af1,af2,ra
  unsigned char ra[9], af1[9], af2[9] ;
  memset(&ra[8], 165, 1);
  memset(&af1[8], 165, 1);
  memset(&af2[8], 165, 1);
  //af1
  ret = mbedtls_ctr_drbg_random(ctr_drbg, af1, 8);
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
  Serial.println();

  //af2
  ret = mbedtls_ctr_drbg_random(ctr_drbg, af2, 8);
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
  Serial.println();

  //ra
  ret = mbedtls_ctr_drbg_random(ctr_drbg, ra, 8);
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
  Serial.println();

  //3.3concatengate af1,af2,ra,rb in the form of (8bytes||8bytes||8bytes||8bytes)
  unsigned char msg[256];
  memset(msg, 0, sizeof(msg) - 1);
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

  unsigned char cipher[257];
  unsigned char signature[257];

  ret = mbedtls_rsa_pkcs1_encrypt(rsa_peer_cert, mbedtls_ctr_drbg_random, ctr_drbg, MBEDTLS_RSA_PUBLIC, strlen((const char*)msg), msg, cipher);
  if (ret == 0) {
    Serial.println("\nEncryption of (AF1||AF2||RA||RB) is successful.");
  } else {
    Serial.printf("\nEncryption of (AF1||AF2||RA||RB) is failed. Return code is: %d(-0x%04x)\n", ret, -ret);
  }
  //3.5 sign the message
  //rsa_own represents own rsa key pairs. It is loaded above


  ret = mbedtls_rsa_pkcs1_sign(rsa_own, mbedtls_ctr_drbg_random, ctr_drbg, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, strlen((const char*)msg), msg, signature);
  if (ret != 0) {
    Serial.printf( "\n  Signing Failed mbedtls_rsa_pkcs1_sign returned %d(-0x%04x)\n", ret, -ret);
  } else {
    Serial.println("Successfully signed (AF1||AF2||RA||RB)");
  }
  Serial.println();

  //3.6 send the cert, cipher, signature
  ret = mbedtls_net_send(peer_ctx, (const unsigned char*)server_cert_buf, sizeof(server_cert_buf));
  Serial.println("sent my cert");
  ret = mbedtls_net_send(peer_ctx, (const unsigned char*)cipher, sizeof(cipher));
  Serial.println("sent cipher");
  ret = mbedtls_net_send(peer_ctx, (const unsigned char*)signature, sizeof(signature));
  Serial.println("sent signature");
  Serial.println();

  //4.receive  ( BF1 || BF2 || RA ) encrypted using my cert || (BF1||BF2||RA) sign with peer cert
  ret = mbedtls_net_recv(peer_ctx, cipher, sizeof(cipher));
  Serial.println("received cipher");
  ret = mbedtls_net_recv(peer_ctx, signature, sizeof(signature));
  Serial.println("received signature");
  Serial.println();

  //4.1 decrypt the message to get (BF1||BF2||RA)
  Serial.println("Decryption Starts...");
  size_t olen; //store the length of the plaintext
  unsigned char plain_text[256];
  ret = mbedtls_rsa_pkcs1_decrypt(rsa_own, mbedtls_ctr_drbg_random, ctr_drbg, MBEDTLS_RSA_PRIVATE, &olen, cipher, plain_text, sizeof(plain_text));
  if (ret != 0) {
    Serial.printf( "failed\n  ! mbedtls_rsa_pkcs1_decrypt returned %d(-0x%04x)\n", ret, -ret);
  } else {
    Serial.printf( "The RSA decryption is finished successfully.\n" );
  }
  Serial.println("The decrypted ( BF1||BF2||RA ) is:");
  for (int i = 0; i < sizeof(plain_text); i++) {
    Serial.printf("%d.", plain_text[i]);
  }
  Serial.println();

  //4.2 verify the signature
  Serial.println("Verifying Signature...");
  ret = mbedtls_rsa_pkcs1_verify(rsa_peer_cert, mbedtls_ctr_drbg_random, ctr_drbg, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, strlen((const char*)plain_text), plain_text, signature);

  if (ret != 0) {
    Serial.printf( " failed\n  ! mbedtls_rsa_pkcs1_verify returned %d(-0x%04x)\n", ret, -ret);
  } else {
    Serial.printf( " the signature of ENC( BF1||BF2||RA )is verified ok\n" );
  }

  //4.3 Settle ( BF1||BF2||RA )
  Serial.println("Separating BF1||BF2||RA");
  unsigned char bf1[9], bf2[9], received_ra[9];
  memset(&bf1[8],165,1);
  memset(&bf2[8],165,1);
  memset(&received_ra[8],165,1);

  Serial.println();
  Serial.println();
  ret = settle_token(plain_text, bf1, bf2, received_ra);

  Serial.println("BF1 is:");
  for (int i = 0; i < sizeof(bf1); i++) {
    Serial.printf("%d.", bf1[i]);
  }
  Serial.println();
  Serial.println();

  Serial.println("BF2 is:");
  for (int i = 0; i < sizeof(bf2); i++) {
    Serial.printf("%d.", bf2[i]);
  }
  Serial.println();
  Serial.println();

  Serial.println("RA is:");
  for (int i = 0; i < sizeof(ra); i++) {
    Serial.printf("%d.", ra[i]);
  }

  Serial.println("Received RA is:");
  for (int i = 0; i < sizeof(received_ra); i++) {
    Serial.printf("%d.", ra[i]);
  }
  Serial.println();
  Serial.println();

  //4.4 check received RA and Sent RA
  ret = is_same(ra, received_ra, sizeof(ra));
  if (ret == 0) {
    Serial.println("RA Mismatch!");
  } else {
    Serial.println("RA is match!");
  }

  //5. Key establishment using AF&BF

  mbedtls_md_context_t md_ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
  mbedtls_md_init(&md_ctx);
  mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(md_type), 0);
  //concatenate AF1||BF1

  unsigned char key_aes[17];
  memset(key_aes, 0, 17);
  memcpy(&key_aes[0], af1, 8);
  memcpy(&key_aes[8], bf1, 8);


  unsigned char key_hmac[17];
  memset(key_hmac, 0, 17);
  memcpy(&key_hmac[0], af2, 8);
  memcpy(&key_hmac[8], bf2, 8);

  unsigned char iv_material[33];
  memset(iv_material, 0, 32);
  memset(&iv_material[32],165,1);
  memcpy(&iv_material[0], af2, 8);
  memcpy(&iv_material[8], bf2, 8);
  memcpy(&iv_material[16], af1, 8);
  memcpy(&iv_material[24], bf1, 8);

  //5.1 KC = SHA256(AF1||BF1)
  mbedtls_md_starts(&md_ctx);
  mbedtls_md_update(&md_ctx, (const unsigned char *) key_aes, sizeof(key_aes));
  mbedtls_md_finish(&md_ctx, kc);


  //5.2 KI = SHA256(AF2||BF2)
  mbedtls_md_starts(&md_ctx);
  mbedtls_md_update(&md_ctx, (const unsigned char *) key_hmac, sizeof(key_hmac));
  mbedtls_md_finish(&md_ctx, ki);

  //5.2 iv = SHA256(AF2||BF2||AF1||BF1)
  mbedtls_md_starts(&md_ctx);
  mbedtls_md_update(&md_ctx, (const unsigned char *) iv_material, sizeof(iv_material));
  mbedtls_md_finish(&md_ctx, iv);

  mbedtls_md_free(&md_ctx);

  //-------------End of Authentication&&Handshake&&Key Establishment--------------//
  return ret;
}


//check two buffer the same. 0 for true,1 for false
int is_same(unsigned char *buf1, unsigned char *buf2, int len) {
  for (int i = 0; i < len; i++) {
    if (buf1[i] != buf2[i])
      return 0;
  }
  return 1;
}
