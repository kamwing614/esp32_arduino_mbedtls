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
#include "aes.h"


char buf[4096];
const char* PORT = "80";
mbedtls_net_context client_ctx;
mbedtls_net_context listening_ctx;

boolean error = false;
char err_msg[4096];


void setup() {
  Serial.begin(115200);
  Serial.println("TLS Server running... \n");
  const char* ssid = "";
  const char* password =  "";

  String ip_str;
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.println("Connecting to WiFi..");
  }
  int ret;

  //Setup the listening TCP socket (TCP/IP interface)

  mbedtls_net_init(&listening_ctx);
  mbedtls_net_init(&client_ctx);
  ip_str = WiFi.localIP().toString();
  Serial.println(ip_str);


  printf("Now Creating the Listening Socket... \n");
  ret = mbedtls_net_bind(&listening_ctx, "127.0.0.1", PORT, MBEDTLS_NET_PROTO_TCP);


  if (ret != 0) {
    Serial.printf("Socket Creation Failed!...the error code is: % d(-0x % 04x)\n", ret, -ret);
    error = true;
  } else {
    Serial.printf("Socket Created at IP: %s, PORT %s", ip_str, PORT);

  }



}

unsigned char msg_buf[4096];
void loop() {
  if (error == true) {
    Serial.println("Failed");
  }
  int ret;
  Serial.println("Waiting for connection...");
  //accept connection from client
  ret = mbedtls_net_accept(&listening_ctx, &client_ctx, NULL, sizeof(NULL), NULL);
  if (ret != 0) {
    Serial.println("Connection Failed!");
  } else {
    Serial.println("A client has connected!");
  }

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
