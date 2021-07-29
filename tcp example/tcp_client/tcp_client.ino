#include "build_info.h"
#include <stddef.h>
#include <stdint.h>
#include "mbedtls/net_sockets.h"
#include "WiFi.h"


//#define SERVER_PORT 443
//#define SERVER_NAME "192.168.0.128"

char buf[4096];
const char* PORT = "443";
mbedtls_net_context server_ctx;
mbedtls_net_context listening_ctx;
boolean error = false;

void setup() {
  Serial.begin(115200);
  Serial.println("TLS Client running... \n");
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

  mbedtls_net_init(&server_ctx);
  ip_str = WiFi.localIP().toString();
  Serial.println(ip_str);

  ret= mbedtls_net_bind(&listening_ctx, "127.0.0.1","81",MBEDTLS_NET_PROTO_TCP );
  if(ret!=0){
    Serial.println("Socket Binding Failed");
  }else{
    Serial.println("Socket Binding Succeeded");
  }


}

unsigned char msg_buf[4096];

void loop() {
  int ret;
  Serial.println("Connecting 192.168.0.30:80");
  //connect to server
  ret = mbedtls_net_connect(&server_ctx, "192.168.0.130", "80", MBEDTLS_NET_PROTO_TCP);
  if (ret != 0) {
    Serial.println("Connection Failed!");
  } else {
    Serial.println("Connected to 192.168.0.130:80");
  }

  //Read/write data (SSL/TLS interface)
  while (true) {
    //send a hello msg to client after connection
    ret = mbedtls_net_send(&server_ctx, (unsigned char*)"hello I am the client", sizeof("hello I am the client"));
    ret = mbedtls_net_recv(&server_ctx, msg_buf, 4096);
    for (int i = 0; i < ret; i++) {
      Serial.print((char)msg_buf[i]);
    }
    Serial.println();
  }


}
