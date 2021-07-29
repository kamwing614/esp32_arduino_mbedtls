#include "mbedtls/build_info.h"
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
#include "mbedtls/tls_server_cert.h"
#include "mbedtls/ssl.h"
#include <stddef.h>
#include <stdint.h>
#include "mbedtls/net_sockets.h"


#include "mbedtls/aes.h"
#include <iostream>
#pragma comment(lib,"mbedTLS.lib")


//#define SERVER_PORT 443
//#define SERVER_NAME "192.168.0.128"

char buf[4096];
const char* PORT = "443";
mbedtls_net_context server_ctx, listening_ctx;

mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_x509_crt ca_cert;

mbedtls_ssl_context ssl_ctx;
mbedtls_ssl_config ssl_conf;
bool error = false;

static void my_debug(void* ctx, int level, const char* file, int line, const char* str);

int main() {
    
    printf("TLS Client running... \n");
 

    int ret;
    //Load your certificate and your private RSA key (X.509 interface)
    const char* pers = "rsa_seed";

    //initialize context
    mbedtls_x509_crt_init(&ca_cert);
    /* 2. Parse CA cert */
    printf("\n  . Parse cacert...\n");

    ret = mbedtls_x509_crt_parse(&ca_cert, (unsigned char*)ca_cert_buf, sizeof(ca_cert_buf));
    if (ret != 0) {
        printf(" failed\n  ! mbedtls_x509_crt_parse cacert returned % d(-0x % 04x)\n", ret, -ret);
        error = true;
    }
    else {
        printf(" Successfully Parsed the CA cert \n");
    }


    /* 2. Load CA cert info into buffer and then show */
    printf("\n  . CA Cert Information: \n");

    ret = mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "      ", &ca_cert);
    if (ret < 0) {
        printf("fail! mbedtls_x509_crt_info return % d(-0x % 04x)\n", ret, -ret);
        error = true;
    }
    else {
        buf[ret] = '\0';
        printf("CA cert info is successfully loaded into buffer:\r\n");
        printf("crt info has % d chars\r\n", strlen(buf));
        printf(" % s\r\n", buf);
    }




    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    printf("\n  . Seeding the random bit generator...\n");
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
        (const unsigned char*)pers,
        strlen(pers));
    if (ret != 0) {
        printf(" failed\n  ! mbedtls_ctr_drbg_seed returned % d(-0x % 04x)\n", ret, -ret);
    }
    else {
        printf(" Random Bit Generator is Seeded. \n");
    }


    //Setup the listening TCP socket (TCP/IP interface)


    mbedtls_net_init(&server_ctx);
    mbedtls_net_init(&listening_ctx);

    ret = mbedtls_net_bind(&listening_ctx, "127.0.0.1", "81", MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        printf("Socket Binding Failed\n");
    }
    else {
        printf("Socket Binding Succeeded\n");
    }

    //exit:
    //  /* 3. release structure */
    //  mbedtls_x509_crt_free(&server_cert);
    //  mbedtls_x509_crt_free(&ca_cert);
    //  printf("Program Finished");


    printf("Connecting 127.0.0.1:443\n");
    //connect to server
    ret = mbedtls_net_connect(&server_ctx, "127.0.0.1", "443", MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        printf("Connection Failed!\n");
    }
    else {
        printf("Connected to server!\n");
    }

    //Initialise as an SSL-server (SSL/TLS interface)
    mbedtls_ssl_init(&ssl_ctx);
    //Set parameters, e.g. authentication, ciphers, CA-chain, key exchange
    ret = mbedtls_ssl_config_defaults(&ssl_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);

    if (ret != 0) {
        printf("ssl config error!\n");
        printf("Error Code is: %d\n", ret);
    }
    else {
        printf("Successfully set the default config!\n");
    }
    //set the authenication mode. It determines how strictly the certificates are checked.
    printf("Setting auth mode!\n");
    //mbedtls_ssl_conf_authmode( &ssl_conf, MBEDTLS_SSL_VERIFY_NONE );
    mbedtls_ssl_conf_authmode(&ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    //Set callback functions RNG, IO, session handling
    printf("Setting RNG Callback!\n");
    mbedtls_ssl_conf_rng(&ssl_conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    printf("Setting Debug Callback!\n");
    mbedtls_ssl_conf_dbg(&ssl_conf, my_debug, NULL);

    if ((ret = mbedtls_ssl_set_hostname(&ssl_ctx, "CityU_CS")) != 0) {
        printf(" failed\n ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
    }
    else {
        printf("Hostname is match!\n");
    }
    printf("Setting communication function!\n");
    mbedtls_ssl_set_bio(&ssl_ctx, &server_ctx, mbedtls_net_send, mbedtls_net_recv, NULL);
    printf("Setting Trusted CA chain!\n");
    mbedtls_ssl_conf_ca_chain(&ssl_conf, &ca_cert, NULL);//mbedtls_x509_crt server_cert, ca_cert
    //config cipher suites
    mbedtls_ssl_conf_max_version(&ssl_conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_min_version(&ssl_conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    // Only use this cipher suite
    static const int tls_cipher_suites[2] = { MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0 };
    mbedtls_ssl_conf_ciphersuites(&ssl_conf, tls_cipher_suites);

    if ((ret = mbedtls_ssl_setup(&ssl_ctx, &ssl_conf)) != 0) {
        printf("mbedtls_ssl_setup failed, error code is %d \n", ret);
    }
    else {
        printf("Config is successfully loaded into ssl context\n");
    }
    //Perform an SSL-handshake (SSL/TLS interface)
    //  ret = mbedtls_ssl_handshake(&ssl_ctx);
    //  if (ret != 0) {
    //    Serial.printf("Handshake Fail, Error Code is: %d |%x", ret, ret);
    //  }else{
    //    printf("Handshake done");
    //  }

    //Read/write data (SSL/TLS interface)
    unsigned char msg_buf[4096];
    int count = 0;
    while (count < 3) {
        char greeting[] = "Hello I am Alice";
        //send a hello msg to client after connection
        //ret = mbedtls_net_send(&client_ctx, (unsigned char*)"hello", sizeof("hello"));
        ret = mbedtls_ssl_write(&ssl_ctx, (unsigned char*)greeting, sizeof(greeting));
        ret = mbedtls_ssl_read(&ssl_ctx, msg_buf, 4096);
        //ret = mbedtls_net_recv(&client_ctx, msg_buf, 4096);
        printf("Received Message from Server:\n");
        for (int i = 0; i < ret; i++) {
            printf("%c",(char)msg_buf[i]);
        }
        printf("\n");
        count++;
    }
    printf("3 send&receive is done, connection finished\n");
    mbedtls_net_free(&server_ctx);
    mbedtls_net_free(&listening_ctx);
    mbedtls_ssl_free(&ssl_ctx);
    mbedtls_ssl_config_free(&ssl_conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    
    return 0;

}

static void my_debug(void* ctx, int level, const char* file, int line, const char* str) {
    ((void)level);
    fprintf((FILE*)ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE*)ctx);
}
