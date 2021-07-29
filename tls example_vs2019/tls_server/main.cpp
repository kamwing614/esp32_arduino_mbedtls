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

#pragma comment(lib,"mbedTLS.lib")
#include "mbedtls/aes.h"
#include <iostream>


char buf[4096];
const char* PORT = "443";
mbedtls_net_context client_ctx;
mbedtls_net_context listening_ctx;
mbedtls_rsa_context* rsa_private_key_ctx;
mbedtls_pk_context pk;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_x509_crt server_cert, ca_cert;

mbedtls_ssl_context ssl_ctx;
mbedtls_ssl_config ssl_conf;
bool error = false;
char err_msg[4096];
unsigned char msg_buf[4096];

static void my_debug(void* ctx, int level, const char* file, int line, const char* str);
int main() {

    printf("TLS Server running... \n");
    const char* ssid = "TP-Link_82F4";
    const char* password = "31208499";

    int ret;
    //Load your certificate and your private RSA key (X.509 interface)
    const char* pers = "rsa_seed";

    //initialize context
    mbedtls_x509_crt_init(&server_cert);
    mbedtls_x509_crt_init(&ca_cert);
    /* 2. Parse CA cert */
    printf("\n  . Parse cacert...");

    ret = mbedtls_x509_crt_parse(&ca_cert, (unsigned char*)ca_cert_buf, sizeof(ca_cert_buf));
    if (ret != 0) {
        printf(" failed\n  ! mbedtls_x509_crt_parse cacert returned % d(-0x % 04x)\n", ret, -ret);
        error = true;
    }
    else {
        printf(" Successfully Parsed the CA cert \n");
    }


    /* 2. Load CA cert info into buffer and then show */
    printf("\n  . CA Cert Information: ");

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

    /* 2. Parse server cert */
    ret = mbedtls_x509_crt_parse(&server_cert, (unsigned char*)server_cert_buf, sizeof(server_cert_buf));
    if (ret != 0) {
        printf(" failed\n  ! mbedtls_x509_crt_parse cacert returned % d(-0x % 04x)\n", ret, -ret);
        error = true;
    }
    else {
        printf("Successfully parsed the Server's cert \n");
    }


    /* 2. Load Server's cert into buffer and show */
    printf("\n  . Server Cert Information: \n");

    ret = mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "      ", &server_cert);
    if (ret < 0) {
        printf("fail! mbedtls_x509_crt_info return % d(-0x % 04x)\n", ret, -ret);
        error = true;
    }
    else {
        buf[ret] = '\0';
        printf("Successfully Load Server's cert into buffer!\r\n");
        printf("crt info has % d chars\r\n", strlen(buf));
        printf(" % s\r\n", buf);
    }

    //Parsing RSA key from Server cert

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_pk_init(&pk);

    printf("\n  . Seeding the random bit generator...");
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
        (const unsigned char*)pers,
        strlen(pers));
    if (ret != 0) {
        printf(" failed\n  ! mbedtls_ctr_drbg_seed returned % d(-0x % 04x)\n", ret, -ret);
    }
    else {
        printf(" Random Bit Generator is Seeded. \n");
    }

    ret = mbedtls_pk_parse_key(&pk, (unsigned char*)server_rsa_key_buf, sizeof(server_rsa_key_buf), NULL, 0, NULL, NULL);
    if (ret != 0) {
        printf("failed parsing rsa key, the error code is: % d(-0x % 04x)\n", ret, -ret);
        error = true;
    }
    else {
        printf("The RSA Key is Parsed from the Server Cert.\n");
    }

    rsa_private_key_ctx = mbedtls_pk_rsa(pk);


    //Setup the listening TCP socket (TCP/IP interface)

    mbedtls_net_init(&listening_ctx);
    mbedtls_net_init(&client_ctx);



    printf("Now Creating the Listening Socket... \n");
    ret = mbedtls_net_bind(&listening_ctx, "127.0.0.1", PORT, MBEDTLS_NET_PROTO_TCP);


    if (ret != 0) {
        printf("Socket Creation Failed!...the error code is: % d(-0x % 04x)\n", ret, -ret);
        error = true;
    }
    else {
        printf("Socket Created at IP: 127.0.0.1, PORT %s", PORT);

    }

    //exit:
    //  /* 3. release structure */
    //  mbedtls_x509_crt_free(&server_cert);
    //  mbedtls_x509_crt_free(&ca_cert);
    //  printf("Program Finished");

    if (error == true) {
        printf("Failed\n");
    }

    printf("Waiting for connection...\n");
    //accept connection from client
    ret = mbedtls_net_accept(&listening_ctx, &client_ctx, NULL, sizeof(NULL), NULL);
    if (ret != 0) {
        printf("Connection Failed!\n");
    }
    else {
        printf("A client has connected!\n");
    }

    //Initialise as an SSL-server (SSL/TLS interface)
    mbedtls_ssl_init(&ssl_ctx);
    printf("Just initiated the ssl context\n");
    //Set parameters, e.g. authentication, ciphers, CA-chain, key exchange
    ret = mbedtls_ssl_config_defaults(&ssl_conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        printf("ssl default config failed!\n");
    }
    else {
        printf("ssl default config succeed!\n");
    }
    printf("loading CA cert\n");
    mbedtls_ssl_conf_ca_chain(&ssl_conf, &ca_cert, NULL);//mbedtls_x509_crt server_cert, ca_cert
    printf("loading OWN cert\n");
    mbedtls_ssl_conf_own_cert(&ssl_conf, &server_cert, &pk);
    //Set callback functions RNG, IO, session handling
    printf("Setting RNG\n");
    mbedtls_ssl_conf_rng(&ssl_conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    printf("Setting debug callback\n");
    mbedtls_ssl_conf_dbg(&ssl_conf, my_debug, NULL);

    printf("Setting read write function\n");
    mbedtls_ssl_set_bio(&ssl_ctx, &client_ctx, mbedtls_net_send, mbedtls_net_recv, NULL);

    //config cipher suites 
    mbedtls_ssl_conf_max_version(&ssl_conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_min_version(&ssl_conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    // Only use this cipher suite (TLS1.2)
    static const int tls_cipher_suites[2] = { MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0 };
    mbedtls_ssl_conf_ciphersuites(&ssl_conf, tls_cipher_suites);


    if ((ret = mbedtls_ssl_setup(&ssl_ctx, &ssl_conf)) != 0) {
        printf("mbedtls_ssl_setup failed, error code is %d \n", ret);
    }
    else {
        printf("Config is loaded successfully\n");
    }



    //Perform an SSL-handshake (SSL/TLS interface)
    ret = mbedtls_ssl_handshake(&ssl_ctx);
    if (ret != 0) {
        printf("Handshake Fail, Error Code is: %d |%x", ret, ret);
    }
    else {
        printf("Handshake done\n");
    }
    //Read/write data (SSL/TLS interface)
    //Close and cleanup (all interfaces)
    int count = 0;
    while (count<3) {
        //send a hello msg to client after connection
        //ret = mbedtls_net_send(&client_ctx, (unsigned char*)"hello", sizeof("hello"));
        ret = mbedtls_ssl_write(&ssl_ctx, (unsigned char*)"Welcome to the server", sizeof("Welcome to the server"));
        ret = mbedtls_ssl_read(&ssl_ctx, msg_buf, 4096);
        //ret = mbedtls_net_recv(&client_ctx, msg_buf, 4096);
        printf("Received Message from Client:\n");
        for (int i = 0; i < ret; i++) {
            printf("%c", (char)msg_buf[i]);
        }
        printf("\n");
        count++;
    }
    printf("3 send&receive is done, connection finished\n");
    mbedtls_net_free(&listening_ctx);
    mbedtls_net_free(&client_ctx);
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

