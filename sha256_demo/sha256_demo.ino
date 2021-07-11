#include "mbedtls/md.h"

//to modify the codes for own use, just change the value of the p1
void setup(){

  Serial.begin(115200);
//create message for hashing 
  char *payload = "Hello SHA 256!";//<-- here is the only thing to modify for our own use

  
//store the hash
  byte sha_result[32];

//get the size of the message 
  const size_t payload_length = strlen(payload);

//create a context for operating the hashing
  mbedtls_md_context_t ctx;
//specify the hash function
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

//start of hashing//
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx, (const unsigned char *) payload, payload_length);
  mbedtls_md_finish(&ctx, sha_result);
  mbedtls_md_free(&ctx);
//end of hashing//

//start to print out the hash//
  Serial.println("Hash: of 'Hello SHA 256!'");
  for(int i= 0; i< sizeof(sha_result); i++){
      char str[2];
      sprintf(str, "%02x", (int)sha_result[i]);
      Serial.print(str);  
  }
//end of printing hash

}

void loop(){}
