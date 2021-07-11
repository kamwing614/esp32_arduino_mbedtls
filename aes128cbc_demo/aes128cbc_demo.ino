#include "mbedtls/aes.h"

void setup() {
  Serial.begin(115200);
  //Initiate a context for the encryption or decryption
  mbedtls_aes_context ctx;

//decalre 128 bits key
  unsigned char key[16]={
    0x06, 0xa9, 0x21, 0x40, 0x36, 0xb8, 0xa1, 0x5b,
    0x51, 0x2e, 0x03, 0xd5, 0x34, 0x12, 0x00, 0x06,
  };
  //print the key in the serial
  Serial.println("The Key is:");
  for (int i=0;i<sizeof(key);i++){
    if(i%8==0&&i!=0)
    Serial.println();
    Serial.printf("%02x ",int(key[i]));
  }

  Serial.println();

  //declare the iv
  unsigned char iv[16] = {
    0x3d, 0xaf, 0xba, 0x42, 0x9d, 0x9e, 0xb4, 0x30,
    0xb4, 0x22, 0xda, 0x80, 0x2c, 0x9f, 0xac, 0x41,
  };
  //print the iv in serial
   Serial.println("The iv is:");
  for (int i=0;i<sizeof(iv);i++){
    if(i%8==0&&i!=0)
    Serial.println();
    Serial.printf("%02x ",int(iv[i]));
  }
  Serial.println();

  //set the input message
  unsigned char input [14]="hello testing";
  
  //print the input for validation
  Serial.println("The input is:");
  for (int i=0;i<sizeof(input);i++){
    if(i%8==0&&i!=0)
    Serial.println();
    Serial.printf("%02x ",int(input[i]));
  }
  Serial.println();
  Serial.println();

  //declare a buffer to contain the output
  unsigned char output[16];
  mbedtls_aes_init(&ctx);
  
  //load the key into the context
  mbedtls_aes_setkey_enc( &ctx, key, 128 );
  
  Serial.println("Encryption starts...");
  //the encryption starts
  mbedtls_aes_crypt_cbc( &ctx, MBEDTLS_AES_ENCRYPT, 16, iv, input, output );
  Serial.println("Encryption finished...");
  Serial.println();

 //show encrypted hexdump
 Serial.println("The hexdump of the cipher is:");
  for (int i=0;i<sizeof(output);i++){
    if(i%8==0&&i!=0)
    Serial.println();
    Serial.printf("%02x ",int(output[i]));
  }
  Serial.println();
  
  //create buffer to contain the decrypted message
  unsigned char decrypt_data[16];
  //free the context object used before
  mbedtls_aes_free(&ctx);

  //define the key used for decryption
  unsigned char key_dec[32]={
    0x06, 0xa9, 0x21, 0x40, 0x36, 0xb8, 0xa1, 0x5b,
    0x51, 0x2e, 0x03, 0xd5, 0x34, 0x12, 0x00, 0x06,
  };

  //define the iv used for decryption
  unsigned char iv_dec[16] = {
    0x3d, 0xaf, 0xba, 0x42, 0x9d, 0x9e, 0xb4, 0x30,
    0xb4, 0x22, 0xda, 0x80, 0x2c, 0x9f, 0xac, 0x41,
  };

  //set the key for decryption
  mbedtls_aes_setkey_dec( &ctx, key_dec, 128 );
  //start of decryption
  mbedtls_aes_crypt_cbc( &ctx, MBEDTLS_AES_DECRYPT, 16, iv_dec, output, decrypt_data );

  //print out the decrypted message
  Serial.println("The hexdump of the decrypted cipher is:");
  for (int i=0;i<sizeof(decrypt_data);i++){
    if(i%8==0&&i!=0)
    Serial.println();
    Serial.printf("%02x ",int(decrypt_data[i]));
  }
}

void loop() {
  // put your main code here, to run repeatedly:

}
