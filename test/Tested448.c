/*
Current Issues:
-Private key does not generate/randomize with yarrow
-Public key does not match with test vectors when using its "matching" private key
-Memory Leak with malloc/free causing sign function to "randomize"
-In verify, vector p(computed sign from public key) does not match sign
  -it also seems to contain the first half of sign in the second half always

Error Code Translations:
4294901766 = Bad Params
4294914162 = Invalid Sign(Verify Failed)

*/


#include "ed448.h"
//#include "tee_api_defines_ed448.h"
#include "unity.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "error.h"

void setUp() {}

void tearDown() {}

// make sure Unity test works
void test_verifyUnity() {
  int x = 0;
  TEST_ASSERT_EQUAL(0, x);
}
uint8_t PRIVATE_KEY[] = {
    0x6c, 0x82, 0xa5, 0x62, 0xcb, 0x80, 0x8d, 0x10, 0xd6, 0x32, 0xbe, 0x89, 0xc8, 0x51, 0x3e, 0xbf, 0x6c, 0x92, 0x9f, 0x34, 0xdd, 0xfa, 0x8c, 0x9f, 0x63, 0xc9, 0x96, 0x0e, 0xf6, 0xe3, 0x48, 0xa3, 0x52, 0x8c, 0x8a, 0x3f, 0xcc, 0x2f, 0x04, 0x4e, 0x39, 0xa3, 0xfc, 0x5b, 0x94, 0x49, 0x2f, 0x8f, 0x03, 0x2e, 0x75, 0x49, 0xa2, 0x00, 0x98, 0xf9, 0x5b};

 uint8_t PUBLIC_KEY[] = {
    0x5f, 0xd7, 0x44, 0x9b, 0x59, 0xb4, 0x61, 0xfd, 0x2c, 0xe7, 0x87, 0xec, 0x61, 0x6a, 0xd4, 0x6a, 0x1d, 0xa1, 0x34, 0x24, 0x85, 0xa7, 0x0e, 0x1f, 0x8a, 0x0e, 0xa7, 0x5d, 0x80, 0xe9, 0x67, 0x78, 0xed, 0xf1, 0x24, 0x76, 0x9b, 0x46, 0xc7, 0x06, 0x1b, 0xd6, 0x78, 0x3d, 0xf1, 0xe5, 0x0f, 0x6c, 0xd1, 0xfa, 0x1a, 0xbe, 0xaf, 0xe8, 0x25, 0x61, 0x80};

/*sign should be 
*/
void test_keygen() { 
  int a = 1;
  
  uint8_t *emptyPRIVATE_KEY = (uint8_t*) calloc(57, 1);
  uint8_t *emptyPUBLIC_KEY = (uint8_t*) calloc(57, 1);

 
   
  
  //printf("%p\n", x);
  error_t output = ed448GeneratePublicKey(PRIVATE_KEY, emptyPUBLIC_KEY);
/**/
printf("Private Key: "); 
for(int i=0;i<57*sizeof(uint8_t);i++)
{
    printf("%02x", (unsigned)emptyPRIVATE_KEY[i]);
}
printf("\n"); 
printf("Public Key: "); 
for(int j=0;j<57*sizeof(uint8_t);j++)
{
     
    printf("%02x", (unsigned)emptyPUBLIC_KEY[j]);
}
printf("\n");
free(emptyPRIVATE_KEY);
free(emptyPUBLIC_KEY);
  TEST_ASSERT_EQUAL(0, output);
}


 

void test_sign() {
  
  // priv->privateKey = PRIVATE_KEY;
  // pub->publicKey = PUBLIC_KEY;
  char *message = "";
  size_t messageLen = 0;
  
  
  uint8_t *signature = (uint8_t*) malloc(144);
  memset(signature, 0, 144);
  
  error_t output = ed448GenerateSignature(PRIVATE_KEY, PUBLIC_KEY, message, messageLen,
                                             NULL, 0, 0, signature);
 
     //signature= realloc(signature, 114);
printf("Signature: ");        
              
for(int i=0;i<114*sizeof(uint8_t);i++)
    printf("%02x", (unsigned)signature[i]); 
  
   
 memset(signature, 0, 114);
  free(signature);
 

  TEST_ASSERT_EQUAL(0, output);
}

void test_printsign()
{
    const char hexstring[] = "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600", *pos = hexstring;
    unsigned char val[114];

     /* WARNING: no sanitization or error-checking whatsoever */
    for (size_t count = 0; count < sizeof val/sizeof *val; count++) {
        sscanf(pos, "%2hhx", &val[count]);
        pos += 2;
    }
    
    
    for(size_t count = 0; count < sizeof val/sizeof *val; count++)
    {
        printf(", 0x");
        printf("%02x", val[count]);
    }
    printf("\n");
}
void test_verifysign()
{
  

  // priv->privateKey = PRIVATE_KEY;
  // pub->publicKey = PUBLIC_KEY;
  char *message = "";
  size_t messageLen = 0;
  
  uint8_t signature[] = {
     0x53, 0x3a, 0x37, 0xf6, 0xbb, 0xe4, 0x57, 0x25, 0x1f, 0x02, 0x3c, 0x0d, 0x88, 0xf9, 0x76, 0xae, 0x2d, 0xfb, 0x50, 0x4a, 0x84, 0x3e, 0x34, 0xd2, 0x07, 0x4f, 0xd8, 0x23, 0xd4, 0x1a, 0x59, 0x1f, 0x2b, 0x23, 0x3f, 0x03, 0x4f, 0x62, 0x82, 0x81, 0xf2, 0xfd, 0x7a, 0x22, 0xdd, 0xd4, 0x7d, 0x78, 0x28, 0xc5, 0x9b, 0xd0, 0xa2, 0x1b, 0xfd, 0x39, 0x80, 0xff, 0x0d, 0x20, 0x28, 0xd4, 0xb1, 0x8a, 0x9d, 0xf6, 0x3e, 0x00, 0x6c, 0x5d, 0x1c, 0x2d, 0x34, 0x5b, 0x92, 0x5d, 0x8d, 0xc0, 0x0b, 0x41, 0x04, 0x85, 0x2d, 0xb9, 0x9a, 0xc5, 0xc7, 0xcd, 0xda, 0x85, 0x30, 0xa1, 0x13, 0xa0, 0xf4, 0xdb, 0xb6, 0x11, 0x49, 0xf0, 0x5a, 0x73, 0x63, 0x26, 0x8c, 0x71, 0xd9, 0x58, 0x08, 0xff, 0x2e, 0x65, 0x26, 0x00};
 
//uint8_t signature[114];
     uint8_t *sign = signature;

error_t output = ed448VerifySignature(PUBLIC_KEY, message, messageLen,
                                            NULL, 0, 0, sign);
    TEST_ASSERT_EQUAL(0, output);

}
int main(void) {
  UNITY_BEGIN();

  //RUN_TEST(test_verifyUnity);
   //RUN_TEST(test_keygen);
   
  //RUN_TEST(test_sign);
  //RUN_TEST(test_printsign); 
 RUN_TEST(test_verifysign);
   
  return UNITY_END();
} 
