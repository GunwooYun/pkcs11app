#include <dlfcn.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "pkcs11.h"

CK_FUNCTION_LIST *pFuncList = NULL;

void handle_error(CK_RV rv, char *msg)
{
   if(rv != CKR_OK)
   {
      fprintf(stderr, "%s (ERROR 0x%lx)\n", msg, rv);
      exit(1);
   }
   return;
}

void showCryptokiName(const char *api)
{
   printf("\n");
   printf("\x1b[31m%s\n", api);
   printf("\x1b[0m");
}


CK_RV showSlotInfo(CK_SLOT_ID slot)
{  
   CK_SLOT_INFO slotInfo;
   CK_RV rv = 0;
   rv = pFuncList->C_GetSlotInfo(slot, &slotInfo);
   if(rv == CKR_OK)
   {
      printf("Slot Information:\n");
      printf("  Slot ID: %lu\n", slot);
      printf("  Slot Description: %s\n", slotInfo.slotDescription);
      printf("  Manufacturer ID: %s\n",  slotInfo.manufacturerID);
      printf("  Hardware Version: %d.%d\n", slotInfo.hardwareVersion.major, slotInfo.hardwareVersion.minor);
      printf("  Firmware Version: %d.%d\n", slotInfo.firmwareVersion.major, slotInfo.firmwareVersion.minor);
   }
   return rv;
}

CK_RV showTokenInfo(CK_SLOT_ID slot)
{  
   CK_TOKEN_INFO tokenInfo;
   CK_RV rv = 0;
   rv = pFuncList->C_GetTokenInfo(slot, &tokenInfo);
   if(rv == CKR_OK)
   {
      printf("\nToken Information:\n");
      printf("  Label: %s\n", tokenInfo.label);
      printf("  Manufacturer ID: %s\n", tokenInfo.manufacturerID);
      printf("  Model: %s\n", tokenInfo.model);
      printf("  Serial Number: %s\n", tokenInfo.serialNumber);
      printf("  Flags: 0x%lx\n", tokenInfo.flags);
      printf("  Max PIN Length: %lu\n", tokenInfo.ulMaxPinLen);
      printf("  Min PIN Length: %lu\n", tokenInfo.ulMinPinLen);
      printf("  Public Memory: %lu\n", tokenInfo.ulTotalPublicMemory);
      printf("  Free Public Memory: %lu\n", tokenInfo.ulFreePublicMemory);
      printf("  Private Memory: %lu\n", tokenInfo.ulTotalPrivateMemory);
      printf("  Free Private Memory: %lu\n", tokenInfo.ulFreePrivateMemory);
   }
   return rv;
}

int main()
{
   CK_C_GetFunctionList get_functionlist = {NULL};
   CK_SESSION_HANDLE session = CK_INVALID_HANDLE; /* Session handler */
   void *pkcs11so = NULL;
   CK_FLAGS flags;
   int rc = -1;
   char *ptr;
   CK_RV rv; /* Cryptoki Retrun value */


   /* Dynamic Library Handler */
   void *pDlHandle = dlopen("/usr/local/lib/softhsm/libsofthsm2.so", RTLD_NOW | RTLD_LOCAL);
   if(NULL == pDlHandle)
   {
      printf("Failed to load dynamic library\n");
      return 1;
   }

   *(void **)(&get_functionlist) = dlsym(pDlHandle, "C_GetFunctionList");
   if (get_functionlist == NULL)
   {
      printf("check 2\n");
      return 1;
   }

   /* Get functions of PKCS#11 */
   rv = get_functionlist(&pFuncList);
   handle_error(rv, "get_functionlist");

   /* Initialize the Cryptoki library */
   showCryptokiName("C_Initialize");
   rv = pFuncList->C_Initialize(NULL); // No thread
   handle_error(rv, "C_Initialize");

   /* Get Cryptoki info */
   showCryptokiName("C_GetInfo");
   CK_INFO info; /* Cryptoki information */
   rv = pFuncList->C_GetInfo(&info);
   handle_error(rv, "C_GetInfo");
   printf("Library Description: %s\n", info.libraryDescription);
   printf("Library Version: %u.%u\n", info.libraryVersion.major, info.libraryVersion.minor);
   printf("Manufacturer ID: %s\n", info.manufacturerID);
   printf("Flags: 0x%lX\n", info.flags);
   
   /* Get Slot List */
   showCryptokiName("C_GetSlotList");
   CK_ULONG ulSlotCnt = 0;
   CK_SLOT_ID_PTR pSlotList = NULL;

   rv = pFuncList->C_GetSlotList(CK_FALSE, NULL_PTR, &ulSlotCnt); /* Return number of slots */
   if(rv == CKR_OK)
   {
      /* Allocate memory according to the size of number of slots */
      pSlotList = (CK_SLOT_ID_PTR)malloc(ulSlotCnt * sizeof(CK_SLOT_ID));
      if(pSlotList != NULL)
      {
         rv = pFuncList->C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCnt);
         if(rv == CKR_OK)
         {
            printf("Slot Count: %ld\n", ulSlotCnt);
         }
         else
         {
            handle_error(rv, "C_GetSlotList");
         }
      }
   }
   else
   {
      handle_error(rv, "C_GetSlotList");
   }

   /* Get slot info */
   showCryptokiName("C_GetSlotInfo");
   CK_SLOT_INFO slotInfo;
   for(int i = 0; i < ulSlotCnt; i++)
   {
      rv = pFuncList->C_GetSlotInfo(pSlotList[i], &slotInfo);
      if(rv == CKR_OK)
      {
         printf("Slot Description: %s\n", slotInfo.slotDescription);
         printf("Manufacturer ID: %s\n", slotInfo.manufacturerID);
         printf("Flags: 0x%lX\n", slotInfo.flags);
      }
   }

   /* Get token info */
   showCryptokiName("C_GetTokenInfo");
   CK_TOKEN_INFO tokenInfo;
   rv = pFuncList->C_GetTokenInfo(pSlotList[0], &tokenInfo);
   if(rv == CKR_OK)
   {
      printf("Token Information:\n");
      printf("  Label: %s\n", tokenInfo.label);
      printf("  Manufacturer ID: %s\n", tokenInfo.manufacturerID);
      printf("  Model: %s\n", tokenInfo.model);
      printf("  Serial Number: %s\n", tokenInfo.serialNumber);
      printf("  Flags: 0x%lx\n", tokenInfo.flags);
      printf("  Max PIN Length: %lu\n", tokenInfo.ulMaxPinLen);
      printf("  Min PIN Length: %lu\n", tokenInfo.ulMinPinLen);
      printf("  Public Memory: %lu\n", tokenInfo.ulTotalPublicMemory);
      printf("  Free Public Memory: %lu\n", tokenInfo.ulFreePublicMemory);
      printf("  Private Memory: %lu\n", tokenInfo.ulTotalPrivateMemory);
      printf("  Free Private Memory: %lu\n", tokenInfo.ulFreePrivateMemory);
   }

   /* Open a session between an application and a token in a particular slot */
   showCryptokiName("C_OpenSession");
   printf("before open session: %ld\n", session);
   rv = pFuncList->C_OpenSession(pSlotList[0], /* slot ID */
                          CKF_SERIAL_SESSION | CKF_RW_SESSION, /* flag */
                          NULL, /* pApplication: an application-defined pointer to be passed to the notification callback */
                          NULL, /* Notify: the address of the notification callback funtion */
                          &session /* phSession: points to the location that receives the handle for the new session */
   );
   handle_error(rv, "C_OpenSession");
   printf("after open session: %ld\n", session);

   /* Login */
   showCryptokiName("C_Login");
   rv = pFuncList->C_Login(session,                   /* Session handler */
                           CKU_USER,                  /* User */
                           (CK_UTF8CHAR_PTR)"ranix",  /* PIN */
                           5);                        /* PIN length */
   handle_error(rv, "C_Login");


   /* Generate Random Data */
   showCryptokiName("C_GenerateRandom");
   CK_BYTE pRandom[16] = {0};
   CK_ULONG ulRandomLen = sizeof(pRandom);
   rv = pFuncList->C_GenerateRandom(session, pRandom, ulRandomLen);
   handle_error(rv, "C_GenerateRandom");

   int i = 0;
   printf("Random: ");
   while(i < ulRandomLen)
   {
      printf("%02x ", pRandom[i++]);
   }
   printf("\n");

   /* Message digest */
   showCryptokiName("C_DigestInit");
   CK_MECHANISM mechanism = {CKM_SHA256, NULL_PTR, 0}; /* SHA256 */
   rv = pFuncList->C_DigestInit(session, &mechanism);
   handle_error(rv, "C_DigestInit");

   showCryptokiName("C_DigestUpdate");
   unsigned char msg[64] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,};
   rv = pFuncList->C_DigestUpdate(session, msg, sizeof(msg));
   handle_error(rv, "C_DigestUpdate");

   showCryptokiName("C_DigestFinal");
   unsigned char digest[32] = {0};
   CK_ULONG ulDigestLen = sizeof(digest);

   rv = pFuncList->C_DigestFinal(session, digest, &ulDigestLen);
   handle_error(rv, "C_DigestFinal");
   printf("Digest: ");
   for (int i = 0; i < ulDigestLen; i++) {
      printf("%02x ", digest[i]);
   }

   showCryptokiName("C_Digest");
   rv = pFuncList->C_DigestInit(session, &mechanism);
   handle_error(rv, "C_DigestInit");

   rv = pFuncList->C_Digest(session, msg, sizeof(msg), digest, &ulDigestLen);
   handle_error(rv, "C_Digest");
   printf("Digest: ");
   for (int i = 0; i < ulDigestLen; i++) {
      printf("%02x ", digest[i]);
   }

   showCryptokiName("C_DigestKey");
   CK_MECHANISM hmacMechanism = {CKM_SHA256, NULL_PTR, 0}; /* CK_MECHANISM 구조체 */
   rv = pFuncList->C_DigestInit(session, &hmacMechanism);
   handle_error(rv, "C_DigestInit");

   /* Generate a key for digest */
   CK_OBJECT_HANDLE hDigestKey; /* Create key object handle */
   CK_MECHANISM digestMechanism = {CKM_AES_KEY_GEN, NULL_PTR, 0}; /* CK_MECHANISM 구조체 */
   CK_OBJECT_CLASS digestKeyClass = CKO_SECRET_KEY;
   CK_KEY_TYPE digestKeyType = CKK_AES;
   CK_BBOOL extractable = CK_TRUE;
   unsigned char keyValue[16] = {0};
   CK_ULONG digestKeySize = 16;
   CK_ATTRIBUTE digestKeyTemplate[] = {                  /* CK_ATTRIBUTE: structure includes type, value, length */
      {CKA_CLASS, &digestKeyClass, sizeof(digestKeyClass)},    /* Set object class */
      {CKA_KEY_TYPE, &digestKeyType, sizeof(digestKeyType)},   /* Set key type */
      {CKA_EXTRACTABLE, &extractable, sizeof(extractable)},   /* Set key type */
      //{CKA_ENCRYPT, &true, sizeof(true)},          /* Secret key: encryption */
      //{CKA_DECRYPT, &true, sizeof(true)},          /* Secret key: decryption */
      //{CKA_VALUE, (unsigned char*)keyValue, sizeof(keyValue)},          /* Secret key: decryption */
      {CKA_VALUE_LEN, &digestKeySize, sizeof(digestKeySize)}   /* Secret key: length */
   };

   rv = pFuncList->C_GenerateKey(session,                                     /* Session handler */
                                 &digestMechanism,                                  /* Generation mechanism */
                                 digestKeyTemplate,                                 /* template for new key */
                                 sizeof(digestKeyTemplate) / sizeof(digestKeyTemplate[0]), /* number of template */
                                 &hDigestKey);                                      /* New key hanadler */
   handle_error(rv, "C_Generatekey");

   rv = pFuncList->C_DigestKey(session, hDigestKey);
   handle_error(rv, "C_DigestKey");

   rv = pFuncList->C_DigestFinal(session, digest, &ulDigestLen);
   handle_error(rv, "C_DigestFinal");
   printf("Digest Key: ");
   for (int i = 0; i < ulDigestLen; i++) {
      printf("%02x ", digest[i]);
   }

   /* Message sign (MAC) */
   showCryptokiName("C_SignInit");
   
   CK_MECHANISM macMech = {CKM_SHA256_HMAC, NULL_PTR, 0};

   CK_OBJECT_HANDLE hMacKey;
   CK_MECHANISM macKeyMech = {CKM_GENERIC_SECRET_KEY_GEN, NULL_PTR, 0}; /* CK_MECHANISM 구조체 */
   CK_OBJECT_CLASS macKeyClass = CKO_SECRET_KEY;
   CK_KEY_TYPE macKeyType = CKK_GENERIC_SECRET;
   CK_ULONG macKeySize = 32; /* HMAC-SHA256 keyLen >= 32 */

   CK_ATTRIBUTE macKeyTemplate[] = {                  /* CK_ATTRIBUTE: structure includes type, value, length */
      {CKA_CLASS, &macKeyClass, sizeof(macKeyClass)},    /* Set object class */
      {CKA_KEY_TYPE, &macKeyType, sizeof(macKeyType)},   /* Set key type */
      {CKA_VALUE_LEN, &macKeySize, sizeof(macKeySize)}   /* Secret key: length */
   };

#if 1
   rv = pFuncList->C_GenerateKey(session,                                     /* Session handler */
                                 &macKeyMech,                                  /* Generation mechanism */
                                 macKeyTemplate,                                 /* template for new key */
                                 sizeof(macKeyTemplate) / sizeof(macKeyTemplate[0]), /* number of template */
                                 &hMacKey);                                      /* New key hanadler */
   handle_error(rv, "C_Generatekey");
#endif


   rv = pFuncList->C_SignInit(session, &macMech, hMacKey);
   handle_error(rv, "C_SignInit");

   showCryptokiName("C_SignUpdate");
   rv = pFuncList->C_SignUpdate(session, msg, sizeof(msg));
   handle_error(rv, "C_SignUpdate");

   showCryptokiName("C_SignFinal");
   unsigned char signature[64] = {0};
   CK_ULONG ulSignatureLen = sizeof(signature);
   rv = pFuncList->C_SignFinal(session, (unsigned char *)signature, &ulSignatureLen);
   handle_error(rv, "C_SignFinal");

   printf("Signature(MAC): ");
   for (int i = 0; i < ulSignatureLen; i++) {
      printf("%02x ", signature[i]);
   }

   showCryptokiName("C_Sign");
   rv = pFuncList->C_SignInit(session, &macMech, hMacKey);
   handle_error(rv, "C_SignInit");
   rv = pFuncList->C_Sign(session, msg, sizeof(msg),(unsigned char *)signature, &ulSignatureLen);
   handle_error(rv, "C_Sign");
   printf("Signature(MAC): ");
   for (int i = 0; i < ulSignatureLen; i++) {
      printf("%02x ", signature[i]);
   }
   printf("\n");

#if 0
   /* Message Sign and Verify */
   showCryptokiName("C_SignInit");
   
   CK_MECHANISM ecdsaMech = {CKM_ECDSA_SHA256, NULL_PTR, 0};

   CK_OBJECT_HANDLE hSignKey;
   CK_MECHANISM ecdsaKeyMech = {CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0}; /* CK_MECHANISM 구조체 */
   CK_OBJECT_CLASS signKeyClass = CKO_PRIVATE_KEY;
   CK_KEY_TYPE ecdsaKeyType = CKK_ECDSA;
   CK_ULONG signKeySize = 32; /* HMAC-SHA256 keyLen >= 32 */

   CK_ATTRIBUTE ecdsaKeyTemplate[] = {                  /* CK_ATTRIBUTE: structure includes type, value, length */
      {CKA_CLASS, &signKeyClass, sizeof(signKeyClass)},    /* Set object class */
      {CKA_KEY_TYPE, &ecdsaKeyType, sizeof(ecdsaKeyType)},   /* Set key type */
      {CKA_VALUE_LEN, &signKeySize, sizeof(signKeySize)}   /* Secret key: length */
   };

#if 1
   rv = pFuncList->C_GenerateKey(session,
                                 &ecdsaKeyMech,
                                 ecdsaKeyTemplate,
                                 sizeof(ecdsaKeyTemplate) / sizeof(ecdsaKeyTemplate[0]),
                                 &hSignKey);
   handle_error(rv, "C_Generatekey");
#endif

   rv = pFuncList->C_SignInit(session, &macMech, hMacKey);
   handle_error(rv, "C_SignInit");

   showCryptokiName("C_SignUpdate");
   rv = pFuncList->C_SignUpdate(session, msg, sizeof(msg));
   handle_error(rv, "C_SignUpdate");

   showCryptokiName("C_SignFinal");
   unsigned char signature[64] = {0};
   CK_ULONG ulSignatureLen = sizeof(signature);
   rv = pFuncList->C_SignFinal(session, (unsigned char *)signature, &ulSignatureLen);
   handle_error(rv, "C_SignFinal");

   printf("Signature(MAC): ");
   for (int i = 0; i < ulSignatureLen; i++) {
      printf("%02x ", signature[i]);
   }

   showCryptokiName("C_Sign");
   rv = pFuncList->C_SignInit(session, &macMech, hMacKey);
   handle_error(rv, "C_SignInit");
   rv = pFuncList->C_Sign(session, msg, sizeof(msg),(unsigned char *)signature, &ulSignatureLen);
   handle_error(rv, "C_Sign");
   printf("Signature(MAC): ");
   for (int i = 0; i < ulSignatureLen; i++) {
      printf("%02x ", signature[i]);
   }
#endif

   /* Generate AES key */
   CK_OBJECT_HANDLE hKey; /* Create key object handle */
   CK_MECHANISM encMechanism = {CKM_AES_KEY_GEN, NULL_PTR, 0}; /* CK_MECHANISM 구조체 */
   CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
   CK_KEY_TYPE keyType = CKK_AES;
   CK_BBOOL true = CK_TRUE;
   CK_ULONG keySize = 16;
   CK_ATTRIBUTE keyTemplate[] = {                  /* CK_ATTRIBUTE: structure includes type, value, length */
      {CKA_CLASS, &keyClass, sizeof(keyClass)},    /* Set object class */
      {CKA_KEY_TYPE, &keyType, sizeof(keyType)},   /* Set key type */
      {CKA_ENCRYPT, &true, sizeof(true)},          /* Secret key: encryption */
      {CKA_DECRYPT, &true, sizeof(true)},          /* Secret key: decryption */
      {CKA_EXTRACTABLE, &true, sizeof(true)},          /* Secret key: decryption */
      {CKA_VALUE_LEN, &keySize, sizeof(keySize)}   /* Secret key: length */
   };

   rv = pFuncList->C_GenerateKey(session,                                     /* Session handler */
                                 &encMechanism,                                  /* Generation mechanism */
                                 keyTemplate,                                 /* template for new key */
                                 sizeof(keyTemplate) / sizeof(keyTemplate[0]), /* number of template */
                                 &hKey);                                      /* New key hanadler */
   handle_error(rv, "C_Generatekey");

   CK_ULONG ul_plainLen = 32;
   CK_ULONG ul_encLen = 32;
   CK_ULONG ul_decLen = 32;
   unsigned char IV[16] = {0};

   CK_BYTE pPlain[32] = {0};
   CK_BYTE pCipher[32] = {0};

   CK_BYTE pDePlain[32] = {0};

   CK_MECHANISM aesMech = {CKM_AES_CBC, (unsigned char *)IV, 16}; /* AES-CBC, iv, iv length */


   /* Initialize encryption operation */
   showCryptokiName("C_EncryptInit");
   rv = pFuncList->C_EncryptInit(session, &aesMech, hKey);
   handle_error(rv, "C_EncryptInit");

   showCryptokiName("C_Encrypt");
   printf("plain: ");
   for(int i = 0; i < ul_plainLen; i++)
   {
      printf("%02x ", pPlain[i]);
   }
   printf("\n");
   rv = pFuncList->C_Encrypt(session, pPlain, ul_plainLen, pCipher, &ul_encLen);
   handle_error(rv, "C_EncryptUpdate");

   printf("cipher: ");
   for(int i = 0; i < ul_encLen; i++)
   {
      printf("%02x ", pCipher[i]);
   }
   printf("\n");

   showCryptokiName("C_DecryptInit");
   rv = pFuncList->C_DecryptInit(session, &aesMech, hKey);
   handle_error(rv, "C_DecryptInit");

   showCryptokiName("C_Decrypt");
   rv = pFuncList->C_Decrypt(session, pCipher, ul_encLen, pDePlain, &ul_decLen);
   handle_error(rv, "C_Decrypt");

   printf("deplain: ");
   for(int i = 0; i < ul_decLen; i++)
   {
      printf("%02x ", pDePlain[i]);
   }
   printf("\n");

   /* Wrap key*/
   showCryptokiName("C_WrapKey");
   CK_MECHANISM wrapKeyMech = {CKM_AES_KEY_WRAP, NULL_PTR, 0};
   CK_BYTE wrappedKey[32] = {0};
   CK_ULONG ulWrappedKeyLen = sizeof(wrappedKey);
   rv = pFuncList->C_WrapKey(session, &wrapKeyMech, hDigestKey, hKey, wrappedKey, &ulWrappedKeyLen);
   handle_error(rv, "C_WrapKey");
   printf("warpped key: ");
   for(int i = 0; i < ulWrappedKeyLen; i++)
   {
      printf("%02x ", wrappedKey[i]);
   }
   printf("\n");

   showCryptokiName("C_Logout");
   rv = pFuncList->C_Logout(session);
   handle_error(rv, "C_Logout");

   showCryptokiName("C_CloseSession");
   rv = pFuncList->C_CloseSession(session);
   handle_error(rv, "C_CloseSession");
   

   free(pSlotList);
   dlclose(pDlHandle);

   return 0;
}

