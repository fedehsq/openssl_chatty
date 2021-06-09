#ifndef SymmetricEncription_h
#define SymmetricEncription_h

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "../message/Message.h"

// General:
//    - cipher: EVP_CIPHER *cipher = EVP_aes_128_cbc();
//    - Block size: int block_size = EVP_CIPHER_block_size(cipher);
//    - Iv len (size): iv_len = EVP_CIPHER_iv_length(cipher)

/*
AEAD:
Authenticated encryption with associated data (AEAD).
An AEAD can be represented as a function which takes three inputs:
    - a key, 
    - a plaintext, 
    - an additional authenticated data (AAD); 
and it returns two outputs: 
    - a ciphertext, 
    - a tag. 
The ciphertext is the encrypted plaintext. 
The tag acts as a MAC and assures the authenticity of the plaintext
together with the AAD.
The same key is used for encrypting and authenticating.

The presence of the AAD means that the authenticity mechanism covers 
a superset of what is covered by the encryption mechanism. 
This is useful in many common situations, for example when a message
must be auth-encrypted in such a way that some of the header is left
in the clear. Such an in-the-clear header may contain information 
needed for decrypting, for example the IV, 
or the key index if more keys are used. 
Common authenticated encryption modes implemented in OpenSSL are:
    - GCM (Galois-Counter Mode), 
    - CCM (Counter and CBC-MAC Mode), 
    - OCB (Offset CodeBook mode)

-----------------------------------------------------------------------
| clear_header (IV) | encrypted_header (IV) | encrypted_payload (msg) |
-----------------------------------------------------------------------
|       AAD         |                     ENCRYPTION                  |
-----------------------------------------------------------------------
|                           AUTHENTICATION                            |
-----------------------------------------------------------------------

HOT TO IMPLEMENT:
Encryption: We must first initialize the context, 
giving the various parameters (cipher, mode, key, iv). 
Then we cycle giving a series of AAD fragments (context update).
After this, we do the same with the plaintext fragments 
(context update again).
The encryptor gives back a series of ciphertext fragments. 
Finally, we finalize the context, retrieving the last 
ciphertext fragment, and we retrieve the computed tag.

Decryption: the context must be informed about the received tag before
executing the context finalization. 
Such a context finalization returns an error in case the received tag 
does not match with the computed one.
*/


class SymmetricEncryption {
    // These fields are deafult private
    
    // Encryption: calculated by encryptUpdate 
    // Decryption: needed by decryptUpdate
    Message<unsigned char> *ciphertext = NULL;
    
    // To encrypt
    Message<unsigned char> *plaintext = NULL;

    // Decryption: calculated by decryptUpdate
    Message<unsigned char> *decrypted = NULL;

    // Encryption with AEAD: tag for authentication
    Message<unsigned char> *tag = NULL;

    // Context for encryption / decryption
    EVP_CIPHER_CTX *context = NULL;

    // Kind of cipher
    EVP_CIPHER const *cipher = NULL;

    // Calculated by cipher mode (it depends from cipher)
    int block_size;

    // Ephimeral variables
    unsigned char *pt = NULL;
    unsigned char *ct = NULL;
    unsigned char *sk = NULL;
    unsigned char *iiv = NULL;
    unsigned char *aead = NULL;
    unsigned char *decr = NULL;
    unsigned char *t_tag = NULL;
    unsigned char *recv_tag = NULL;

    public:
        SymmetricEncryption(const EVP_CIPHER *cipher);

        // Destructor
        ~SymmetricEncryption();

        // Encrypt plaintext
        int encrypt(
            Message<unsigned char> *plaintext, 
            Message<unsigned char> *symmetric_key, 
            Message<unsigned char> *iv);

        // Decrypt ciphertext
        int decrypt(
            Message<unsigned char> *cipheretxt,
            Message<unsigned char> *symmetric_key, 
            Message<unsigned char> *iv);

        // Encrypt plaintext using header
        int AEADencrypt(
            Message<unsigned char> *plaintext, 
            Message<unsigned char> *symmetric_key, 
            Message<unsigned char> *iv,
            Message<unsigned char> *aad);

        // Decrypt ciphertext using header and aad
        int AEADdecrypt(
            Message<unsigned char> *cipheretxt,
            Message<unsigned char> *symmetric_key, 
            Message<unsigned char> *iv,
            Message<unsigned char> *aad,
            Message<unsigned char> *tag);
        
        // Return encrypted plaintext (ciphertext)
        Message<unsigned char> *getCiphertext();
        
        // Return decrypted ciphertext (plaintext)
        Message<unsigned char> *getDecrypted();
        
        // Return tag
        Message<unsigned char> *getTag();

    private:

        // Initialize and free a buffer 
        void destroy(unsigned char **buf, int len);

        // Initialize and free a Message structure
        void destroy(Message<unsigned char> **message);
        
        // Clean all class structure 
        void clean();
};

#endif