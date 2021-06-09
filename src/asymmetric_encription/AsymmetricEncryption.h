#ifndef AsymmetricEncryption_h
#define AsymmetricEncryption_h

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "../message/Message.h"

//
// NOTES:
// Generate a RSA private key protected by a password:
//	- openssl genrsa -aes128 -f4 -out bob_private_key.pem
// Extract public key:
//    - openssl rsa -in bob_private_key.pem -outform PEM -pubout -out bob_public_key.pem

// Generare an EC private key:
//  - openssl ecparam -name secp256k1 -genkey -noout -out priatev_key.pem
// Extract ec public key
//  - openssl ec -pubout -in private_key.pem -out public_key.pem


// General:
//    - cipher: EVP_CIPHER *cipher = EVP_aes_128_cbc();
//    - Block size: int block_size = EVP_CIPHER_block_size(cipher);
//    - Iv len (size): iv_len = EVP_CIPHER_iv_length(cipher)
  
// When I want to encrypt with Digital Envelope tecnique:
//    - Public key: EVP_PKEY *key = PEM_read_PUBKEY(fp_key, NULL, NULL, NULL);
//    - Size of Encrypted symmetric key: int len = EVP_PKEY_size(key)

class AsymmetricEncryption {
    // These fields are deafult private

    // Encryption: calculated by sealInit 
    // Decryption: needed by openInit
    Message<unsigned char> *encrypted_symmetric_key = NULL;
    unsigned char *ek = NULL;

    // Encryption: calculated by sealInit 
    // Decryption: needed by openInit
    Message<unsigned char> *iv = NULL;
    unsigned char *ivv = NULL;
    
    // Encryption: calculated by sealUpdate 
    // Decryption: needed by openUpdate
    Message<unsigned char> *ciphertext = NULL;
    unsigned char *ct = NULL;

    // Decryption: calculated by openUpdate
    Message<unsigned char> *decrypted = NULL;
    unsigned char *d = NULL;

    // Context for encryption / decryption
    EVP_CIPHER_CTX *context = NULL;

    // Encryption: public key     
    // Decryption: private key
    FILE *fp_key = NULL;
    EVP_PKEY *key = NULL;

    // Kind of cipher
    EVP_CIPHER const *cipher = NULL;

    // Calculated by cipher mode (it depends from cipher)
    int block_size;
    
    public:
        AsymmetricEncryption(const EVP_CIPHER *cipher);

        // Destructor
        ~AsymmetricEncryption();

        // Encrypt plaintext from file key
        int encrypt(Message<unsigned char> *plaintext, const char *key_path);

        // Encrypt plaintext with in memory key
        int encrypt(Message<unsigned char> *plaintext, EVP_PKEY *public_key);

        // Decrypt ciphertext from on file private key
        int decrypt(
            Message<unsigned char> *cipheretxt,
            Message<unsigned char> *encrypted_symmetric_key, 
            Message<unsigned char> *iv,
            const char *key_path);
        
        // Decrypt ciphertext in memory key
        int decrypt(
            Message<unsigned char> *cipheretxt,
            Message<unsigned char> *encrypted_symmetric_key, 
            Message<unsigned char> *iv,
            EVP_PKEY *prv_key);
        
        // Return encrypted plaintext (ciphertext)
        Message<unsigned char> *getCiphertext();
        
        // Return decrypted ciphertext (plaintext)
        Message<unsigned char> *getDecrypted();
        
        // Return iv
        Message<unsigned char> *getIv();
        
        // Return ecrypted symmetric key
        Message<unsigned char> *getEncryptedSymmetricKey();

        // Print on stdout the bytes of ct, ek, iv
        void printBytes(Message<unsigned char> *bytes);

    private:    
        // Encryption: read public from path        
        int readPublicKey(const char *public_key_path);

        // Decryption: read private key from path 
        int readPrivateKey(const char *private_key_path);

        // Initialize and free a buffer 
        void destroy(unsigned char **buf, int len);

        // Initialize and free a Message structure
        void destroy(Message<unsigned char> **message);
        
        // Clean all class structure 
        void clean();
};


#endif