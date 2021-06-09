#ifndef DigitalSignature_h
#define DigitalSignature_h

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "../message/Message.h"

/*
The digital signature technique authenticates a message in such a way 
that everyone can verify its authenticity. 
Usually, we do not authenticate the message itself, but the digest 
of the message, relying on the collision-resistance property 
of the hash algorithm. 
The digest is authenticated by signing it with the private key of the 
authenticating entity.
Like encryption, there are symmetric and asymmetric
algorithms for protecting integrity. 
- The symmetric version is called a message authentication code (MAC). 
- The asymmetric version is called a digital signature.
In short:
- Digital Signature = Hash of the message is encrypted with the private key of the sender.
- HMAC = Hash of the message is encrypted with the symmetric key.

NB: It is not necessary that I manually hash, SignInit/Update/Final
do the tricks.
*/

class DigitalSignature {
    // These fields are deafult private

    // Generated sign
    Message<unsigned char> *signature = NULL;

    // Context for sign creation / verificaion
    EVP_MD_CTX *context = NULL;

    // Sign: private key     
    // Verify: public key
    FILE *fp_key = NULL;
    EVP_PKEY *key = NULL;

    // Temporary variables
    unsigned char *sgn = NULL;
    unsigned char *msg = NULL;

    // Kind of cipher
    EVP_CIPHER const *cipher = NULL;
    
    public:
        DigitalSignature();

        // Destructor
        ~DigitalSignature();

        // Create sign
        int sign(Message<unsigned char> *message, const char *key_path);

        // Verify sign reading public key from file
        int verify(
            Message<unsigned char> *message,
            Message<unsigned char> *signature,
            const char *public_key_path);

        // Verify sign reading public key from program
        int verify(
            Message<unsigned char> *message,
            Message<unsigned char> *signature,
            EVP_PKEY *public_key);
        
        // Return generated sign
        Message<unsigned char> *getSign();

        // Print on stdout the bytes
        void printBytes(Message<unsigned char> *bytes);

    private:    
        // Verify: read public from path        
        int readPublicKey(const char *public_key_path);

        // Sign: read private key from path 
        int readPrivateKey(const char *private_key_path);

        // Initialize and free a buffer 
        void destroy(void *buf, size_t len);

        // Initialize and free a Message structure
        void destroy(Message<unsigned char> **message);
        
        // Clean all class structure 
        void clean();
};

#endif