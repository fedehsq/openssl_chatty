#ifndef DiffieHellman_h
#define DiffieHellman_h

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "../message/Message.h"

/* In OpenSSL, the EVP_PKEY structure represents a generic
quantity for asymmetric cryptography, for example private and public RSA keys. In this
example, it represents Diffie-Hellman parameters. The EVP_PKEY_CTX structure
represents a context of a generic public-key algorithm, in this case an algorithm to 
generate a pair of public/private keys. To generate a new key pair from the parameters, 
we have to use the EVP_PKEY_keygen_init() and the EVP_PKEY_keygen() functions. */

/*
The second step is to derive the shared secret from my private key and the peer’s
public key. We use the EVP_PKEY_derive_init(), EVP_PKEY_derive_set_peer() and 
EVP_PKEY_derive() functions to do that. Note that we call the EVP_PKEY_derive() 
function twice: the first time to get the maximum size of the shared secret to allocate 
enough space for it, and the second time to actually compute the shared secret.
*/

/* -----------------
Note that you should never use directly the shared secret (or a truncation of) as a key
------------------- */

/* 
DH parmas on command line:
openssl dhparam -C 2048
Creates dh params with public key of 2048 bits, 
and print the source code of a C function that 
allocates and return a DH structure containing such params:

static DH *get_dh2048(void) {
    ... generated code
}
int main() {
    EVP_PKEY *dh_params = EVP_PKEY_new()
    DH *tmp = get_dh2048();
    EVP_PKEY_set1_DH(dh_params, tmp);
    DH_free(tmp);
}
 */

/* ------------------ ECC DH ----------------
    read slides code (last slide)
*/

class DiffieHellman {
    // These fields are deafult private

    // High-level DH parameters
    EVP_PKEY *dh_params = NULL;

    // My private key (generated automatically by algo)
    EVP_PKEY *m_private_key = NULL;

    // My public key (generated automatically by algo)
    EVP_PKEY *m_public_key = NULL;

    // Public key o peer
    EVP_PKEY *peer_public_key = NULL;

    // Path of my public key
    const char *m_public_key_path;

    // fp to public key file
    FILE *fp_dh_public_key = NULL;

    // Key that will be used for encryption 
    Message<unsigned char> *session_key = NULL;

    // Key that will be used for encryption (temp)
    unsigned char *sk = NULL;
    
    // Called with dh parameters: key generation (private, public) 
    // Called with private key: secret derivation (session key)
    EVP_PKEY_CTX *context = NULL;

    // To store public key in internal memory (Not on file), to print
    // Useful params
    BIO *bio = NULL;
    
    public:
        DiffieHellman();

        // Destructor
        ~DiffieHellman();

        // Generate pair of keys (public and private) 
        // using the low-level DH parameters (dh_st *key)
        // => write public key to file and then read it from file 
        // and store to m_public_key
        int generateDHKeysToFile(const char *m_public_key_path, dh_st *key);

        // Generate pair of keys (public and private) 
        // using the low-level DH parameters (dh_st *key)
        int generateDHKeys(dh_st *key);

        // Generate pair of keys (public and private) 
        // using the Elliptic curves
        // => write public key to file and then read it from file 
        // and store to m_public_key
        int generateECDHKeysToFile(const char *m_public_key_path);

        // Generate pair of keys (public and private) 
        // using the Elliptic curves
        // => write them in internal memory
        int generateECDHKeys();

        // Given peer public key, compute the session key
        int computeSessionKey(const char *peer_public_key_path);

        // Return session key
        Message<unsigned char> *getSessionKey();

        // Return my private key
        EVP_PKEY *getPrivateKey();

        // Return my public key 
        EVP_PKEY *getPublicKey();

        // Return my private key as string
        char *getPrivateKeyToString();

        // Return my public key as string
        char *getPublicKeyToString();

        // Return my private key as Message
        Message<char> *getPrivateKeyToMessage();

        // Return my public key as Message
        Message<char> *getPublicKeyToMessage();

        // Print on stdout the bytes
        void printBytes(Message<unsigned char> *bytes);
        
        // Print private key, public key, random g and prime p
        void printDHparams();

    private:    

        // Initialize and free a buffer 
        void destroy(void *buf, size_t len);

        // Initialize and free a Message structure
        void destroy(Message<unsigned char> **message);
        
        // Clean all class structure 
        void clean();
};


#endif