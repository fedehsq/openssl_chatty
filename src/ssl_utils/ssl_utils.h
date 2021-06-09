#ifndef SSL_utils_h
#define SSL_utils_h

#include <iostream>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "../message/Message.cc"

#define MAX_SIZE 10000
#define CHUNK 256
#define SIGN_SIZE 256

// Generate and return random bytes as Message* object.
Message<unsigned char> *generate_random_bytes(int len);

// Print bytes of Message* object.
template <typename T>
void print_bytes(Message<T> *bytes);

// ----- KEYS UTILITIES -----

// Print on stdout the keys.
void print_key(EVP_PKEY *key);

// Read and return private key from file.
EVP_PKEY *read_private_key_from_file(const char *path);

// Read and return public key from file.
EVP_PKEY *read_public_key_from_file(const char *path);

// Extract and return the public key from private key.
EVP_PKEY *get_public_key(EVP_PKEY *prv);

// Extract from EVP_PKEY* the public key and return it as string.
char *get_public_key_to_string(EVP_PKEY *public_key);

// Extract from EVP_PKEY* the public key and return it as Message* object.
Message<char>* get_public_key_to_message(EVP_PKEY *pubk);

// Extract from Message* object the public key and return it as EVP_PKEY* structure.
template <typename T>
EVP_PKEY* get_public_key_from_message(Message<T> *key);

// Generate and return RSA keys (private and public) in a RSA* structure.
RSA *generate_RSA_keys();

// Extract and return the RSA private key from RSA* struct.
EVP_PKEY *get_private_key(RSA *rsa);

// ----- CERTIFICATE UTILITIES ------

// Read and return a certificate from PEM file.
X509 *read_certificate_from_file(const char* certificate_path);

// The i2d_X509() and d2i_X509() functions respectively serialize and deserialize a 
// certificate in DER format, which is a binary format. This is useful for example for 
// sending/receiving certificates over sockets. «i2d» and «d2i» stand respectively for 
// «internal-to-DER» and «DER-to-internal».
// Convert and return X509* certificate to Message* object.
Message<unsigned char> *certificate_to_bytes(X509 *certificate);

// Convert and return bytes certificate to X509 *certificate.
X509 *bytes_to_certificate(unsigned char *cert, int cert_len);

#endif