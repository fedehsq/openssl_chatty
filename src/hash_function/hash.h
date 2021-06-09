#ifndef Hash_h
#define Hash_h
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include "../message/Message.cc"
/*
Within security applications, keyed hash algorithms (HMAC) are more useful than 
“pure” ones, because they are used for authenticating communications. The logical 
representation of a keyed hash algorithm is a function, taking a key and a variable-sized 
message as input, and returning a fixed-size digest as output.
The majority of cryptographic libraries uses incremental functions for keyed hash 
algorithms as well.

Note that HMAC algorithms do not impose constraints on the key length. However, 
keys of the same size of the digests are implicitly recommended by the HMAC RFC 
(rfc2104). This is because if the key is shorter than the digest, then it will be easier to 
guess the key, thus the security is weaker. Otherwise, a key longer than the digest is 
useless, since it makes more convenient to guess directly the digest.

Like encryption, there are symmetric and asymmetric
algorithms for protecting integrity. 
- The symmetric version is called a message authentication code (MAC). 
- The asymmetric version is called a digital signature.
In short:
- Digital Signature = Hash of the message is encrypted with the private key of the sender.
- HMAC = Hash of the message is encrypted with the symmetric key.

=> Use aes256 with sha 256 => their len is 32
*/

Message<unsigned char> *hash_with_key(unsigned char *key, int key_len, 
    unsigned char *message, int message_len) {
    // Context for hashing
    HMAC_CTX *context = HMAC_CTX_new();
    if (!context) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Digest 
    unsigned char *digest = (unsigned char *)calloc(EVP_MD_size(EVP_sha256()) + 1, 
        sizeof(unsigned char));
    if (!digest) {
        HMAC_CTX_free(context);
        std::cerr << strerror(errno) << "\n";
        return NULL;
    }
    // Digest len
    unsigned int digest_len;

    // Hashing
    if (!HMAC_Init_ex(context, key, key_len, EVP_sha256(), NULL)) {
        free(digest);
        ERR_print_errors_fp(stderr);
        HMAC_CTX_free(context);
        return NULL;
    }
    if (!HMAC_Update(context, message, message_len)) {
        free(digest);
        ERR_print_errors_fp(stderr);
        HMAC_CTX_free(context);
        return NULL;
    }
    if (!HMAC_Final(context, digest, &digest_len)) {
        free(digest);
        ERR_print_errors_fp(stderr);
        HMAC_CTX_free(context);
        return NULL;
    }
    HMAC_CTX_free(context);
    Message<unsigned char> *dgst = new Message<unsigned char>(digest, digest_len);
    if (!dgst) {
        free(digest);
        std::cerr << strerror(errno);
        return NULL;
    }
    free(digest);
    return dgst;
}


Message<unsigned char> *hash(unsigned char *message, int message_len) {
    // Context for hashing
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (!context) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Digest 
    unsigned char *digest = (unsigned char *)calloc(EVP_MD_size(EVP_sha256()) + 1, 
        sizeof(unsigned char));
    if (!digest) {
        std::cerr << strerror(errno) << "\n";
        EVP_MD_CTX_free(context);
        return NULL;
    }
    // Digest len
    unsigned int digest_len;

    // Hashing
    if (!EVP_DigestInit(context, EVP_sha256())) {
        free(digest);
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(context);
        return NULL;
    }
    if (!EVP_DigestUpdate(context, message, message_len)) {
        free(digest);
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(context);
        return NULL;
    }
    if (!EVP_DigestFinal(context, digest, &digest_len)) {
        free(digest);
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(context);
        return NULL;
    }
    EVP_MD_CTX_free(context);
    Message<unsigned char> *dgst = new Message<unsigned char>(digest, digest_len);
    if (!dgst) {
        free(digest);
        std::cerr << strerror(errno);
        return NULL;
    }
    free(digest);
    return dgst;
}
#endif