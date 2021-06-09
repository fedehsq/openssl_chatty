#include "ssl_utils.h"

// Check for errors
#define ERR(res, line_togo) { \
    if (!(res)) { \
        std::cerr << "In " << __FILE__ << " error on " << __LINE__; \
        if (errno) { \
            if (errno == EINTR) { \
                std::cerr << ": SIGINT received. Server is shutting down..."; \
            } else { \
                std::cerr << ": " << strerror(errno); \
            } \
        } \
        puts(""); \
        ERR_print_errors_fp(stderr); \
        goto line_togo; \
    } \
} \

#define N_ERR(res, line_togo) { \
    if (res == -1) { \
        std::cerr << "In " << __FILE__ << " error on " << __LINE__; \
        if (errno) { \
            if (errno == EINTR) { \
                std::cerr << ": SIGINT received. Server is shutting down..."; \
            } else { \
                std::cerr << ": " << strerror(errno); \
            } \
        } \
        puts(""); \
        ERR_print_errors_fp(stderr); \
        goto line_togo; \
    } \
} \

// Generate and return random bytes as Message* object.
Message<unsigned char> *generate_random_bytes(int len) {
    unsigned char *bytes = NULL;
    Message<unsigned char> *random = NULL;
    ERR(RAND_poll(), destroy);  
    ERR(bytes = (unsigned char *)calloc(len + 1, 
        sizeof(unsigned char)), destroy);
    ERR(RAND_bytes(bytes, len), destroy);
    ERR(random = new Message<unsigned char>(bytes, len), destroy);
    free(bytes);
    return random;
destroy:
    if (bytes) {
        free(bytes);
    }
    if (random) {
        free(random);
    }
    return NULL;
}

// Print bytes of Message* object.
template <typename T>
void print_bytes(Message<T> *bytes) {
    T* b = bytes -> getMessage();
    BIO_dump_fp(stdout, (char *)b, bytes -> getLen());
    free(b);
}

// ----- KEYS UTILITIES -----

// Print on stdout the keys.
void print_key(EVP_PKEY *key) {
    BIO* fp = BIO_new_fp(stdout, BIO_NOCLOSE);
    EVP_PKEY_print_private(fp, key, 0, NULL);
    EVP_PKEY_print_public(fp, key, 0, NULL);
    BIO_free(fp);
}

// Read and return private key from file.
EVP_PKEY *read_private_key_from_file(const char *path) {
    FILE *fp_key = NULL;
    EVP_PKEY *key = NULL;
    ERR(fp_key = fopen(path, "r"), destroy);
    ERR(key = PEM_read_PrivateKey(fp_key, NULL, NULL, NULL), destroy);
destroy:
    if (fp_key) {
        fclose(fp_key);
    }
    return key;
}

// Read and return public key from file.
EVP_PKEY *read_public_key_from_file(const char *path) {
    FILE *fp_key = NULL;
    EVP_PKEY *key = NULL;
    ERR(fp_key = fopen(path, "r"), destroy);
    ERR(key = PEM_read_PUBKEY(fp_key, NULL, NULL, NULL), destroy);
destroy:
    if (fp_key) {
        fclose(fp_key);
    }
    return key;
}

// Extract and return the public key from private key.
EVP_PKEY *get_public_key(EVP_PKEY *prv) {
    BIO *bio = NULL;
    EVP_PKEY *pub = NULL;
    bio = BIO_new(BIO_s_mem());
    ERR(bio, destroy);
    ERR(PEM_write_bio_PUBKEY(bio, prv), destroy);
    ERR(PEM_read_bio_PUBKEY(bio, &pub, NULL, NULL), destroy);
    BIO_free_all(bio);
    return pub;
destroy:
    if (bio) {
        BIO_free_all(bio);
    }
    if (pub) {
        EVP_PKEY_free(pub);
    }
    return NULL;
}

// Extract from EVP_PKEY* the public key and return it as string.
char* get_public_key_to_string(EVP_PKEY *public_key) {
    BIO *bio = NULL;
    char *key = NULL;
    int key_len;
    ERR(bio = BIO_new(BIO_s_mem()), destroy);
    ERR(PEM_write_bio_PUBKEY(bio, public_key), destroy);
    key_len = BIO_pending(bio);
    ERR(key_len, destroy);
    ERR(key = (char *) calloc(key_len + 1, sizeof(char)), destroy);
    ERR(BIO_read(bio, key, key_len), destroy);
    BIO_free_all(bio);
    return key;
    // In case of any error, go here
destroy:
    if (key) {
        free(key);
    }
    if (bio) {
        BIO_free_all(bio);
    }
    return NULL;
}

// Extract from EVP_PKEY* the public key and return it as Message* object.
Message<char>* get_public_key_to_message(EVP_PKEY *pubk) {
    Message<char> *key = NULL;
    char *s_key = NULL;
    ERR(s_key = get_public_key_to_string(pubk), destroy);
    ERR(key = new Message<char>(s_key, strlen(s_key)), destroy);
    free(s_key);
    return key;
destroy:
    if (s_key) {
        free(s_key);
    }
    if (key) {
        delete key;
    }
    return NULL;
}

// Extract from Message* object the public key and return it as EVP_PKEY* structure.
template <typename T>
EVP_PKEY* get_public_key_from_message(Message<T> *key) {
    BIO *bio = NULL;
    unsigned char *pkey = NULL;
    EVP_PKEY *pub_key = NULL;
    ERR(pkey = key -> getMessage(), destroy);
    ERR(bio = BIO_new(BIO_s_mem()), destroy);
    ERR(BIO_write(bio, pkey, key -> getLen()), destroy);
    ERR(pub_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL), destroy);
    BIO_free_all(bio);
    memset(pkey, 0, key -> getLen());
    free(pkey);
    return pub_key;
    // In case of any error, go here
destroy:
    if (pkey) {
        memset(pkey, 0, key -> getLen());
        free(pkey);
    }
    if (bio) {
        BIO_free_all(bio);
    }
    return NULL;
}

// Generate and return RSA keys (private and public) in a RSA structure.
RSA *generate_RSA_keys() {
	RSA *rsa = NULL;
	BIGNUM* big_num = NULL;
	// Generate rsa key
	ERR(big_num = BN_new(), destroy);
	ERR(BN_set_word(big_num, RSA_F4), destroy);
	ERR(rsa = RSA_new(), destroy);
	ERR(RSA_generate_key_ex(rsa, 2048, big_num, NULL), destroy);
	BN_free(big_num);
    return rsa;
destroy:
    if (rsa) {
        RSA_free(rsa);
    }
    if (big_num) {
    	BN_free(big_num);
    }
    return NULL;
}

// Extract and return the RSA private key from RSA* struct.
EVP_PKEY *get_private_key(RSA *rsa) {
    BIO *bio = NULL;
    EVP_PKEY *prv = NULL;
    bio = BIO_new(BIO_s_mem());
    ERR(bio, destroy);
    ERR(PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL), destroy);
    ERR(PEM_read_bio_PrivateKey(bio, &prv, NULL, NULL), destroy);
    BIO_free_all(bio);
    return prv;
destroy:
    if (bio) {
        BIO_free_all(bio);
    }
    if (prv) {
        EVP_PKEY_free(prv);
    }
    return NULL;
}

// ----- CERTIFICATE UTILITIES ------

// Read and return a certificate from PEM file.
X509 *read_certificate_from_file(const char* certificate_path) {
    FILE *fp_certificate = NULL;
    X509 *certificate = NULL;  
    ERR(fp_certificate = fopen(certificate_path, "r"), destroy);
    ERR(certificate = PEM_read_X509(fp_certificate, NULL, NULL, NULL), destroy);
    fclose(fp_certificate);
    return certificate;
destroy:
    if (fp_certificate) {
        fclose(fp_certificate);
    }
    if (certificate) {
        X509_free(certificate);
    }
    return NULL;
}

// The i2d_X509() and d2i_X509() functions respectively serialize and deserialize a 
// certificate in DER format, which is a binary format. This is useful for example for 
// sending/receiving certificates over sockets. «i2d» and «d2i» stand respectively for 
// «internal-to-DER» and «DER-to-internal».
// Convert and return X509* certificate to Message* object.
Message<unsigned char> *certificate_to_bytes(X509 *certificate) {
    unsigned char *cert = NULL;
    Message<unsigned char> *bytes_cert = NULL;
    int cert_size;
    ERR(cert_size = i2d_X509(certificate, &cert), destroy);
    ERR(bytes_cert = new Message<unsigned char>(cert, cert_size), destroy);
    free(cert);
    return bytes_cert;
destroy:
    if (cert) {
        free(cert);
    }
    return NULL;
}

// Convert and return bytes certificate to X509 *certificate.
X509 *bytes_to_certificate(unsigned char *cert, int cert_len) {
    X509 *certificate = NULL;
    unsigned char *bytes_cert = cert;
    ERR(certificate = d2i_X509(NULL, 
        (const unsigned char **)&bytes_cert, cert_len), line);
line:
    return certificate;
}