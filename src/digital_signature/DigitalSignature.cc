#include "DigitalSignature.h"

// Check for errors
#define D_ERR(res, ret) { \
    if (!(res)) { \
        std::cerr << "In " << __FILE__ << " error on line " << __LINE__; \
        if (errno) { \
            std::cerr << ": " << strerror(errno); \
        } \
        puts(""); \
        ERR_print_errors_fp(stderr); \
        clean(); \
        errno = 0; \
        return ret; \
    } \
}

// Check for errors
#define DN_ERR(res, ret) { \
    if ((res) <= 0) { \
        std::cerr << "In " << __FILE__ << " error on line " << __LINE__; \
        if (errno) { \
            std::cerr << ": " << strerror(errno); \
        } \
        puts(""); \
        ERR_print_errors_fp(stderr); \
        clean(); \
        errno = 0; \
        return ret; \
    } \
}

// Constructor
DigitalSignature::DigitalSignature() {}

// Destructor
DigitalSignature::~DigitalSignature() {
    clean();
}

// Generate signature for a message
int DigitalSignature::sign(Message<unsigned char> *message,
        const char* private_key_path) {
    // Clean all previously signatures / verifi
    clean();
    // Read private key from file and initiliaze it
    D_ERR(readPrivateKey(private_key_path), 0);

    // Allocates the cipher context 
    D_ERR(context = EVP_MD_CTX_new(), 0);

    // Temporary variables
    D_ERR(sgn = (unsigned char *)calloc(EVP_PKEY_size(key) 
        + 1, sizeof(unsigned char)), 0);
    D_ERR(msg =  message -> getMessage(), 0);
    unsigned int sign_len;

    // Initlizing signature
    D_ERR(EVP_SignInit(context, EVP_sha256()), 0);

    // Calculate sign of message 
    D_ERR(EVP_SignUpdate(context, msg, message -> getLen()), 0);

    // Generate sign 
    DN_ERR(EVP_SignFinal(context, sgn, &sign_len, key), 0);

    // Create sign
    D_ERR(signature = new Message<unsigned char>(sgn, sign_len), 0);

    //destroy(msg, message -> getLen());
    //destroy(sgn, sign_len);

    // Clean private key 
    EVP_PKEY_free(key);
    key = NULL;
    fclose(fp_key);
    fp_key = NULL;

    // Clean cipher context 
    EVP_MD_CTX_free(context);
    context = NULL;
    return 1;
}

// Verifiy a message signature
int DigitalSignature::verify(
        Message<unsigned char> *message,
        Message<unsigned char> *signature,
        const char* public_key_path) {
    // Clean all previously signatures / verify
    clean();
    // Read public key from file and initiliaze it
    D_ERR(readPublicKey(public_key_path), 0);

    // Allocates the cipher context 
    D_ERR(context = EVP_MD_CTX_new(), 0);

    // Temporary variables
    D_ERR(sgn = signature -> getMessage(), 0);
    D_ERR(msg =  message -> getMessage(), 0);

    // Initlizing signature
    D_ERR(EVP_VerifyInit(context, EVP_sha256()), 0);

    // Calculate sign of message 
    D_ERR(EVP_VerifyUpdate(context, msg, message -> getLen()), 0);

    // Compare the generated signature with the passed one 
    DN_ERR(EVP_VerifyFinal(context, sgn, signature -> getLen(), key), 0);

    //destroy(msg, message -> getLen());
    //destroy(sgn, signature -> getLen());

    // Clean private key 
    EVP_PKEY_free(key);
    key = NULL;
    fclose(fp_key);
    fp_key = NULL;

    // Clean cipher context 
    EVP_MD_CTX_free(context);
    context = NULL;
    return 1;
}


// Verifiy a message signature reading public key from program
int DigitalSignature::verify(
        Message<unsigned char> *message,
        Message<unsigned char> *signature,
        EVP_PKEY *public_key) {
    // Clean all previously signatures / verify
    clean();

    // Allocates the cipher context 
    D_ERR(context = EVP_MD_CTX_new(), 0);

    D_ERR(sgn = signature -> getMessage(), 0);
    D_ERR(msg = message -> getMessage(), 0);

    // Initlizing signature
    D_ERR(EVP_VerifyInit(context, EVP_sha256()), 0);

    // Calculate sign of message 
    D_ERR(EVP_VerifyUpdate(context, msg, message -> getLen()), 0);

    // Compare the generated signature with the passed one 
    DN_ERR(EVP_VerifyFinal(context, sgn, signature -> getLen(), public_key), 0);

    //destroy(msg, message -> getLen());
    //destroy(sgn, signature -> getLen());

    /* Clean private key 
    EVP_PKEY_free(key);
    key = NULL;
    fclose(fp_key);
    fp_key = NULL;
    */

    // Clean cipher context 
    EVP_MD_CTX_free(context);
    context = NULL;
    return 1;
}


// Read public key from file 
int DigitalSignature::readPublicKey(const char *key_path) {
    D_ERR(fp_key = fopen(key_path, "r"), 0);
    D_ERR(key = PEM_read_PUBKEY(fp_key, NULL, NULL, NULL), 0);
    return 1;
}

// Read private key from file 
int DigitalSignature::readPrivateKey(const char *key_path) {
    // 3 possibility to insert password
    for (int i = 3; i > 0; i--) {
        D_ERR(fp_key = fopen(key_path, "r"), 0);
        if (!(key = PEM_read_PrivateKey(fp_key, NULL, NULL, NULL))) {
            cout << "Wrong password. Remaining times: " << i - 1 << endl;
            fclose(fp_key);
            fp_key = NULL;
        } else {
            return 1;
        }
    }
    return 0;
}

// Return decrypted ciphertext (plaintext) => DEEP COPY
Message<unsigned char>* DigitalSignature::getSign() {
    return signature -> clone();
}

// Print some bytes
void DigitalSignature::printBytes(Message<unsigned char> *bytes) {
    unsigned char *b = bytes -> getMessage();
    BIO_dump_fp(stdout, (char *)b, bytes -> getLen());
    destroy(b, bytes -> getLen());
}

// Initialize and free a buffer 
void DigitalSignature::destroy(void *buf, size_t len) {
    if (buf) {
        memset(buf, 0, len);
        free(buf);
        buf = NULL;
    }
}

// Initialize and free a Message structure 
void DigitalSignature::destroy(Message<unsigned char> **message) {
    if (*message) {
        delete *message;
        *message = NULL;
    }
}

// clean all class structure 
void DigitalSignature::clean() {
    destroy(&signature);
    if (msg) {
        free(msg);
        msg = NULL;
    }
    if (sgn) {
        free(sgn);
        sgn = NULL;
    }
    if (key) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    if (fp_key) {
        fclose(fp_key);
        fp_key = NULL;
    }
    if (context) {
        EVP_MD_CTX_free(context);
        context = NULL;
    }
}