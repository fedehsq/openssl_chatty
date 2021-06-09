#include "AsymmetricEncryption.h"


// Check for errors
#define A_ERR(res, ret) { \
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

// Constructor
AsymmetricEncryption::AsymmetricEncryption(
    const EVP_CIPHER* cipher) {
        // Chosen cipher for encryption
        this -> cipher = cipher;
        // Block size depending of cipher
        block_size = EVP_CIPHER_block_size(cipher);
    }

// Destructor
AsymmetricEncryption::~AsymmetricEncryption() {
    clean();
}

// Encrypt a message
int AsymmetricEncryption::encrypt(Message<unsigned char> *plaintext, 
    const char* public_key_path) {
    // Clean all previously encryption / decryption
    clean();
    // Read public key from file and initiliaze it
    readPublicKey(public_key_path);

    // Get plaintext buffer text
    unsigned char *pt;
    A_ERR(pt = plaintext -> getMessage(), 0);
    
    // Allocates the cipher context 
    A_ERR(context = EVP_CIPHER_CTX_new(), 0);

    // Temporary variables
    A_ERR(ct = (unsigned char *)calloc(plaintext -> getLen() + block_size + 1, sizeof(unsigned char)), 0);
    A_ERR(ek = (unsigned char *)calloc(EVP_PKEY_size(key) + 1, sizeof(unsigned char)), 0);
    A_ERR(ivv = (unsigned char *)calloc(EVP_CIPHER_iv_length(cipher) + 1, sizeof(unsigned char)), 0);
    int ekl = EVP_PKEY_size(key);
    int ct_len;

    // Generate symmetric key and iv using public key 
    A_ERR(EVP_SealInit(context, cipher, 
    &ek, &ekl, ivv, &key, 1), 0);
    
    // Real unsigned char* written from seal update 
    int written;

    // encrypt plaintext 
    A_ERR(EVP_SealUpdate(context, 
        ct, &written, pt, plaintext -> getLen()), 0);

    ct_len = written;

    // Finalize encryption, add padding 
    A_ERR(EVP_SealFinal(context,
        &ct[written], &written), 0);
    
    // Update len 
    ct_len += written;

    // Allocate space for iv that will be generate by SealInit
    A_ERR(iv = new Message<unsigned char>(ivv, EVP_CIPHER_iv_length(cipher)), 0);
    // Allocate space for ek that will be generate by SealInit
    A_ERR(encrypted_symmetric_key = new Message<unsigned char>(ek, ekl), 0);
    // Allocate space for ct that will be generate by SealUpdate
    A_ERR(ciphertext = new Message<unsigned char>(ct, ct_len), 0);

    destroy(&pt, plaintext -> getLen());
    destroy(&ct, ct_len);
    destroy(&ivv, EVP_CIPHER_iv_length(cipher));
    destroy(&ek, ekl);

    // Clean public key 
    EVP_PKEY_free(key);
    key = NULL;
    fclose(fp_key);
    fp_key = NULL;

    // Clean cipher context 
    EVP_CIPHER_CTX_free(context);
    context = NULL;
    return 1;
}

// Encrypt a message passing key from program
int AsymmetricEncryption::encrypt(Message<unsigned char> *plaintext, EVP_PKEY *key) {
    // Clean all previously encryption / decryption
    clean();

    // Get plaintext buffer text
    unsigned char *pt;
    A_ERR(pt = plaintext -> getMessage(), 0);

    // Allocates the cipher context 
    A_ERR(context = EVP_CIPHER_CTX_new(), 0);

    // Temporary variables
    A_ERR(ct = (unsigned char *)calloc(plaintext -> getLen() + block_size + 1, sizeof(unsigned char)), 0);
    A_ERR(ek = (unsigned char *)calloc(EVP_PKEY_size(key) + 1, sizeof(unsigned char)), 0);
    A_ERR(ivv = (unsigned char *)calloc(EVP_CIPHER_iv_length(cipher) + 1, sizeof(unsigned char)), 0);
    int ekl = EVP_PKEY_size(key);
    int ct_len;

    // Generate symmetric key and iv using public key 
    A_ERR(EVP_SealInit(context, cipher, 
    &ek, &ekl, ivv, &key, 1), 0);
    
    // Real unsigned char* written from seal update 
    int written;

    // encrypt plaintext 
    A_ERR(EVP_SealUpdate(context, ct, &written, pt, plaintext -> getLen()), 0);

    ct_len = written;

    // Finalize encryption, add padding 
    A_ERR(EVP_SealFinal(context,
        &ct[written], &written), 0);
    
    // Update len 
    ct_len += written;

    // Allocate space for iv that will be generate by SealInit
    A_ERR(iv = new Message<unsigned char>(ivv, EVP_CIPHER_iv_length(cipher)), 0);
    // Allocate space for ek that will be generate by SealInit
    A_ERR(encrypted_symmetric_key = new Message<unsigned char>(ek, ekl), 0);
    // Allocate space for ct that will be generate by SealUpdate
    A_ERR(ciphertext = new Message<unsigned char>(ct, ct_len), 0);

    destroy(&pt, plaintext -> getLen());
    destroy(&ct, ct_len);
    destroy(&ivv, EVP_CIPHER_iv_length(cipher));
    destroy(&ek, ekl);

    // Clean cipher context 
    EVP_CIPHER_CTX_free(context);
    context = NULL;
    return 1;
}


int AsymmetricEncryption::decrypt(
    Message<unsigned char> *ciphertext,
    Message<unsigned char> *encrypted_symmetric_key, 
    Message<unsigned char> *iv,
    const char *private_key_path) {
    
    clean();
    // Temp decrypted
    A_ERR(d = (unsigned char *)calloc(ciphertext -> getLen(), sizeof(unsigned char)), 0);
    A_ERR(ct = ciphertext -> getMessage(), 0);
    A_ERR(ek = encrypted_symmetric_key -> getMessage(), 0);
    A_ERR(ivv = iv -> getMessage(), 0);

    // Read private key 
    readPrivateKey(private_key_path);
    // Allocates the cipher context
    A_ERR(context = EVP_CIPHER_CTX_new(), 0);

    // Pass ek symmetric key and iv, decrypt ek using private key
    A_ERR(EVP_OpenInit(context, cipher, 
    ek, encrypted_symmetric_key -> getLen(), ivv, key), 0);
    
    // Real unsigned char written from Open update 
    int written;

    // Decrypt ciphertext
    A_ERR(EVP_OpenUpdate(context, d, &written, 
    ct, ciphertext -> getLen()), 0);
    int d_len = written;

    // Finalize encryption, add padding
    A_ERR(EVP_OpenFinal(context, 
    &d[written], &written), 0);
    d_len += written;
    
    // Create plaintext
    decrypted = new Message<unsigned char>(d, d_len);

    // Destroy temporary pt
    destroy(&d, d_len);
    destroy(&ek, encrypted_symmetric_key -> getLen());
    destroy(&ct, ciphertext -> getLen());
    destroy(&ivv, iv -> getLen());

    // Clean private key 
    EVP_PKEY_free(key);
    key = NULL;
    fclose(fp_key);
    fp_key = NULL;

    // Clean cipher context 
    EVP_CIPHER_CTX_free(context);
    context = NULL;
    return 1;
}


int AsymmetricEncryption::decrypt(
    Message<unsigned char> *ciphertext,
    Message<unsigned char> *encrypted_symmetric_key, 
    Message<unsigned char> *iv,
    EVP_PKEY *prv_key) {
    
    clean();
    // Temp decrypted
    A_ERR(d = (unsigned char *)calloc(ciphertext -> getLen(), sizeof(unsigned char)), 0);
    A_ERR(ct = ciphertext -> getMessage(), 0);
    A_ERR(ek = encrypted_symmetric_key -> getMessage(), 0);
    A_ERR(ivv = iv -> getMessage(), 0);

    // Allocates the cipher context
    A_ERR(context = EVP_CIPHER_CTX_new(), 0);

    // Pass ek symmetric key and iv, decrypt ek using private key
    A_ERR(EVP_OpenInit(context, cipher, 
    ek, encrypted_symmetric_key -> getLen(), ivv, prv_key), 0);
    
    // Real unsigned char written from Open update 
    int written;

    // Decrypt ciphertext
    A_ERR(EVP_OpenUpdate(context, d, &written, 
    ct, ciphertext -> getLen()), 0);
    int d_len = written;

    // Finalize encryption, add padding
    A_ERR(EVP_OpenFinal(context, 
    &d[written], &written), 0);
    d_len += written;
    
    // Create plaintext
    decrypted = new Message<unsigned char>(d, d_len);

    // Destroy temporary pt
    destroy(&d, d_len);
    destroy(&ek, encrypted_symmetric_key -> getLen());
    destroy(&ct, ciphertext -> getLen());
    destroy(&ivv, iv -> getLen()); 

    // Clean cipher context 
    EVP_CIPHER_CTX_free(context);
    context = NULL;
    return 1;
}

// Read public key from file 
int AsymmetricEncryption::readPublicKey(const char *key_path) {
    A_ERR(fp_key = fopen(key_path, "r"), 0);
    A_ERR(key = PEM_read_PUBKEY(fp_key, NULL, NULL, NULL), 0);
    return 1;
}

// Read private key from file 
int AsymmetricEncryption::readPrivateKey(const char *key_path) {
    A_ERR(fp_key = fopen(key_path, "r"), 0);
    A_ERR(key = PEM_read_PrivateKey(fp_key, NULL, NULL, NULL), 0);
    return 1;
}

// Return decrypted ciphertext (plaintext) => DEEP COPY
Message<unsigned char>* AsymmetricEncryption::getDecrypted() {
    return decrypted -> clone();
}

// Return ciphertext => DEEP COPY
Message<unsigned char>* AsymmetricEncryption::getCiphertext() {
    return ciphertext -> clone();
}

// Return iv => DEEP COPY
Message<unsigned char>* AsymmetricEncryption::getIv() {
    return iv -> clone();
}

// Return ek => DEEP COPY
Message<unsigned char>* AsymmetricEncryption::getEncryptedSymmetricKey() {
    return encrypted_symmetric_key -> clone();
}

// Print some bytes
void AsymmetricEncryption::printBytes(Message<unsigned char> *bytes) {
    unsigned char *b = bytes -> getMessage();
    BIO_dump_fp(stdout, (char *)b, bytes -> getLen());
    destroy(&b, bytes -> getLen());
}

// Initialize and free a buffer 
void AsymmetricEncryption::destroy(unsigned char **buf, int len) {
    if (*buf) {
        memset(*buf, 0, len);
        free(*buf);
        *buf = NULL;
    }
}

// Initialize and free a Message structure 
void AsymmetricEncryption::destroy(Message<unsigned char> **message) {
    if (*message) {
        delete *message;
        *message = NULL;
    }
}

// clean all class structure 
void AsymmetricEncryption::clean() {
    destroy(&ciphertext);
    destroy(&encrypted_symmetric_key);
    destroy(&iv);
    destroy(&decrypted);
    if (ek) {
        free(ek);
        ek = NULL;
    }
    if (ct) {
        free(ct);
        ct = NULL;
    }
    if (ivv) {
        free(ivv);
        ivv = NULL;
    }
    if (d) {
        free(d);
        d = NULL;
    }
    if (key) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    if (fp_key) {
        fclose(fp_key);
        key = NULL;
    }
    if (context) {
        EVP_CIPHER_CTX_free(context);
        context = NULL;
    }
}