#include "SymmetricEncryption.h"

// Check for errors
#define S_ERR(res, ret) { \
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
SymmetricEncryption::SymmetricEncryption(
    const EVP_CIPHER* cipher) {
        // Chosen cipher for encryption
        this -> cipher = cipher;
        // Block size depending of cipher
        block_size = EVP_CIPHER_block_size(cipher);
    }

// Destructor
SymmetricEncryption::~SymmetricEncryption() {
    clean();
}

// Encrypt a message 
int SymmetricEncryption::encrypt(
        Message<unsigned char> *plaintext, 
        Message<unsigned char> *symmetric_key, 
        Message<unsigned char> *iv) {
    // Clean all previously encryption / decryption
    clean();

    // Get bytes of the plaintext
    S_ERR(pt = plaintext -> getMessage(), 0);

    // Allocate space for ct that will be generate by SealUpdate
    S_ERR(ct = (unsigned char *)calloc(
        plaintext -> getLen() + block_size + 1, sizeof(unsigned char)), 0);
    S_ERR(sk = symmetric_key -> getMessage(), 0);
    S_ERR(iiv = iv -> getMessage(), 0);
    int ct_len;
    
    // Real unsigned char* written from EncryptUpdate
    int written;

    // Allocates the cipher context 
    S_ERR(context = EVP_CIPHER_CTX_new(), 0);
    
    // Initialize encryption
    S_ERR(EVP_EncryptInit(context, cipher, 
        sk, iiv), 0);

    // Encrypt plaintext
    S_ERR(EVP_EncryptUpdate(context, ct, &written, 
        pt, plaintext -> getLen()), 0);

    // Update ct len
    ct_len = written;

    // Finalize encryption, add padding
    S_ERR(EVP_EncryptFinal(context, &ct[written], &written), 0);
    
    // Update len
    ct_len += written;

    S_ERR(ciphertext = new Message<unsigned char>(ct, ct_len), 0);

    // Free temp ct
    destroy(&ct, ct_len);
    destroy(&sk, symmetric_key -> getLen());
    destroy(&iiv, iv -> getLen());

    // Clean cipher context 
    EVP_CIPHER_CTX_free(context);
    context = NULL;
    return 1;
}

// Encrypts a message with header.
// Starting from aad, the alghoritm genereates a tag that is used
// for authentication.
// The tag acts as a MAC and assures the authenticity of the plaintext
// together with the aad.
int SymmetricEncryption::AEADencrypt(
        Message<unsigned char> *plaintext, 
        Message<unsigned char> *symmetric_key, 
        Message<unsigned char> *iv,
        Message<unsigned char> *aad) {
    // Clean all previously encryption / decryption
    clean();

        // Get bytes of the plaintext
    S_ERR(pt = plaintext -> getMessage(), 0);

    // Allocate space for ct that will be generate by SealUpdate
    S_ERR(ct = (unsigned char *)calloc(
        plaintext -> getLen() + block_size + 1, sizeof(unsigned char)), 0);
    S_ERR(sk = symmetric_key -> getMessage(), 0);
    S_ERR(iiv = iv -> getMessage(), 0);
    S_ERR(aead = aad -> getMessage(), 0);

    // Allocate space for tag that will be generate by auth-encr
    // It is always 16 byte
    unsigned char *t_tag = (unsigned char *)calloc(
        17, sizeof(unsigned char));
    S_ERR(t_tag, 0);

    // Length of ciphertext
    int ct_len;
    // Real unsigned char* written from EncryptUpdate/Final
    int written;
    
    // Allocates the cipher context 
    S_ERR(context = EVP_CIPHER_CTX_new(), 0);
    
    // Initialize encryption
    S_ERR(EVP_EncryptInit(context, cipher,  
        sk, iiv), 0);

    // Introduce aad that will generate tag 
    S_ERR(EVP_EncryptUpdate(context, NULL, &written, 
        aead, aad -> getLen()), 0);

    // Encrypt plaintext
    S_ERR(EVP_EncryptUpdate(context, ct, &written,
        pt, plaintext -> getLen()), 0);

    // Update ct len
    ct_len = written;

    // Finalize encryption, add padding
    S_ERR(EVP_EncryptFinal(context, &ct[written], &written), 0);
    
    // Update len
    ct_len += written;

    // Generate tag
    S_ERR(EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_GET_TAG, 16, t_tag), 0);

    S_ERR(ciphertext = new Message<unsigned char>(ct, ct_len), 0);
    S_ERR(tag = new Message<unsigned char>(t_tag, 16), 0);

    // Free temp ct/tag
    destroy(&ct, ct_len);
    destroy(&t_tag, 16);
    destroy(&sk, symmetric_key -> getLen());
    destroy(&iiv, iv -> getLen());
    destroy(&aead, aad -> getLen());

    // Clean cipher context 
    EVP_CIPHER_CTX_free(context);
    context = NULL;
    return 1;
}

// Decrypt ciphertext
int SymmetricEncryption::decrypt(
    Message<unsigned char> *ciphertext,
    Message<unsigned char> *symmetric_key, 
    Message<unsigned char> *iv) {
    
    // Clean prev decrypted
    // destroy(&&decrypted);
    clean();

    // Allocate decr size
    S_ERR(decr = (unsigned char*) calloc(
        ciphertext -> getLen() + 1, sizeof(unsigned char)), 0);
    S_ERR(ct = ciphertext -> getMessage(), 0);
    S_ERR(sk = symmetric_key -> getMessage(), 0);
    S_ERR(iiv = iv -> getMessage(), 0);
    
    // Decrypted's length
    int decr_len;

    // Allocates the cipher context
    S_ERR(context = EVP_CIPHER_CTX_new(), 0);

    // Initialize context for decryption
    S_ERR(EVP_DecryptInit(context, cipher,
        sk, iiv), 0);
    
    // real unsigned char written from Decrypt update 
    int written;

    // Decrypt plaintext
    S_ERR(EVP_DecryptUpdate(context, decr, &written, 
        ct, ciphertext -> getLen()), 0);

    // Updatre decrypted len
    decr_len = written;

    // Finalize encryption, add padding 
    S_ERR(EVP_DecryptFinal(context, &decr[written], &written), 0);

    // Update decrypted len
    decr_len += written;
    
    // Create decrypted with its len
    S_ERR(decrypted = new Message<unsigned char>(decr, decr_len), 0);
    destroy(&decr, decr_len);
    destroy(&sk, symmetric_key -> getLen());
    destroy(&iiv, iv -> getLen());
    destroy(&ct, ciphertext -> getLen());

    // Clean cipher context 
    EVP_CIPHER_CTX_free(context);
    context = NULL;
    return 1;
}

// Decrypts a message and check for authenticity.
// The tag acts as a MAC and assures the authenticity of the plaintext
// together with the AAD.
int SymmetricEncryption::AEADdecrypt(
    Message<unsigned char> *ciphertext,
    Message<unsigned char> *symmetric_key, 
    Message<unsigned char> *iv,
    Message<unsigned char> *aad,
    Message<unsigned char> *rec_tag) {
    
    // Clean prev decrypted
    //destroy(&&decrypted);
    clean();
    
    // Allocate decr size
    S_ERR(decr = (unsigned char*) calloc(
        ciphertext -> getLen() + 1, sizeof(unsigned char)), 0);
    S_ERR(sk = symmetric_key -> getMessage(), 0);
    S_ERR(ct = ciphertext -> getMessage(), 0);
    S_ERR(iiv = iv -> getMessage(), 0);
    S_ERR(aead = aad -> getMessage(), 0);
    S_ERR(recv_tag = rec_tag -> getMessage(), 0);
    // Allocate space for tag that will be generate by auth-encr
    // It is always 16 byte
    S_ERR(t_tag = (unsigned char*)calloc(17, sizeof(unsigned char)), 0);
    
    // Decrypted's length
    int decr_len;

    // real unsigned char written from Decrypt update 
    int written;

    // Allocates the cipher context
    S_ERR(context = EVP_CIPHER_CTX_new(), 0);

    // Initialize context for decryption
    S_ERR(EVP_DecryptInit(context, cipher,
        sk, iiv), 0);

    // Introduce aad that will generate tag and will be compared
    // with received one for checking authenticity of the message
    S_ERR(EVP_DecryptUpdate(context, NULL, &written, 
        aead, aad -> getLen()), 0);

    // Decrypt plaintext
    S_ERR(EVP_DecryptUpdate(context, decr, &written, 
        ct, ciphertext -> getLen()), 0);

    // Updatre decrypted len
    decr_len = written;

    // Compare the rec_tag with the actual one
    S_ERR(EVP_CIPHER_CTX_ctrl(context, 
        EVP_CTRL_AEAD_SET_TAG, 16, (unsigned char *)recv_tag), 0);

    // Finalize encryption, add padding 
    S_ERR(EVP_DecryptFinal(context, &decr[written], &written), 0);

    // Update decrypted len
    decr_len += written;
    
    // Create decrypted with its len
    S_ERR(decrypted = new Message<unsigned char>(decr, decr_len), 0);
    destroy(&decr, decr_len);
    destroy(&t_tag, 16);
    destroy(&sk, symmetric_key -> getLen());
    destroy(&iiv, iv -> getLen());
    destroy(&ct, ciphertext -> getLen());
    destroy(&aead, aad -> getLen());
    destroy(&recv_tag, rec_tag -> getLen());

    // Clean cipher context 
    EVP_CIPHER_CTX_free(context);
    context = NULL;
    return 1;
}

// Return decrypted ciphertext (plaintext) => DEEP COPY
Message<unsigned char>* SymmetricEncryption::getDecrypted() {
    return decrypted -> clone();
}

// Return ciphertext => DEEP COPY
Message<unsigned char>* SymmetricEncryption::getCiphertext() {
    return ciphertext -> clone();
}

// Return tag => DEEP COPY
Message<unsigned char>* SymmetricEncryption::getTag() {
    return tag -> clone();
}

// Initialize and free a buffer 
void SymmetricEncryption::destroy(unsigned char **buf, int len) {
    if (*buf) {
        memset(*buf, 0, len);
        free(*buf);
        *buf = NULL;
    }
} 

// Initialize and free a Message structure 
void SymmetricEncryption::destroy(Message<unsigned char> **message) {
    if (*message) {
        delete *message;
        *message = NULL;
    }
}

// clean all class structure 
void SymmetricEncryption::clean() {
    if (pt) {
        free(pt);
        pt = NULL;
    }
    if (recv_tag) {
        free(recv_tag);
        recv_tag = NULL;
    }
    if (t_tag) {
        free(t_tag);
        t_tag = NULL;
    }
    if (decr) {
        free(decr);
        decr = NULL;
    }
    if (ct) {
        free(ct);
        ct = NULL;
    }
    if (sk) {
        free(sk);
        sk = NULL;
    }
    if (iiv) {
        free(iiv);
        iiv = NULL;
    }
    if (aead) {
        free(aead);
        aead = NULL;
    }
    destroy(&ciphertext);
    destroy(&decrypted);
    destroy(&tag);
    if (context) {
        EVP_CIPHER_CTX_free(context);
        context = NULL;
    }
}