#include "DiffieHellman.h"

// Check for errors
#define DH_ERR(res, ret) { \
    if (!(res), 0) { \
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
DiffieHellman::DiffieHellman(){};

// Destructor
DiffieHellman::~DiffieHellman() {
    clean();
}

// Generate pair of keys (public and private) 
// using the low-level DH parameters (dh_st *key) i.e DH_get_2048_224()
// => write public key to file and then read it from file 
// and store to m_public_key
int DiffieHellman::generateDHKeysToFile(const char *m_public_key_path, dh_st *key) {
    this -> m_public_key_path = m_public_key_path;
    // Clean all
    clean();
    DH_ERR(dh_params = EVP_PKEY_new(), 0);
    // Copies the low-level DH parameters (key) 
    // into high-level DH parameters (dh_params) (1 on success).
    // If key == DH_get_2048_224(), it will be an object containing DH standard 
    // parameters with public of 2048 bits and private key of 224 bits
    // (112 bits security level)
    DH_ERR(EVP_PKEY_set1_DH(dh_params, key), 0);
    DH_free(key);

    // In this case EVP_PKEY_CTX_new() is called with dh parameters, 
    // so the opeation is a key generation
    DH_ERR(context = EVP_PKEY_CTX_new(dh_params, NULL), 0);

    // Initializes a context for dh key generation (1 on success)
    DH_ERR(EVP_PKEY_keygen_init(context), 0);

    // To generate a new key pair from the parameters:
    // Generate a dh private key and store in **pkey (1 on success)
    DH_ERR(EVP_PKEY_keygen(context, &m_private_key), 0);

    // Saves a DH public key on a .PEM file,
    // if pkey is a DH private key, it extracts 
    // the public key and save this (1 on success)
    DH_ERR(fp_dh_public_key = fopen(m_public_key_path, "w"), 0);
    DH_ERR(PEM_write_PUBKEY(fp_dh_public_key, m_private_key), 0);
    //EVP_PKEY_free(m_private_key);
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(dh_params);
    context = NULL;
    fclose(fp_dh_public_key);
    fp_dh_public_key = NULL;

    // Read public key from file
    DH_ERR(fp_dh_public_key = fopen(m_public_key_path, "r"), 0);
    DH_ERR(m_public_key = PEM_read_PUBKEY(fp_dh_public_key, NULL, NULL, NULL), 0);
    fclose(fp_dh_public_key);
    fp_dh_public_key = NULL;
    // DELETE PUBLIC KEY?
    return 1;
}

// Generate pair of keys (public and private) 
// using the low-level DH parameters (dh_st *key) i.e DH_get_2048_224()
// => write public key to file and then read it from file 
// and store to m_public_key
int DiffieHellman::generateDHKeys(dh_st *key) {
    // Clean all
    clean();
    DH_ERR(dh_params = EVP_PKEY_new(), 0);
    // Copies the low-level DH parameters (key) 
    // into high-level DH parameters (dh_params) (1 on success).
    // If key == DH_get_2048_224(), it will be an object containing DH standard 
    // parameters with public of 2048 bits and private key of 224 bits
    // (112 bits security level)
    DH_ERR(EVP_PKEY_set1_DH(dh_params, key), 0);
    DH_free(key);

    // In this case EVP_PKEY_CTX_new() is called with dh parameters, 
    // so the opeation is a key generation
    DH_ERR(context = EVP_PKEY_CTX_new(dh_params, NULL), 0);

    // Initializes a context for dh key generation (1 on success)
    DH_ERR(EVP_PKEY_keygen_init(context), 0);

    // To generate a new key pair from the parameters:
    // Generate a dh private key and store in **pkey (1 on success)
    DH_ERR(EVP_PKEY_keygen(context, &m_private_key), 0);

    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(dh_params);
    context = NULL;
    
    // Saves a DH public key from private key
    // Read public from private key
    bio = BIO_new(BIO_s_mem());
    DH_ERR(bio, 0);
    DH_ERR(PEM_write_bio_PUBKEY(bio, m_private_key), 0);
    DH_ERR(PEM_read_bio_PUBKEY(bio, &m_public_key, NULL, NULL), 0);
    BIO_free_all(bio);
    bio = NULL;
    return 1;
}

// Generate Elliptic-Curve Diffie-Hellman (ECDH) parameters relative 
// to the standard prime256v1 elliptic curve, 
// providing for 128 bits of effective security strength.
// It store the public key in passed path.
int DiffieHellman::generateECDHKeysToFile(const char *m_public_key_path) {
    // Clean all
    clean();
    this -> m_public_key_path = m_public_key_path;

    /* -------
    EVP_PKEY_CTX *ecdh_context
    ecdh_context = EVP_PKEY_CTX_new(dh_params, NULL);
    // Initializes a context for ECDH key generation 
    DH_ERR(EVP_PKEY_keygen_init(ecdh_context), 0);
    // To generate a new key pair from the parameters:
    // Generate a dh private key and store in **pkey 
    DH_ERR(EVP_PKEY_keygen(ecdh_context, &m_private_key), 0);
    ------  */

    // New context for generate keys with EC
    DH_ERR(context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL), 0);

    // Initializes a context for dh key generation...
    DH_ERR(EVP_PKEY_paramgen_init(context), 0);
    
    // With standard prime256v1 elliptic curve
    DH_ERR(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context, 
        NID_X9_62_prime256v1), 0);

    // Generate all needed parameters for ECDH
    DH_ERR(EVP_PKEY_paramgen(context, &dh_params), 0);

    // Initializes a context for ECDH key generation 
    DH_ERR(EVP_PKEY_keygen_init(context), 0);

    // To generate a new key pair from the parameters:
    // Generate a dh private key and store in **pkey 
    DH_ERR(EVP_PKEY_keygen(context, &m_private_key), 0);

    // Saves a DH public key on a .PEM file,
    // if pkey is a DH private key, it extracts 
    // the public key and save this 
    DH_ERR(fp_dh_public_key = fopen(m_public_key_path, "w"), 0);
    DH_ERR(PEM_write_PUBKEY(fp_dh_public_key, m_private_key), 0);
    //EVP_PKEY_free(m_private_key);
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(dh_params);
    context = NULL;
    fclose(fp_dh_public_key);
    fp_dh_public_key = NULL;

    // Read public key from file
    DH_ERR(fp_dh_public_key = fopen(m_public_key_path, "r"), 0);
    DH_ERR(m_public_key = PEM_read_PUBKEY(fp_dh_public_key, NULL, NULL, NULL), 0);
    fclose(fp_dh_public_key);
    fp_dh_public_key = NULL;
    return 1;
}

// Generate Elliptic-Curve Diffie-Hellman (ECDH) parameters relative 
// to the standard prime256v1 elliptic curve, 
// providing for 128 bits of effective security strength.
// It store the keys in internal program memory.
int DiffieHellman::generateECDHKeys() {
    // Clean all
    clean();

    /* -------
    EVP_PKEY_CTX *ecdh_context
    ecdh_context = EVP_PKEY_CTX_new(dh_params, NULL);
    // Initializes a context for ECDH key generation 
    DH_ERR(EVP_PKEY_keygen_init(ecdh_context), 0);
    // To generate a new key pair from the parameters:
    // Generate a dh private key and store in **pkey 
    DH_ERR(EVP_PKEY_keygen(ecdh_context, &m_private_key), 0);
    ------  */

    // New context for generate keys with EC
    DH_ERR(context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL), 0);

    // Initializes a context for dh key generation...
    DH_ERR(EVP_PKEY_paramgen_init(context), 0);
    
    // With standard prime256v1 elliptic curve
    DH_ERR(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context, 
        NID_X9_62_prime256v1), 0);

    // Generate all needed parameters for ECDH
    DH_ERR(EVP_PKEY_paramgen(context, &dh_params), 0);

    // Initializes a context for ECDH key generation 
    DH_ERR(EVP_PKEY_keygen_init(context), 0);

    // To generate a new key pair from the parameters:
    // Generate a dh private key and store in **pkey 
    DH_ERR(EVP_PKEY_keygen(context, &m_private_key), 0);

    //EVP_PKEY_free(m_private_key);
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(dh_params);
    context = NULL;

    // Saves a DH public key from private key
    // Read public from private key
    bio = BIO_new(BIO_s_mem());
    DH_ERR(bio, 0);
    DH_ERR(PEM_write_bio_PUBKEY(bio, m_private_key), 0);
    DH_ERR(PEM_read_bio_PUBKEY(bio, &m_public_key, NULL, 
        NULL), 0);
    BIO_free_all(bio);
    bio = NULL;
    return 1;
}

// Generate the shared secret passing peer's path public key.
int DiffieHellman::computeSessionKey(const char *peer_public_key_path) {
    // Retrieve pubkey of peer and store it in peer_public_key
    // (Load public key from file)
    DH_ERR(fp_dh_public_key = fopen(peer_public_key_path, "r"), 0);
    DH_ERR(peer_public_key = PEM_read_PUBKEY(fp_dh_public_key, NULL, NULL, NULL), 0);
    fclose(fp_dh_public_key);
    fp_dh_public_key = NULL;
    
    // In this case EVP_PKEY_CTX_new() is called with private key, 
    // so the opeation is a secret derivation (session key)
    // Initialize shared secret derivation context
    DH_ERR(context = EVP_PKEY_CTX_new(m_private_key, NULL), 0);

    // Derive the shared secret from my private key and the peer’s public key
    DH_ERR(EVP_PKEY_derive_init(context), 0);
    DH_ERR(EVP_PKEY_derive_set_peer(context, peer_public_key), 0);
    
    size_t key_len;
    // Get secret's length (1 on success)
    DH_ERR(EVP_PKEY_derive(context, NULL, &key_len), 0);
    // Secret (session key)
    DH_ERR(sk = (unsigned char*)calloc(key_len + 1, sizeof(unsigned char)), 0);
    // Fill secret
    DH_ERR(EVP_PKEY_derive(context, sk, &key_len), 0);
    DH_ERR(session_key = new Message<unsigned char>(sk, key_len), 0);
    destroy(sk, key_len);
    sk = NULL;
    EVP_PKEY_CTX_free(context);
    context = NULL;
    return 1;
}

// Print on stdout all DH / ECDH parameters.
void DiffieHellman::printDHparams() {
    bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    EVP_PKEY_print_private(bio, m_private_key, 0, NULL);
    BIO_free(bio);
    bio = NULL;
}

// Return the private key as string.
char* DiffieHellman::getPrivateKeyToString() {
    bio = BIO_new(BIO_s_mem());
    DH_ERR(bio, NULL);
    DH_ERR(PEM_write_bio_PrivateKey(bio, m_private_key, NULL, NULL, 0, NULL, NULL), 0);
    const int key_len = BIO_pending(bio);
    DH_ERR(key_len, NULL);
    char* key = (char *) calloc(key_len + 1, sizeof(char));
    DH_ERR(key, NULL);
    DH_ERR(BIO_read(bio, key, key_len), 0);
    BIO_free_all(bio);
    bio = NULL;
    return key;
}

// Return public key as string.
char* DiffieHellman::getPublicKeyToString() {
    bio = BIO_new(BIO_s_mem());
    DH_ERR(bio, NULL);
    DH_ERR(PEM_write_bio_PUBKEY(bio, m_public_key), 0);
    const int key_len = BIO_pending(bio);
    DH_ERR(key_len, NULL);
    char* key = (char *) calloc(key_len + 1, sizeof(char));
    DH_ERR(key, NULL);
    DH_ERR(BIO_read(bio, key, key_len), 0);
    BIO_free_all(bio);
    bio = NULL;
    return key;
}

// Return the private key as Message<char>*.
Message<char>* DiffieHellman::getPrivateKeyToMessage() {
    Message<char> *key = NULL;
    char *s_key = NULL;
    DH_ERR(s_key = getPrivateKeyToString(), NULL);
    DH_ERR(key = new Message<char>(s_key, strlen(s_key)), NULL);
    return key;
}

// Return public key as Message *.
Message<char>* DiffieHellman::getPublicKeyToMessage() {
    Message<char> *key = NULL;
    char *s_key = NULL;
    DH_ERR(s_key = getPublicKeyToString(), NULL);
    DH_ERR(key = new Message<char>(s_key, strlen(s_key)), NULL);
    return key;
}

// Return session key. (DEEP COPY)
Message<unsigned char>* DiffieHellman::getSessionKey() {
    return session_key -> clone();
}

// Return private key.
EVP_PKEY* DiffieHellman::getPrivateKey() {
    return m_private_key;
}

// Return private key.
EVP_PKEY* DiffieHellman::getPublicKey() {
    return m_public_key;
}

// Print some bytes on stdout.
void DiffieHellman::printBytes(Message<unsigned char> *bytes) {
    unsigned char *b = bytes -> getMessage();
    BIO_dump_fp(stdout, (char *)b, bytes -> getLen());
    destroy(b, bytes -> getLen());
}

// Initialize and free a Message structure.
void DiffieHellman::destroy(Message<unsigned char> **message) {
    if (*message) {
        delete *message;
        *message = NULL;
    }
}

// Initialize and free a buffer 
void DiffieHellman::destroy(void *buf, size_t len) {
    if (buf) {
        memset(buf, 0, len);
        free(buf);
        buf = NULL;
    }
}

// Clean all class structure.
void DiffieHellman::clean() {
    destroy(&session_key);
    if (bio) {
        BIO_free_all(bio);
        bio = NULL;
    }
    if (sk) {
        free(sk);
        sk = NULL;
    }
    if (m_private_key) {
        EVP_PKEY_free(m_private_key);
        m_private_key = NULL;
    }
    if (m_public_key) {
        EVP_PKEY_free(m_public_key);
        m_public_key = NULL;
    }
    if (peer_public_key) {
        EVP_PKEY_free(peer_public_key);
        peer_public_key = NULL;
    }
    if (fp_dh_public_key) {
        fclose(fp_dh_public_key);
        fp_dh_public_key = NULL;
    }
    if (context) {
        EVP_PKEY_CTX_free(context);
        context = NULL;
    }
}