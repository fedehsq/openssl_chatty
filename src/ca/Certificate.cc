#include "Certificate.h"

// Check for errors
#define HANDLE_C_ERROR(res, ret) { \
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
#define HANDLE_ERROR(res) { \
    if (!(res)) { \
        std::cerr << "In " << __FILE__ << " error on line " << __LINE__ << ": "; \
        std::cerr << strerror(errno) << "\n"; \
        ERR_print_errors_fp(stderr); \
        clean(); \
        errno = 0; \
    } \
}

// Initialize a certificate context only with owner certificate
Certificate::Certificate(const char* certificate_path) {
    readCertificateFromFile(certificate_path);
    buildStore();
}

// Initialize a certificate context with owner certificate and crl
Certificate::Certificate(const char* certificate_path, const char* certificate_list_path) {
    readCertificateFromFile(certificate_path);
    readCrlFromFile(certificate_list_path);
    buildStore();
}

Certificate::~Certificate() {
    clean();
}

// Build store
void Certificate::buildStore() {
    HANDLE_ERROR(store = X509_STORE_new());
}

// Read a certificate from PEM file
void Certificate::readCertificateFromFile(const char* certificate_path) {
    HANDLE_ERROR(fp_certificate = fopen(certificate_path, "r"));
    HANDLE_ERROR(certificate = PEM_read_X509(fp_certificate, NULL, NULL, NULL));
    fclose(fp_certificate);
    fp_certificate = NULL;
}

// Read a certificate revocation list from PEM file
void Certificate::readCrlFromFile(const char* certificate_list_path) {
    HANDLE_ERROR(fp_certificate = fopen(certificate_list_path, "r"));
    HANDLE_ERROR(crl = PEM_read_X509_CRL(fp_certificate, NULL, NULL, NULL));
    fclose(fp_certificate);
    fp_certificate = NULL; 
}

// Extract subject of certificate and return its name
char* Certificate::getSubjectName(X509 *certificate) {
    char *name;
    HANDLE_C_ERROR(subject_name = X509_get_subject_name(certificate), NULL);
    HANDLE_C_ERROR(name = X509_NAME_oneline(subject_name, NULL, 0), NULL);
    // free(subject_name);
    return name;
}

X509* Certificate::getOwnerCertificate() {
    return certificate;
}

X509_CRL* Certificate::getOwnerCrl() {
    return crl;
}

// Add a certifcate in the store
int Certificate::addCertificate(X509 *certificate) {
    HANDLE_C_ERROR(X509_STORE_add_cert(store, certificate), 0);
    return 1;
}

// Add a certifcate in the store
int Certificate::addCRL(X509_CRL *crl) {
    HANDLE_C_ERROR(X509_STORE_add_crl(store, crl) , 0);
    // Indicates to use crl
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    return 1;
}

// Verify a certifcate using the store
int Certificate::verifyCertificate(X509 *certificate) {
    HANDLE_C_ERROR(context = X509_STORE_CTX_new(), 0);
    HANDLE_C_ERROR(X509_STORE_CTX_init(context, store, certificate, NULL), 0);
    HANDLE_C_ERROR(X509_verify_cert(context), 0);
    X509_STORE_CTX_free(context);
    context = NULL;
    return 1;
}

// Extracts the public key from a certificate
EVP_PKEY* Certificate::getPublicKey(X509 *certificate) {
    EVP_PKEY *public_key;
    HANDLE_C_ERROR(public_key = X509_get_pubkey(certificate), NULL);
    return public_key;
}

// Clean all class structure 
void Certificate::clean() {
    /*
    if (subject_name) {
        //X509_NAME_free(subject_name);
        free(subject_name);
        subject_name = NULL;
    }
    */
    if (store) {
        X509_STORE_free(store);
        store = NULL;
    }
    if (fp_certificate) {
        fclose(fp_certificate);
        fp_certificate = NULL;
    }
    if (context) {
        X509_STORE_CTX_free(context);
        context = NULL;
    }
    if (certificate) {
        X509_free(certificate);
        certificate = NULL;
    }
    if (crl) {
        X509_CRL_free(crl);
        crl = NULL;
    }
}