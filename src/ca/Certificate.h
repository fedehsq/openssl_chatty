#ifndef Certificate_h
#define Certificate_h

#include <stdio.h>
#include <string.h>
#include "../ssl_utils/ssl_utils.h"

/* A main problem in asymmetric cryptography is to be sure that a 
certain subject uses a certain crypto quantity.
For example be sure that the server reachable at "www.server.com" 
uses a certain public key.
Only sending the public key over the net is not safe because 
a man in the middle could change it.
We need a trusted entity called Certification Authority (CA).
Everyone trusts the CA.
Everyone knows CA's public key.
The CA releases signed certificates, which bind a given subject 
to a given crypto quantity.
Public key certificares: bind a given subject 
(internet domain, sevrer, company) to a given public key. */

class Certificate {
    // fp to certificate or certificate revocation list
    FILE *fp_certificate = NULL;

    // Certificate
    X509 *certificate = NULL;

    // Certificate revocation list
    X509_CRL *crl = NULL;

    // Subject of a certificate
    X509_NAME *subject_name = NULL;

    // Store containing valid certifies
    X509_STORE *store = NULL;

    // Context to verify a certificate with the store
    X509_STORE_CTX *context = NULL;

public: 

    Certificate(const char* certificate_path);
    Certificate(const char* certificate_path, const char* certificate_list_path);

    ~Certificate();

    // Extract subject of certificate and return its name
    char *getSubjectName(X509 *certificate);

    // Add a certifcate in the store
    int addCertificate(X509 *certificate);

    // Get owner certificate
    X509 *getOwnerCertificate();
    
    // Get owner crl
    X509_CRL *getOwnerCrl();

    // Add a certifcate in the store
    int addCRL(X509_CRL *crl);

    // Verify a certifcate using the store
    int verifyCertificate(X509 *certificate);

    // Extracts the public key from a certificate
    EVP_PKEY* getPublicKey(X509 *certificate);

private:
    
    // Read a certificate from PEM file 
    void readCertificateFromFile(const char* certificate_path);

    // Read a certificate revocation list from PEM file 
    void readCrlFromFile(const char* crl_path);

    // Build store
    void buildStore();

    // Clean all class structure 
    void clean();
};

#endif