#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>
#include <iostream>
#include <vector>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <bits/stdc++.h>
#include "../ssl_utils/ssl_utils.cc"
#include "../utils/utils.cc"
#include "../digital_signature/DigitalSignature.cc"
#include "../ca/Certificate.cc"
#include "../asymmetric_encription/AsymmetricEncryption.cc"
using namespace std;

// Ip address of service
#define ADDRESS "127.0.0.1"
// Main port of the service
#define PORT 8080
// Chat requests port of the service
#define REQ_PORT 8081
// Maximum lenght of messages
#define MAX_LEN 10000

volatile int KILL = 0;

// Server public key
EVP_PKEY *server_key = NULL;

// To manage shared variables (list of incoming requests and the KILL_CLIENT variable)
pthread_mutex_t mux = PTHREAD_MUTEX_INITIALIZER;
// Id of thread that waits for incoming chat requests by peers
pthread_t requester_tid;

// Chat requested, list shared between main thread and the chat handler
vector<string> requests = {};

// It verifies if server certificate is valid
int certify(X509 *server_cert); 

// This peer starts the key negotiations.
// Client and peer negotiate a session key to use for encrypt
// guarantee perfect forward secrecy, following this schema: (ERSA)
//  1: Client sends a R random to the peer (nonce) signed [R, signed R]
//  2: peer generates a temporary public and private RSA keys (TpubK, TprivK)
//  3: peer sends [[R, TpubK]signed PrvK, Tpubk]
//  4: Client verifies message and it chooses a random session K key
//  5: Client encrypts this K with Tpubk and send it to the peer [E(k)]
//     Real message is: [E(K gen_dig_env)), iv, iv signed, ct]
// Return the ephimeral session key.
Message<unsigned char> *server_key_negotiation(User *user);

// Same with the other peer
Message<unsigned char> *key_negotiation_new(User *user, EVP_PKEY *peer_pubkey);
Message<unsigned char> *key_negotiation_new(EVP_PKEY *peer_pubkey, User *user);

// Client and server exchange encrypted and authenticated messages.
// Now the symmetric key is chosen.
// To guarantee integrity and authentication the communication uses
// Authenticated encryption with associated data (AEAD).
// Possible request:
//  1: server sends to the client ondestroy users.
//  2: client send a chat request to the server, so the server forward
//     this request to the peer chat socket and the client requester is 
//     put in wait for response.
//  3: if 2 peer are agree to start a chat, they negotiate a symmetric
//     key and they begin to chat.
//  4: after a chat session, server disconnect the 2 peers.
int request(User *user);

// Split online usernames and put them in a vector.
vector<string> tokenize_username(char *s);

// Print the possible operation for a client.
void print_menu(Message<unsigned char>* m);

// Read client input while it is a valid operation.
string read_operation(User *user);

// When a client connects, it start a thread that receives incoming chat request.
void *requester(void *arg);

// Handle chat requests
int handle_chat_requests(User *user, Message<unsigned char> *sym_server_key);

// If user has inserted a valid username of peer, 
// send to him through server the chat request
int send_chat_request(User *user, Message<unsigned char> *sym_server_key, vector<string> names, string input);

// Server sends to the peer the public key of other pert, 
// then the symmetric key negotiations starts.
// After it is completed, a 'reader' thread is created that receive incoming messages.
// This thread instead wait for user input and send the message to the server
// that forwward the message to other peer.
// Then the chat begins.
// Every message is sent to the server, it forward the message to other peer.
// Return 1 if the chat ends with correct word "__exit__" by one of the two
// peer, 0 in case of some error.
int chatty(User *user, const char *peer_username);

// Read message AEAD; Increase the recv counter of user
Message<unsigned char>* recv_aead_decrypt_message(User *user, Message<unsigned char> *key);

// Increase the counter of user then send message with AEAD on socket socket
int send_aead_encrypt_message(string input, User *user, int socket, Message<unsigned char> *key);

// Increase the counter of user then send bytes message with AEAD
int send_aead_encrypt_message(Message<unsigned char> *plaintext, User *user,  int socket, Message<unsigned char> *key);

// Before the chat starts, a 'reader' thread is created that receive 
// incoming chat messages.
void *reader(void *arg);

// This struct is passed to the reader thread, it containes the user socket,
// the peer username,
// and the symmetric session key used for chat with other peer.
struct client {
    User *user;
    const char *peer_username;
    Message<unsigned char> *key;
};

int main() {
    
    // Main socket with whose client communicates with the server 
    int main_server_socket;
    // Number of times that client can insert wrong username
    int times = 3;
    // Chat socket with whose the requester thread receives incoming chat requests
    long chat_server_socket;
    // The two struct that permit connection with the service
	struct sockaddr_in server, chat_server;
    // Client public/private key path, client username 
    string pubkey_path, prvkey_path, username; 
    // After user is correctly authenticated pass it 
    // to chat requester thread as argument
    User *user = NULL;
    // Client public key
    EVP_PKEY *pubkey = NULL;
    // Session key negotiates with the server
    Message<unsigned char> *server_sym_key = NULL;
    // If user public key can be opened, he exits
    FILE *fp_user = NULL;

	// Create TCP sockets: one 'implements' the standard communication 
    // between server and client, 
    // the other one is just to receive incoming chat requests 
	N_ERR((main_server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)), destroy);
    N_ERR((chat_server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)), destroy);

    // Prepare the structure for standard communication 
    bzero((char *)&server, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr(ADDRESS);
	server.sin_port = htons(PORT);

    // Prepare the structure for receiving chat requests 
    bzero((char *)&chat_server, sizeof(chat_server));
	chat_server.sin_family = AF_INET;
	chat_server.sin_addr.s_addr = inet_addr(ADDRESS);
	chat_server.sin_port = htons(REQ_PORT);
	
	// Connect to the server 
	N_ERR(connect(main_server_socket, (struct sockaddr *)&server, 
        sizeof(server)), destroy);
    N_ERR(connect(chat_server_socket, (struct sockaddr *)&chat_server, 
        sizeof(chat_server)), destroy);

    do {
        cout << "Enter your username: ";
        getline(cin, username);
        pubkey_path = username;
        pubkey_path.append("_public_key.pem");
        // Search if public key exists in the . dir
        if ((fp_user = fopen(pubkey_path.c_str(), "r")) == NULL) {
            cout << "Wrong username. Remaining times: " << --times << endl;
        } else {
            times = 0;
            fclose(fp_user);
        }
    } while (times > 0);
    pubkey_path = username;
    pubkey_path.append("_public_key.pem");
    prvkey_path.append("_private_key.pem");
    // Read the public key from client directory
    ERR(pubkey = read_public_key_from_file(pubkey_path.c_str()), destroy);
    // Create an istance of User
    ERR(user = new User(username, main_server_socket, chat_server_socket, pubkey), destroy);
    // Negotiation with server for the session key
    ERR(server_sym_key = server_key_negotiation(user), destroy);
    // Set it as user parameter
    user -> setServerSymKey(server_sym_key);
    NO_0_ERR(pthread_create(&requester_tid, NULL, requester, (void *)user), destroy);
    // Client and server communications
    ERR(request(user), destroy);
    // Correct termination of client
    NO_0_ERR(pthread_join(requester_tid, NULL), destroy);
destroy:
    close(main_server_socket);
    mdestroy(1, &server_sym_key);
    if (server_key) {
        EVP_PKEY_free(server_key);
    }
    if (pubkey) {
        EVP_PKEY_free(pubkey);
    }
    odestroy(1, &user);
    return 0;
}

// It verifies if server certificate is valid
int certify(X509 *server_cert) {
    int ret = 0;
    Certificate *ca = NULL;
    X509 *ca_cert = NULL;
    ERR(ca = new Certificate("CA_cert.pem", "CA_crl.pem"), 
        end);
    ERR(ca_cert = ca -> getOwnerCertificate(), end);
    ERR(ca -> addCertificate(ca_cert), end);
    ERR(ca -> addCRL(ca -> getOwnerCrl()), end)
    ERR(ret = ca -> verifyCertificate(server_cert), end);
    cout << "Certificate is valid!" << endl;
    ret = 1;
end:
    if (ca) {
        delete ca;
    }
    return ret;   
}

// When a client connects, it start a thread that receives incoming chat request
void *requester(void *arg) {
    User *user = NULL;
    // Decrypted ciphertext sent by server (chat user request)
    Message<unsigned char> *plaintext = NULL;
    Message<unsigned char> *server_sym_key = NULL;
    // Put peer request in a list
    string s_peer;
    char *c_peer = NULL;

    ERR(user = (User *)arg, destroy);
    ERR(server_sym_key = user -> getServerSymKey(), destroy);
    for(;;) {
        // Server AEAD message: username peer requester
        ERR(plaintext = recv_aead_msg(user), destroy);
        pthread_mutex_lock(&mux);
        user -> increaseServerRecvCounter();
        pthread_mutex_unlock(&mux);
        //cout << "recv counter: " << user -> getServerRecvCounter() << endl;

        c_peer = (char*)plaintext -> getMessage();
        s_peer = c_peer;
        // User has started a chat, Server send to this thread to shutdown
        if (s_peer.compare("exit") == 0) {
            break;
        }
        // Put peer request in a list
        pthread_mutex_lock(&mux);
        requests.push_back(s_peer);
        pthread_mutex_unlock(&mux);

        delete plaintext;
        plaintext = NULL;
        memset(c_peer, 0, strlen(c_peer));
        free(c_peer);
        c_peer = NULL;
    }
destroy:
    if (plaintext) {
        delete plaintext;
    }
    if (c_peer) {
        memset(c_peer, 0, strlen(c_peer));
        free(c_peer);
    }
    if (server_sym_key) {
        delete server_sym_key;
    }
    pthread_exit(EXIT_SUCCESS);
}

// This peer starts the key negotiations.
// Client and peer negotiate a session key to use for encrypt
// guarantee perfect forward secrecy, following this schema: (ERSA)
//  1: Client sends a R random to the peer (nonce) signed [R, signed R]
//  2: peer generates a temporary public and private RSA keys (TpubK, TprivK)
//  3: peer sends [[R, TpubK]signed PrvK, Tpubk]
//  4: Client verifies message and it chooses a random session K key
//  5: Client encrypts this K with Tpubk and send it to the peer [E(k)]
//     Real message is: [E(K gen_dig_env)), iv, iv signed, ct]
// Return the ephimeral session key.
Message<unsigned char> *server_key_negotiation(User *user) {
    puts("Key negotiation starts...");
    // Result (session key)
    Message<unsigned char> *ret = NULL;
    // To send over socket
    unsigned char *to_send = NULL;
    int to_send_size;
    // Clear nonce
    Message<unsigned char> *nonce = NULL;
    // Signed nonce
    Message<unsigned char> *sign = NULL;
    Message<unsigned char> *to_sign = NULL;
    Message<unsigned char> *m_username = NULL;
    // Verify client message
    DigitalSignature *digital_signature = NULL;
    // Peer sign: [R, TpubK]signed PrvK
    Message<unsigned char> *peer_sign = NULL;
    // Concat [R, TpubK] for verifing peer sign
    Message<unsigned char> *verify_sign = NULL;
    // Temporary peer public key as Message: Tpubk
    Message<unsigned char> *peer_tm_pub_key = NULL;
    // Temporary peer public key: Tpubk
    EVP_PKEY *peer_t_pub_key = NULL;
    // To encrypt session key
    AsymmetricEncryption *asym = NULL;
    // All messages from peer
    Message<unsigned char> *received_message = NULL;
    // Splitter messages
    vector<Message<unsigned char>*> messages = {};
    // Ephimeral symmetric key chosen by client
    Message<unsigned char> *session_key = NULL;
    // Ciphertext generated by algo (client chosen symmetric key)
    Message<unsigned char> *ciphertext = NULL;
    // Cipher key generated by algo => to open with peer private key
    Message<unsigned char> *encr_session_key = NULL;
    // IV generated by algo
    Message<unsigned char> *iv = NULL;

    // Received textual certificate
    Message<unsigned char> *certificate = NULL;
    // Bytes certificate
    unsigned char *b_certificate = NULL;
    // Server certificate
    X509 *server_certificate = NULL;

    // Private key path
    string private_key_path = user -> getUsername();
    private_key_path.append("_private_key.pem");

    // Get client username
    ERR(m_username = new Message<unsigned char>((unsigned char*)user -> getUsername().c_str(), user -> getUsername().length()), destroy);

    // 1: Client sends a R random to peer (nonce) signed [R, signed R]
    // Generate random nonce R
    ERR(nonce = generate_random_bytes(CHUNK), destroy);
    ERR(to_send = concat(&to_send_size, nonce, m_username, NULL), destroy);
    // Send message
    N_ERR(send(user -> getMainSocket(), to_send, to_send_size, 0), destroy);
    puts("[nonce, username] sent");


    // 3: server sends [[R, TpubK]signed PrvK, Tpubk, cert]
    if ((messages = read_split_message(user -> getMainSocket())).empty()) {
        goto destroy;
    }
    // Split messages and store them in a vector 
    peer_sign = messages[0];
    peer_tm_pub_key = messages[1];
    certificate = messages[2];
    ERR(b_certificate = certificate -> getMessage(), destroy);
    // Get X509 *certificate
    ERR(server_certificate = 
        bytes_to_certificate(b_certificate, certificate -> getLen()), destroy);
    // Verify server certificate
    ERR(certify(server_certificate), destroy);
    // Extract server public key and verify its sign
    ERR(server_key = X509_get_pubkey(server_certificate), destroy);
    ERR(digital_signature = new DigitalSignature(), destroy);
    // 4: Client verifies message...
    // Concat [R, TpubK] for verifing peer sign
    ERR(verify_sign = mconcat(nonce, peer_tm_pub_key, NULL), destroy);
    ERR(digital_signature -> verify(verify_sign, peer_sign, 
        server_key), destroy);
    puts("Sign match: [[R, TpubK]signed, Tpubk, cert] received");
    // From bytes to EVP* key
    ERR(peer_t_pub_key = get_public_key_from_message(peer_tm_pub_key), destroy);
    // 4.1 ...and it chooses a random session key K
    ERR(session_key = 
        generate_random_bytes(EVP_CIPHER_key_length(EVP_aes_256_gcm())),
        destroy);

    // 5: Client encrypts this K with Tpubk and send it to the peer [E(k)]
    //    Real message to send is: x = [E(k), iv, ct (session key)], <tPubk, x>
    // Encrypt session key with Tpubk
    ERR(asym = new AsymmetricEncryption(EVP_aes_256_cbc()), destroy);
    ERR(asym -> encrypt(session_key, peer_t_pub_key), destroy);
    ERR(ciphertext = asym -> getCiphertext(), destroy);
    ERR(encr_session_key = asym -> getEncryptedSymmetricKey(), destroy);
    ERR(iv = asym -> getIv(), destroy);
    puts("Sign the message for just generated session key");
    // Client signs: <temp pub k || E(k)>
    ERR(to_sign = mconcat(peer_tm_pub_key, ciphertext, encr_session_key, iv, NULL), destroy);
    ERR(digital_signature -> sign(to_sign, private_key_path.c_str()),
        destroy);
    ERR(sign = digital_signature -> getSign(), destroy);
    memset(to_send, 0, to_send_size);
    free(to_send);
    // Real message to send is: [E(k), iv, <sign>, ct (session key)]
    ERR(to_send = concat(&to_send_size, encr_session_key, iv, sign, ciphertext, NULL), destroy);
    if (send(user -> getMainSocket(), to_send, to_send_size, 0)) {
        ret = session_key;
        puts("Key negotiation done!");
    }
destroy:
    if (!ret && session_key) {
        delete session_key;
    }
    if (to_send) {
        memset(to_send, 0, to_send_size);
        free(to_send);
    }
    if (nonce) {
        delete nonce;
    }
    if (sign) {
        delete sign;
    }
    if (digital_signature) {
        delete digital_signature;
    }
    if (peer_sign) {
        delete peer_sign;
    }
    if (verify_sign) {
        delete verify_sign;
    }
    if (peer_tm_pub_key) {
        delete peer_tm_pub_key;
    }
    if (peer_t_pub_key) {
        EVP_PKEY_free(peer_t_pub_key);
    }
    if (asym) {
        delete asym;
    }
    if (received_message) {
        delete received_message;
    }
    if (ciphertext) {
        delete ciphertext;
    }
    if (encr_session_key) {
        delete encr_session_key;
    }
    if (iv) {
        delete iv;
    }
    return ret;
}


// This peer starts the key negotiations.
// Client and peer negotiate a session key to use for encrypt
// guarantee perfect forward secrecy, following this schema: (ERSA)
//  1: Client sends a R random to the peer (nonce) signed [R, signed R]
//  2: peer generates a temporary public and private RSA keys (TpubK, TprivK)
//  3: peer sends [[R, TpubK]signed PrvK, Tpubk]
//  4: Client verifies message and it chooses a random session K key
//  5: Client encrypts this K with Tpubk and send it to the peer [E(k)]
//     Real message is: [E(K gen_dig_env)), iv, iv signed, ct]
// Return the ephimeral session key.
Message<unsigned char> *key_negotiation_new(User *user, EVP_PKEY *peer_pubkey) {
    puts("Key negotiation starts...");
    // Server sym session key
    Message<unsigned char> *server_sym_key = NULL;
    Message<unsigned char> *plaintext = NULL;
    // Result (session key)
    Message<unsigned char> *ret = NULL;
    // Clear nonce
    Message<unsigned char> *nonce = NULL;
    // Signed nonce
    Message<unsigned char> *sign = NULL;
    Message<unsigned char> *to_sign = NULL;
    Message<unsigned char> *m_username = NULL;
    // Verify client message
    DigitalSignature *digital_signature = NULL;
    // Peer sign: [R, TpubK]signed PrvK
    Message<unsigned char> *peer_sign = NULL;
    // Concat [R, TpubK] for verifing peer sign
    Message<unsigned char> *verify_sign = NULL;
    // Temporary peer public key as Message: Tpubk
    Message<unsigned char> *peer_tm_pub_key = NULL;
    // Temporary peer public key: Tpubk
    EVP_PKEY *peer_t_pub_key = NULL;
    // To encrypt session key
    AsymmetricEncryption *asym = NULL;
    // All messages from peer
    Message<unsigned char> *received_message = NULL;
    // Splitter messages
    vector<Message<unsigned char>*> messages = {};
    // Ephimeral symmetric key chosen by client
    Message<unsigned char> *session_key = NULL;
    // Ciphertext generated by algo (client chosen symmetric key)
    Message<unsigned char> *ciphertext = NULL;
    // Cipher key generated by algo => to open with peer private key
    Message<unsigned char> *encr_session_key = NULL;
    // IV generated by algo
    Message<unsigned char> *iv = NULL;

    // Private key path
    string private_key_path = user -> getUsername();
    private_key_path.append("_private_key.pem");

    ERR(server_sym_key = user -> getServerSymKey(), destroy);

    // Get client username
    ERR(m_username = new Message<unsigned char>((unsigned char*)user -> getUsername().c_str(), user -> getUsername().length()), destroy);

    // 1: Client sends a R random to peer (nonce) signed [R, signed R]
    // Generate random nonce R
    ERR(nonce = generate_random_bytes(CHUNK), destroy);

    ERR(plaintext = mconcat(nonce, m_username, NULL), destroy);
    // Encrypt with server sym key with AEAD then send message
    ERR(send_aead_encrypt_message(plaintext, user, user -> getMainSocket(), server_sym_key), destroy);
    puts("[nonce, username] sent");

    // 3: peer sends [[R, TpubK]signed PrvK, Tpubk]
    ERR(plaintext = recv_aead_decrypt_message(user, server_sym_key), destroy);
    messages = split(plaintext, SIGN_SIZE, plaintext -> getLen() - SIGN_SIZE);
    // Split messages and store them in a vector
    peer_sign = messages[0];
    peer_tm_pub_key = messages[1];
    
    // 4: Client verifies message...
    ERR(digital_signature = new DigitalSignature(), destroy);
    // Concat [R, TpubK] for verifing peer sign
    ERR(verify_sign = mconcat(nonce, peer_tm_pub_key, NULL), destroy);
    ERR(digital_signature -> verify(verify_sign, peer_sign, 
        peer_pubkey), destroy);
    puts("Sign match: [[R, TpubK]signed PrvK, Tpubk] received");
    // From bytes to EVP* key
    ERR(peer_t_pub_key = get_public_key_from_message(peer_tm_pub_key), destroy);
    // 4.1 ...and it chooses a random session key K
    ERR(session_key = 
        generate_random_bytes(EVP_CIPHER_key_length(EVP_aes_256_gcm())),
        destroy);

    // 5: Client encrypts this K with Tpubk and send it to the peer [E(k)]
    //    Real message to send is: x = [E(k), iv, ct (session key)], <tPubk, x>
    // Encrypt session key with Tpubk
    ERR(asym = new AsymmetricEncryption(EVP_aes_256_cbc()), destroy);
    ERR(asym -> encrypt(session_key, peer_t_pub_key), destroy);
    ERR(ciphertext = asym -> getCiphertext(), destroy);
    ERR(encr_session_key = asym -> getEncryptedSymmetricKey(), destroy);
    ERR(iv = asym -> getIv(), destroy);
    puts("Sign the message for just generated session key");
    // Client signs: <temp pub k || E(k)>
    ERR(to_sign = mconcat(peer_tm_pub_key, ciphertext, encr_session_key, iv, NULL), destroy);
    ERR(digital_signature -> sign(to_sign, private_key_path.c_str()),
        destroy);
    ERR(sign = digital_signature -> getSign(), destroy);
    // Real message to send is: [E(k), iv, <sign>, ct (session key)]
    ERR(plaintext = mconcat(encr_session_key, iv, sign, ciphertext, NULL), destroy);
    // Encrypt with server sym key with AEAD then send message
    if (send_aead_encrypt_message(plaintext, user, user -> getMainSocket(), server_sym_key)) {
        ret = session_key;
        puts("Key negotiation done!");
    }
    //print_bytes(ret);
destroy:
    if (!ret && session_key) {
        delete session_key;
    }
    if (nonce) {
        delete nonce;
    }
    if (sign) {
        delete sign;
    }
    if (digital_signature) {
        delete digital_signature;
    }
    if (peer_sign) {
        delete peer_sign;
    }
    if (verify_sign) {
        delete verify_sign;
    }
    if (peer_tm_pub_key) {
        delete peer_tm_pub_key;
    }
    if (peer_t_pub_key) {
        EVP_PKEY_free(peer_t_pub_key);
    }
    if (asym) {
        delete asym;
    }
    if (received_message) {
        delete received_message;
    }
    if (ciphertext) {
        delete ciphertext;
    }
    if (encr_session_key) {
        delete encr_session_key;
    }
    if (iv) {
        delete iv;
    }
    return ret;
}

// (The comments are the same of server session key but here there is client neg)
// Client and Server negotiate a session key to use for encrypt
// guarantee perfect forward secrecy, following this schema: (ERSA)
//  1: Client sends a R random to server (nonce) signed [R, signed R]
//  2: Server generates a temporary public and private RSA keys (TpubK, TprivK)
//  3: Server sends [[R, TpubK]signed PrvK, Tpubk]
//  4: Client verifies message and choose a random session K
//  5: Client encrypts this K with Tpubk and send it to the Server [E(k)]
//     Real message is: [E(k), iv, iv signed, ct (session key)]
//  Client and Server use this K to encrypt.
//  The session key is returned. In case of some errors, NULL is returned
Message<unsigned char>* key_negotiation_new(EVP_PKEY *peer_public_key, User *user) {
    // Return value: key if always go well
    Message<unsigned char> *server_sym_key = NULL;
    Message<unsigned char> *plaintext = NULL;
    Message<unsigned char>* ret = NULL;
    // Entire socket message received
    Message<unsigned char> *received_message = NULL;
    // 1: Clear nonce
    Message<unsigned char> *nonce = NULL;
  
    // 1, 5: Peer sign
    Message<unsigned char> *peer_sign = NULL;
    // Message to verifies sign
    Message<unsigned char> *verify_sign = NULL;
    
    // 2: Generate RSA temporary private and public keys
    RSA *rsa = NULL;
    // Ephimeral RSA private key
    EVP_PKEY *t_private_key = NULL;
    // Ephimeral RSA public key
    EVP_PKEY *t_public_key = NULL;


    // 3: Ephimeral public key as Message*
    Message<char> *tm_public_key = NULL;
    // To sign: [R, TpubK]
    Message<unsigned char> *to_sign = NULL;
    // Sign: [R, TpubK]signed
    Message<unsigned char> *sign = NULL;

    // 5: Ephimeral symmetric key chosen by client
    Message<unsigned char> *session_key = NULL;
    // Ciphertext generated by envelope_update (client chosen symmetric key)
    Message<unsigned char> *ciphertext = NULL;
    // Cipher key generated by envelope_init, to open with server private key
    Message<unsigned char> *encr_session_key = NULL;
    // IV generated by envelope_init,
    Message<unsigned char> *iv = NULL;

    // Vector containing all splitted messages
    vector<Message<unsigned char>*> messages;

    // Verify client message / Sign message
    DigitalSignature *digital_signature = NULL;

    // To decryot ephimeral session key
    AsymmetricEncryption *asym = NULL;
   
    ERR(server_sym_key = user -> getServerSymKey(), destroy);
    ERR(plaintext = recv_aead_decrypt_message(user, server_sym_key), destroy);
    
    // 1: Client sends a R random and username to the server: [nonce, username]
    messages = split(plaintext, CHUNK, plaintext -> getLen() - CHUNK, 0);
    // Assign items
    nonce = messages[0];

    // 2: Client generates a temporary public and private RSA key (TpubK, TprivK)
    ERR(rsa = generate_RSA_keys(), destroy);
    ERR(t_private_key = get_private_key(rsa), destroy);
    ERR(t_public_key = get_public_key(t_private_key), destroy);

    // 3: Server sends [[R, TpubK]signed PrvK, Tpubk]
    digital_signature = new DigitalSignature();
    ERR(tm_public_key = get_public_key_to_message(t_public_key), destroy);
    ERR(to_sign = mconcat(nonce, tm_public_key, NULL), destroy);
    puts("Sign [nonce, TpubK]");
    ERR(digital_signature -> sign(to_sign, user -> getUsername().append("_private_key.pem").c_str()), destroy);
    ERR(sign = digital_signature -> getSign(), destroy);

    ERR(plaintext = mconcat(sign, tm_public_key, NULL), destroy);
    
    ERR(send_aead_encrypt_message(plaintext, user, user -> getMainSocket(), server_sym_key), destroy);

    // peer sends the symmetric key: real message to received is: [E(K), iv, <sign>, ct(session key)]
    ERR(plaintext = recv_aead_decrypt_message(user, server_sym_key), destroy);
    // Split messages
    messages = split(plaintext, 
        // Encrypted symmetric key length
        EVP_PKEY_size(t_public_key),
        // IV length
        EVP_CIPHER_iv_length(EVP_aes_256_cbc()),
        // Sign length
        SIGN_SIZE, 
        // Ciphertext of arbitrary length
        plaintext -> getLen() 
        - SIGN_SIZE 
        - EVP_CIPHER_iv_length(EVP_aes_256_cbc()) 
        - EVP_PKEY_size(t_public_key),
        0);
        
    encr_session_key = messages[0];
    iv = messages[1];
    peer_sign = messages[2];
    ciphertext = messages[3];
    // Verify sign
    ERR(verify_sign = mconcat((Message<unsigned char>*)tm_public_key, ciphertext, encr_session_key, iv, NULL), destroy);
    ERR(digital_signature -> verify(verify_sign, peer_sign, 
        peer_public_key), destroy);
    ERR(asym = new AsymmetricEncryption(EVP_aes_256_cbc()), destroy);
    ERR(asym -> decrypt(ciphertext, encr_session_key, iv, t_private_key), destroy);
    // Symmetric key
    ERR(ret = asym -> getDecrypted(), destroy);
    cout << "Key negotiation done!" << endl;
destroy:
    if (received_message) {
        delete received_message;
    }
    if (nonce) {
        delete nonce;
    }
    if (peer_sign) {
        delete peer_sign;
    }
    if (peer_public_key) {
        EVP_PKEY_free(peer_public_key);
    }
    if (rsa) {
        RSA_free(rsa);
    }
    if (t_private_key) {
        EVP_PKEY_free(t_private_key);
    }
    if (t_public_key) {
        EVP_PKEY_free(t_public_key);
    }
    if (tm_public_key) {
        delete tm_public_key;
    }
    if (to_sign) {
        delete to_sign;
    }
    if (sign) {
        delete sign;
    }
    if (session_key) {
        delete session_key;
    }
    if (ciphertext) {
        delete ciphertext;
    }
    if (encr_session_key) {
        delete encr_session_key;
    }
    if (iv) {
        delete iv;
    }
    if (digital_signature) {
        delete digital_signature;
    }
    if (asym) {
        delete asym;
    }
    return ret;
}


// Client and server exchange encrypted and authenticated messages.
// Now the symmetric key is chosen.
// To guarantee integrity and authentication the communication uses
// Authenticated encryption with associated data (AEAD).
// Possible request:
//  1: server sends to the client ondestroy users.
//  2: client send a chat request to the server, so the server forward
//     this request to the peer chat socket and the client requester is 
//     put in wait for response.
//  3: if 2 peer are agree to start a chat, they negotiate a symmetric
//     key and they begin to chat.
//  4: after a chat session, server disconnect the 2 peers.
int request(User *user) {  
    int ret = 0;  
    // Read from stdin
    string input;
    // Vector of string to save online users
    vector<string> names;
    // Symmetric key with server
    Message<unsigned char> *sym_server_key = NULL;
    // Decrypted ciphertext sent by server (online users able to chat)
    Message<unsigned char> *plaintext = NULL;
    // plaintext in C string
    char *c_plaintext = NULL; 

    // Get the server symmetric session key
    ERR(sym_server_key = user -> getServerSymKey(), destroy);
    for (;;) {
        names.clear();
        mdestroy(1, &plaintext);
        bdestroy(1, &c_plaintext);
        // Server AEAD message
        ERR(plaintext = recv_aead_decrypt_message(user, sym_server_key), destroy);
        ERR(c_plaintext = (char*)plaintext -> getMessage(), destroy);
        if (strncmp(c_plaintext, "Already in", 10) == 0) {
            cout << c_plaintext << endl;
            exit(EXIT_FAILURE);
        }
        // Possible operations for a client
        print_menu(plaintext);
        // Tokenize the online peers received from server
        names = tokenize_username(c_plaintext);
        // Read client operation from stdin
        input = read_operation(user);
        // Show incoming requests
        if (input.compare("requests") == 0) {
            // If some input error, exit
            if (!handle_chat_requests(user, sym_server_key)) {
                puts("HANDLE");
                //break;
            }
        // User wants to logout
        } else if (input.compare("exit") == 0) {
            ERR(send_aead_encrypt_message(input, user, user -> getMainSocket(), sym_server_key), destroy);
            break;
        // User wants to start a chat: search if input is a valid peer username
        } else if (send_chat_request(user, sym_server_key, names, input)) {
            //break;
        }
    }
    ret = 1;
destroy:
    mdestroy(2, &plaintext, &sym_server_key);
    bdestroy(1, &c_plaintext);
    return ret;
}

// Server sends to the peer the public key of other pert, 
// then the symmetric key negotiations starts.
// After it is completed, a 'reader' thread is created that receive incoming messages.
// This thread instead wait for user input and send the message to the server
// that forwward the message to other peer.
// Then the chat begins.
// Every message is sent to the server, it forward the message to other peer.
// Return 1 if the chat ends with correct word "__exit__" by one of the two
// peer, 0 in case of some error.
int chatty(User *user, const char *peer_username) {
    // Return value
    int ret = 0;  
    // Tid of reader thread
    pthread_t tid;
    // Struct argument of reader thread
    struct client *client = NULL;
    // Symmetric key with server
    Message<unsigned char> *sym_server_key = NULL;
    // Symmetric key fir chat
    Message<unsigned char> *sym_chat_key = NULL;
    Message<unsigned char> *to_send = NULL;
    Message<unsigned char> *dummy = NULL;
    // Decrypted ciphertext sent by server (peer public key, peer messages...)
    Message<unsigned char> *plaintext = NULL;
    // Peer public key
    EVP_PKEY *peer_pubkey = NULL;
    string input;
    ERR(sym_server_key = user -> getServerSymKey(), destroy);
    // Peer public key
    ERR(plaintext = recv_aead_decrypt_message(user, sym_server_key), destroy);
    ERR(peer_pubkey = get_public_key_from_message(plaintext), destroy);

    mdestroy(1, &plaintext);

    // Who sent chat requests choose the symmetric key, so he waits
    // the nonce from other peer.
    ERR(sym_chat_key = user -> getIsSender() ? 
        key_negotiation_new(user, peer_pubkey) :
        key_negotiation_new(peer_pubkey, user), destroy);
    
    // Initialize struct
    ERR(client = (struct client*)malloc(sizeof(struct client)), destroy);
    ERR(client -> user = user, destroy);
    ERR(client -> key = sym_chat_key, destroy);
    client -> peer_username = peer_username;
    
    // Create reader thread
    pthread_create(&tid, NULL, reader, (void *)client);

    // Dummy byte for the server
    ERR(dummy = new Message<unsigned char>((unsigned char*)"C", 1), destroy);

    cout << "Chat with " << peer_username << " starts.\nType '__exit__' to logout." << endl;
    for (;;) {
        // 1: Read msg from peer1 and forword it to peer2
        cout << "> ";
        getline(cin, input);
        input = input.empty() ? " " : input;
        // Exit from chat
        if (KILL) {
            KILL = 0;
            requests.clear();
            user -> resetChatCounter();
            user -> setIsSender(false);
            ERR(send_aead_encrypt_message("reload", user,user -> getMainSocket(), sym_server_key), destroy);
            break;
        }
        // Increase send counter
        user -> increasePeerSendCounter();
        // Build AEAD message for the peer
        ERR(to_send = mk_aead_message(input, user -> getPeerSendCounter(), sym_chat_key), destroy);

        // If input == "__exit__" client logout from server
        if (input.compare("__exit__") == 0) {
            ERR(send_aead_encrypt_message(input, user, user -> getMainSocket(), sym_server_key), destroy);
            requests.clear();
            user -> resetChatCounter();
            user -> setIsSender(false);
            break;
        }
        // send: [iv_S, counter_S, tag_S, [ct_Peer]]
        ERR(send_aead_encrypt_message(to_send, user, user -> getMainSocket(), sym_server_key), destroy);
    }
    ret = 1;
destroy:
    requests.clear();
    pthread_join(tid, NULL);
    return ret;
}

// Before the chat starts, a 'reader' thread is created that receive 
// incoming chat messages.
void *reader(void *arg) {
    // Struct with user socket, peer username and symmetric chat key
    struct client *client = NULL;
    // Decrypted ciphertext forworded by server
    Message<unsigned char> *plaintext = NULL;
    Message<unsigned char> *message = NULL;
    Message<unsigned char> *server_sym_key = NULL; 
    ERR(client = (struct client *)arg, destroy);
    ERR(server_sym_key = client -> user -> getServerSymKey(), destroy);
    for (;;) {
        ERR(message = recv_aead_decrypt_message(client -> user, server_sym_key), destroy);
        if (strncmp((char*)message -> getMessage(), "__Exit__", 8) == 0) {
            puts("Other peer leaves the chat. Type ENTER to return to lobby!");
            KILL = 1;
            // Build AEAD message for server
            ERR(send_aead_encrypt_message("__Exit__", client -> user, client -> user -> getMainSocket(), server_sym_key), destroy);
            break;
        }
        if (strncmp((char*)message -> getMessage(), "__exit__", 8) == 0) {
            break;
        }
        ERR(plaintext = get_aead_msg(client -> user -> getPeerRecvCounter(), message, client -> key), destroy);
        client -> user -> increasePeerRecvCounter();
        cout << endl << client -> peer_username << ": ";
        print_string(plaintext);
        cout << "> ";
        fflush(stdout);
    }
destroy:
    pthread_exit(EXIT_SUCCESS);
}

// Split online usernames and put them in a vector
vector<string> tokenize_username(char *s) {
    string token;
    vector<string> names;
   // Tokenize usernames
    stringstream check1(s);
    // Tokenizing w.r.t. escape '\n'
    while(getline(check1, token, '\n')) {
        names.push_back(token);
    }
    return names;
}

// Print possible operation of client
void print_menu(Message<unsigned char> *m) {
    puts("\nOnline users:");
    print_string(m);
    puts("Type 'username' to send a chat request.");
    puts("Type 'reload' to refresh online users.");
    puts("Type 'requests' to see incoming chat requests.");
    puts("Type 'exit' to logout.");
}

// Read client input while it is a valid operation.
string read_operation(User *user) {
    string input;
    do {
        cout << "> ";
        getline(cin, input);
        if (input.compare(user -> getUsername()) == 0 
            || input.find("accept") != string::npos 
            || input.find("refuse") != string::npos) {
            puts("Invalid operation.");
        }
    } while (
            input.compare(user -> getUsername()) == 0 
        || input.find("accept") != string::npos 
        || input.find("refuse") != string::npos);
    return input;
}

// Handle chat requests
int handle_chat_requests(User *user, Message<unsigned char> *sym_server_key) {
    int ret = 0;
    // Read from stdin / token
    string input, operation, token, peer_name;
    bool found = false;
    // counter used when tokenize user input when he asks for chat requests.
    // The expected format is "accept/refuse username", so this c must be 2
    int c = 0;
    char *peer_username = NULL;
    pthread_mutex_lock(&mux);
    // No chat requests
    if (requests.empty()) {
        puts("No requests.");
        pthread_mutex_unlock(&mux);
        ERR(send_aead_encrypt_message("reload", user, user -> getMainSocket(), sym_server_key), destroy);
    } else {
        // Print chat requests
        for (long unsigned int i = 0; i < requests.size(); i++) {
            puts(requests[i].c_str());
        }
        pthread_mutex_unlock(&mux);
        // Client asks to user to insert one of this operations
        puts("Type 'accept username' or 'refuse username' of peer.");
        cout << "> ";
        getline(cin, input);

        // Tokenize input
        stringstream check1(input);
        // First word is operation, second one username
        while(getline(check1, token, ' ')) {
            (c++ == 0) ? operation = token : peer_name = token;
        }

        // Operation must be composed by exactly 2 words:
        // accpet/refuse and an username
        if (c != 2 || (operation.compare("accept") != 0 && operation.compare("refuse") != 0)) {
            puts("Invalid operation.");
            ERR(send_aead_encrypt_message("reload", user, user -> getMainSocket(), sym_server_key), destroy);
            ret = 1;
            goto destroy;
        }
        // Send to the server "accept username" to accept a chat request
        // or "refuse username" to refuse a chat request
        // Check the peer username (if user has inserted a valid username)
        pthread_mutex_lock(&mux);
        for (long unsigned int i = 0; i < requests.size(); i++) {
            // User found in the list
            if (requests[i].compare(peer_name) == 0) {
                found = true;
                // Refused operation
                if (operation.compare("refuse") == 0) {
                    // Remove peer request if it is declined
                    requests.erase(requests.begin() + i);
                    pthread_mutex_unlock(&mux);
                    ERR(send_aead_encrypt_message(input, user, user -> getMainSocket(), sym_server_key), destroy);
                    break;
                } else {
                    // Request accepted
                    peer_username = strdup((char*)requests[i].c_str());
                    pthread_mutex_unlock(&mux);                    
                    ERR(send_aead_encrypt_message(input, user, user -> getMainSocket(), sym_server_key), destroy);
                    //pthread_join(requester_tid, NULL);
                    ERR(chatty(user, peer_username), destroy);
                    ret = 1;
                }
            }
        }
        pthread_mutex_unlock(&mux);
        // peer username inserted isn't valid
        if (!found) {
            // Request from user inserted not exists
            cout << "No request from " << peer_name << endl;
            // Server will re-send list of online users
            ERR(send_aead_encrypt_message("reload", user, user -> getMainSocket(), sym_server_key), destroy);
        }
    }
    ret = 1;
destroy:
    pthread_mutex_unlock(&mux);
    bdestroy(1, &peer_username);
    return ret;
}

// If user has inserted a valid username of peer, 
// send to him through server the chat request
int send_chat_request(User *user, Message<unsigned char> *sym_server_key, vector<string> names, string input) {
    int ret = 0;
    // If inserted name is valid or not
    bool found = false;
    // Response from server
    Message<unsigned char> *plaintext = NULL;
    // Response in char *format
    char *c_plaintext = NULL, *peer_username = NULL;
    string s = "accept ";
    pthread_mutex_lock(&mux);
    // Search if user is alreqdy in chat list
    for (long unsigned int i = 0; i < requests.size(); i++) {
        // User found in the list
        if (requests[i].compare(input) == 0) {
            // Request accepted
            peer_username = strdup((char*)requests[i].c_str());
            pthread_mutex_unlock(&mux);                    
            ERR(send_aead_encrypt_message(s.append(input), user, user -> getMainSocket(), sym_server_key), destroy);
            ERR(chatty(user, peer_username), destroy);
            ret = 1;
            // When come back from chatty, logout
            goto destroy;
        }
    }    
    pthread_mutex_unlock(&mux);                    

    // Search requested peer in the names list
    for (auto u : names) {
        // Username found
        if (u.compare(input) == 0) {
            found = true;
            // Server will forward the request to the peer
            ERR(send_aead_encrypt_message(input, user, user -> getMainSocket(), sym_server_key), destroy);
            puts("Wait for response...");
            ERR(plaintext = recv_aead_msg(user, user -> getMainSocket(), 
                user -> getServerRecvCounter(), sym_server_key), destroy);
            pthread_mutex_lock(&mux);
            user -> increaseServerRecvCounter();
            pthread_mutex_unlock(&mux);
            ERR(c_plaintext = (char*)plaintext -> getMessage(), destroy);
            // Check if peer has accepted the chat request
            if (strncmp(c_plaintext, "refused", 7) == 0) {
                puts("Chat request refused from peer.");
                ERR(send_aead_encrypt_message("refused", user, user -> getMainSocket(), sym_server_key), destroy);
                break;
            // Request accepted, peer username is sent by server
            } else if (strncmp(u.c_str(), c_plaintext, u.length()) == 0) {
                // Chat request accepted                        
                ERR(peer_username = (char*)plaintext -> getMessage(), destroy);
                user -> setIsSender(true);
                ERR(send_aead_encrypt_message("start", user, user -> getMainSocket(), sym_server_key), destroy);
                //pthread_join(requester_tid, NULL);
                ERR(chatty(user, peer_username), destroy);
                // When come back from chatty, logout
                ret = 1;
                break;
            } else if (strncmp(c_plaintext, "ref", 3) == 0) {
                puts("User is waiting for another chat.");
                break;
            } else {
                // Peer nomore online
                puts("User nomore online.");
                ERR(send_aead_encrypt_message("reload", user, user -> getMainSocket(), sym_server_key), destroy);
                break;
            }
        }
    }
    if (!found) {
        ERR(send_aead_encrypt_message("reload", user, user -> getMainSocket(), sym_server_key), destroy);
    }
destroy:
    return ret;
}

// Increase the counter of user then send message with AEAD
int send_aead_encrypt_message(string input, User *user,  int socket, Message<unsigned char> *key) {
    int ret = 0;
    // Send to the client the online users
    pthread_mutex_lock(&mux);
    user -> increaseServerSendCounter();
    ERR(send_aead_msg(input, socket,
        user -> getServerSendCounter(), key), destroy);
    pthread_mutex_unlock(&mux);
    ret = 1;
destroy:
    return ret;
}

// Increase the counter of user then send bytes message with AEAD
int send_aead_encrypt_message(Message<unsigned char> *plaintext, User *user,  int socket, Message<unsigned char> *key) {
    int ret = 0;
    pthread_mutex_lock(&mux);
    user -> increaseServerSendCounter();
    ERR(send_aead_msg(plaintext, socket,
        user -> getServerSendCounter(), key), destroy);
    pthread_mutex_unlock(&mux);
    ret = 1;
destroy:
    return ret;
}

// Read message AEAD; Increase the recv counter of user
Message<unsigned char>* recv_aead_decrypt_message(User *user, Message<unsigned char> *key) {
    Message<unsigned char> *plaintext = NULL;
    ERR(plaintext = recv_aead_msg(user -> getMainSocket(), 
        user -> getServerRecvCounter(), key), destroy);
    pthread_mutex_lock(&mux);
    user -> increaseServerRecvCounter();
    pthread_mutex_unlock(&mux);
destroy: 
    return plaintext;
}