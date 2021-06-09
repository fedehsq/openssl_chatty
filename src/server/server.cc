#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>
#include <stdarg.h>
#include <unordered_map>
#include <signal.h>

#include "../ssl_utils/ssl_utils.cc"
#include "../utils/utils.cc"
#include "../digital_signature/DigitalSignature.cc"
#include "../asymmetric_encription/AsymmetricEncryption.cc"
using namespace std;

//#define DEBUG
// Ip address of service
#define ADDRESS "127.0.0.1"
// Main port of the service
#define PORT 8080
// Chat requests port of the service
#define REQ_PORT 8081

// Server has 2 different TCP connection for each client, 
// One is called "main" connection and the other one is only to
// forward chat requests by client.

// Public and private keys of server, 
// they don't need lock beacuse they are only reading variables
EVP_PKEY *server_private_key;
EVP_PKEY *server_public_key;

// To write/read the users structure
pthread_mutex_t mux = PTHREAD_MUTEX_INITIALIZER;

// Key is username, value is User object
unordered_map<string, User*> users; 

// Client and Server negotiate a session key to use for encrypt
// guarantee perfect forward secrecy, following this schema:
//  1: Client sends a R random to server (nonce) signed [R, signed R]
//  2: Server generates a temporary public and private RSA keys (TpubK, TprivK)
//  3: Server sends [[R, TpubK]signed PrvK, Tpubk]
//  4: Client verifies message and choose a random session K
//  5: Client encrypts this K with Tpubk and send it to the Server [E(k)]
//     Real message is: [E(k), iv, iv signed, ct (session key)]
//  Client and Server use this K to encrypt.
//  The session key is returned. In case of some errors, NULL is returned.
Message<unsigned char>* key_generation(int main_socket, int chat_socket, User **user);

// Client and server exchange encrypted and authenticated messages.
// Now the symmetric key is chosen.
// To guarantee integrity and authentication the communication uses
// Authenticated encryption with associated data (AEAD).
// Possible request:
//  1: server sends to the client online users.
//  2: client send a chat request to the server, so the server forward
//     this request to the peer chat socket and the client requester is 
//     put in wait for response.
//  3: if 2 peer are agree to start a chat, they negotiate a symmetric
//     key and they begin to chat.
//  4: after a chat session, server disconnect the 2 peers.
/*
-----------------------------------------------------------------------
| clear_header (IV) | encrypted_header (IV) | encrypted_payload (msg) |
-----------------------------------------------------------------------
|       AAD         |                     ENCRYPTION                  |
-----------------------------------------------------------------------
|                           AUTHENTICATION                            |
-----------------------------------------------------------------------
*/
int request(User *requester, Message<unsigned char> *key);

// Increase the counter of user then send message with AEAD on socket socket
int send_aead_encrypt_message(string input, User *user, int socket, 
    Message<unsigned char> *key);

// Increase the counter of user then send message with AEAD on socket socket
int send_aead_encrypt_message(Message<unsigned char> *plaintext, 
    User *user,  int socket, Message<unsigned char> *key);

// Read message AEAD; Increase the recv counter of user
Message<unsigned char>* recv_decrypt_aead_message(User *user, 
    Message<unsigned char> *key);

// Delete user from map
void delete_user(User* u);

// Return the list of user as string removing the current one
string get_users_to_string(User *user);

// When a client connects, server starts a thread to manage client sessions.
void *worker(void *arg);

// Takes two user and it starts their chat after session key negotiations.
// First of all, it forward to peers the respective public keys.
// Then, it starts to forward messages.
int chatty(User *requester, User *accepter);

int main() {
    int main_server_socket, main_sock_size;
    int chat_server_socket, chat_sock_size;
    long main_client_socket, chat_client_socket;
    // Two client sockets
    long sockets[2];
	struct sockaddr_in client, chat_client, server, chat_server;

    X509 *server_certificate = NULL;

	// Create TCP socket
	N_ERR((main_server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)), destroy);

    // Create TCP socket
	N_ERR((chat_server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)), destroy);
	
	// Prepare the main server structure
    bzero((char *)&server, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_port = htons(8080);
	
	// Prepare the chat server structure
    bzero((char *)&chat_server, sizeof(chat_server));
	chat_server.sin_family = AF_INET;
	chat_server.sin_addr.s_addr = inet_addr("127.0.0.1");
	chat_server.sin_port = htons(8081);

	// Bind server 
	N_ERR(bind(main_server_socket, (struct sockaddr *)&server , sizeof(server)), destroy);
	N_ERR(bind(chat_server_socket, (struct sockaddr *)&chat_server , sizeof(server)), destroy);
    N_ERR(listen(main_server_socket, 20), destroy);
    N_ERR(listen(chat_server_socket, 20), destroy);

    // Read keys
    ERR(server_private_key = read_private_key_from_file("Server_key.pem"), destroy);
    ERR(server_certificate = read_certificate_from_file("Server_cert.pem"), destroy);
    ERR(server_public_key = X509_get_pubkey(server_certificate), destroy);

    // Loop waiting for client connection
    // When a client connects, start a worker thread
    pthread_t tid;
    while (1) {        
        puts("Listen for incoming connection...");
        main_sock_size = sizeof(client);
        chat_sock_size = sizeof(chat_client);
        N_ERR((main_client_socket = accept(main_server_socket, 
            (struct sockaddr *)&client, (socklen_t*)&main_sock_size)), destroy);
        N_ERR((chat_client_socket = accept(chat_server_socket, 
            (struct sockaddr *)&chat_client, (socklen_t*)&chat_sock_size)), destroy);
        puts("Connection arrived.");

        sockets[0] = main_client_socket;
        sockets[1] = chat_client_socket;
        
        NO_0_ERR(pthread_create(&tid, NULL, worker, (void *)sockets), destroy);
    }
destroy:
    pthread_mutex_destroy(&mux);
    EVP_PKEY_free(server_private_key);
    X509_free(server_certificate);
    EVP_PKEY_free(server_public_key);
    return 0;       
}

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
Message<unsigned char>* key_generation(int main_socket, int chat_socket, User **user) {
    // Return value: key if always go well
    Message<unsigned char>* ret = NULL;
    // Entire socket message received
    Message<unsigned char> *received_message = NULL;
    // 1: Clear nonce
    Message<unsigned char> *nonce = NULL;
    // Client username
    Message<unsigned char> *username = NULL;
    // Client username in c
    char *c_username = NULL;
    // Client pub key path
    string client_pub_key;
    // 1, 5: Peer sign
    Message<unsigned char> *peer_sign = NULL;
    // Message to verifies sign
    Message<unsigned char> *verify_sign = NULL;
    // Peer public key
    EVP_PKEY *peer_public_key = NULL;
    
    // 2: Generate RSA temporary private and public keys
    RSA *rsa = NULL;
    // Ephimeral RSA private key
    EVP_PKEY *t_private_key = NULL;
    // Ephimeral RSA public key
    EVP_PKEY *t_public_key = NULL;
    // Server certificate
    X509 *server_certificate = NULL;
    // Server certificate as bytes
    Message<unsigned char> *message_certificate = NULL;

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
   
    // To send to client over socket
    unsigned char *to_send = NULL;
    int size_to_send;

    // 1: Client sends a R random and username to the server: [nonce, username]
    if ((messages = read_split_message(main_socket)).empty()) {
        goto destroy;
    }
    // Assign items
    nonce = messages[0];
    username = messages[1];
    print_string(username);
    
    ERR(c_username = (char *)username -> getMessage(), destroy);
    client_pub_key = c_username;
    // Get client public key and verify its sign
    ERR(peer_public_key = read_public_key_from_file(client_pub_key.append(".pem").c_str()), destroy);

    // 2: Server generates a temporary public and private RSA key (TpubK, TprivK)
    ERR(rsa = generate_RSA_keys(), destroy);
    ERR(t_private_key = get_private_key(rsa), destroy);
    ERR(t_public_key = get_public_key(t_private_key), destroy);

    // Read certificate from file
    ERR(server_certificate = 
        read_certificate_from_file("Server_cert.pem"), destroy);
    // Store the certificate with its len
    ERR(message_certificate = 
        certificate_to_bytes(server_certificate), destroy);

    // 3: Server sends [[R, TpubK]signed PrvK, Tpubk, cert]
    digital_signature = new DigitalSignature();
    ERR(tm_public_key = get_public_key_to_message(t_public_key), destroy);
    ERR(to_sign = mconcat(nonce, tm_public_key, NULL), destroy);
    ERR(digital_signature -> sign(to_sign, "Server_key.pem"), destroy);
    ERR(sign = digital_signature -> getSign(), destroy);

    ERR(to_send = concat(&size_to_send, sign, tm_public_key, message_certificate, NULL), destroy);
    ERR(send(main_socket, to_send, size_to_send, 0), destroy);

    // Real message to received is: [E(K), iv, <sign>, ct(session key)]
    delete received_message;
    received_message = NULL;
    if ((messages = read_split_message(main_socket)).empty()) {
        goto destroy;
    }
    encr_session_key = messages[0];
    iv = messages[1];
    delete peer_sign;
    peer_sign = NULL;
    peer_sign = messages[2];
    ciphertext = messages[3];
    // Verify sign
    ERR(verify_sign = mconcat((Message<unsigned char>*)tm_public_key, 
        ciphertext, encr_session_key, iv, NULL), destroy);
    ERR(digital_signature -> verify(verify_sign, peer_sign, 
        peer_public_key), destroy);
    ERR(asym = new AsymmetricEncryption(EVP_aes_256_cbc()), destroy);
    ERR(asym -> decrypt(ciphertext, encr_session_key, iv, 
        t_private_key), destroy);
    // Symmetric key
    ERR(ret = asym -> getDecrypted(), destroy);
    // If user is already in:
    *user = new User(c_username, main_socket, chat_socket, peer_public_key);
    if (users.find((char*)username->getMessage()) != users.end()) {
        puts("Already in");
        send_aead_encrypt_message(
            new Message<unsigned char>((unsigned char*)"Already in", 10), 
            *user, main_socket, ret);
        pthread_exit(NULL);
    }
    cout << "Key negotiation with " << (*user) -> getUsername() << " done!" << endl;
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
    if (to_send) {
        memset(to_send, 0, size_to_send);
        free(to_send);
    }
    return ret;
}

// When a client connects, thread sends to him server certificate
void *worker(void *arg) {
    long *sockets = (long*)arg;
    int main_client_socket = sockets[0];
    int chat_client_socket = sockets[1];
    User *user = NULL;
    Message<unsigned char> *k = NULL;
    ERR(k = key_generation(main_client_socket, chat_client_socket, &user), destroy);
    user -> setServerSymKey(k);
    pthread_mutex_lock(&mux);
    users[user -> getUsername()] = user;
    pthread_mutex_unlock(&mux);
    ERR(request(user, k), destroy);
destroy:
    if (user) {
        delete user;
    }
    if (k) {
        delete k;
    }
    close(main_client_socket);
    close(chat_client_socket);
    pthread_exit(EXIT_SUCCESS);
}

// Client and server exchange encrypted and authenticated messages.
// Now the symmetric key is chosen.
// To guarantee integrity and authentication the communication uses
// Authenticated encryption with associated data (AEAD).
// Possible request:
//  1: server sends to the client online users.
//  2: client send a chat request to the server, so the server forward
//     this request to the peer chat socket and the client requester is 
//     put in wait for response.
//  3: if 2 peer are agree to start a chat, they negotiate a symmetric
//     key and they begin to chat.
//  4: after a chat session, server disconnect the 2 peers.
int request(User *requester, Message<unsigned char> *key) {
    int ret = 0;  
    // Read from stdin
    string input;
    // Requester operation requested
    string cpp_message;
    char *c_message = NULL;
    // To extract username of requested peer for chat
    string peer_username;
    // Chat user requested
    User *peer = NULL;
    // Peer sym key with server
    Message<unsigned char> *peer_server_sym_key = NULL;
    // Decrypted ciphertext
    Message<unsigned char> *plaintext = NULL;
    // Every username is separated with an empty char ' '
    string online_users;
    for (;;) {
        // Get online users
        online_users = get_users_to_string(requester);
        // Send users to requester
        ERR(send_aead_encrypt_message(online_users, requester, requester -> getMainSocket(), key), destroy);
        // Client AEAD message
        ERR(plaintext = recv_decrypt_aead_message(requester, key), destroy);
        print_string(plaintext);
        // Check which operation is requested
        c_message = (char*)plaintext -> getMessage();
        cpp_message = c_message;
        mdestroy(1, &plaintext);
        bdestroy(1, &c_message);
        // User wants to logout
        if (cpp_message.compare("exit") == 0) {
            // Tells to chat requester to shutdown
            ERR(send_aead_encrypt_message("exit", requester, 
                requester -> getChatSocket(), key), destroy);
            // Tells to other user the negative response
            vector<User*> req = requester -> getRequests();
            for (auto r : req) {
                ERR(send_aead_encrypt_message("refused", r, 
                    r -> getMainSocket(), r->getServerSymKey()), destroy);
            }
            // Remove user from users
            delete_user(requester);
            break;
        }
        // CLIENT WANTS TO START A CHAT, HE WAITS FOR RESPONSE
        // If c_message is a element of users, the client wants to start a chat
        pthread_mutex_lock(&mux);
        if (users.find(cpp_message) != users.end()) {
            peer = users[cpp_message];
            if (peer->getIsSender()) {
                pthread_mutex_unlock(&mux);
                ERR(send_aead_encrypt_message("ref", requester, 
                    requester -> getMainSocket(), key), destroy);
                continue;   
            }
            requester -> setIsSender(true);
            // Send to this peer requester username encrypted and put requester in list of req
            peer -> insertRequest(requester);
            ERR(peer_server_sym_key = peer -> getServerSymKey(), destroy);
            pthread_mutex_unlock(&mux);
            ERR(send_aead_encrypt_message(requester -> getUsername(), 
                peer, peer -> getChatSocket(), peer_server_sym_key), destroy);
            mdestroy(1, &peer_server_sym_key);
            // This client waits for peer response
            ERR(plaintext = recv_decrypt_aead_message(requester, key), destroy);
            // Check for peer response
            ERR(c_message = (char*)plaintext -> getMessage(), destroy);
            // If response is != refuse, peer has accepted the chat
            if (strncmp(c_message, "refuse", 6) != 0) {
                delete_user(requester);
                // Tells to other user the negative response
                vector<User*> req = requester -> getRequests();
                for (auto r : req) {
                    if (r -> getUsername().compare(peer -> 
                        getUsername()) != 0) {
                        ERR(send_aead_encrypt_message("refused", r, 
                            r -> getMainSocket(), r->getServerSymKey()), 
                            destroy);
                    }
                }
                // Tells to chat requester to shutdown
                ERR(chatty(requester, peer), destroy);
                requester -> eraseRequests();
                continue;
            // Request refused
            } else {
                requester -> setIsSender(false);
                mdestroy(1, &plaintext);
                bdestroy(1, &c_message);
                continue;
            }
        }
        pthread_mutex_unlock(&mux);
        // If message contains 'accept', requester has accepted a chat
        if (cpp_message.find("accept") != string::npos) {
            peer_username = cpp_message.substr(7);
            pthread_mutex_lock(&mux);
            peer = users[peer_username];
            // Remove from users
            users.erase(requester -> getUsername());
            // Send to peer the positive response (username)
            ERR(peer_server_sym_key = peer -> getServerSymKey(), destroy);
            pthread_mutex_unlock(&mux);
            // Tells to other user the negative response
            vector<User*> req = requester -> getRequests();
            for (auto r : req) {
                if (r->getUsername().compare(peer->getUsername()) != 0) {
                    ERR(send_aead_encrypt_message("refused", r, 
                        r -> getMainSocket(), r->getServerSymKey()), destroy);
                }
            }
            ERR(send_aead_encrypt_message(requester -> getUsername(), 
                peer, peer -> getMainSocket(), peer_server_sym_key), destroy);   
            mdestroy(1, &peer_server_sym_key);
            ERR(chatty(requester, peer), destroy);
            requester -> eraseRequests();
            continue;
        // Requester has refused the chat request
        } else if (cpp_message.find("refuse") != string::npos) {
            peer_username = cpp_message.substr(7);
            pthread_mutex_lock(&mux);
            peer = users[peer_username];
            // Send to peer the negative response
            ERR(peer_server_sym_key = peer -> getServerSymKey(), destroy);
            pthread_mutex_unlock(&mux);
            requester->removeRequest(peer);
            ERR(send_aead_encrypt_message("refused", peer, peer -> getMainSocket(), peer_server_sym_key), destroy);
            mdestroy(1, &peer_server_sym_key);
        }
    }
    ret = 1;
destroy:
    if (plaintext) {
        delete plaintext;
    }
    if (peer_server_sym_key) {
        delete peer_server_sym_key;
    }
    if (c_message) {
        memset(c_message, 0, strlen(c_message));
        free(c_message);
    }
    return ret;
}

// Takes two user and it starts their chat after session key negotiations.
// First of all, it forward to peers the respective public keys.
// Then, it starts to forward messages.
int chatty(User *peer1, User *peer2) {
    int ret = 0;
    // Forwarding message from peer1 to peer2
    // Server tries to decrypts messages
    Message<unsigned char> *received = NULL;
    // Peer1 client's key shared with server
    Message<unsigned char> *peer1_server_sym_key = NULL;
    Message<unsigned char> *peer2_server_sym_key = NULL;
    // Peer2 client's public key
    EVP_PKEY *peer2_pkey = NULL;
    // Peer2 public key as string to forword to peer1
    char *peer2_str_pubk = NULL;
    // Encrypted message to send
    int socket1, socket2;
    // Convert public key to string for sending it over socket to other peer
    // This key is needed to start the symmetric key negotiations
    ERR(peer2_pkey = peer2 -> getPublicKey(), destroy);
    ERR(peer2_str_pubk = get_public_key_to_string(peer2_pkey), destroy);
    // Get the keys to use for send encrypted message from server to peer
    ERR(peer1_server_sym_key = peer1 -> getServerSymKey(), destroy);
    ERR(peer2_server_sym_key = peer2 -> getServerSymKey(), destroy);
    // Send the peer2 public key to peer1
    ERR(send_aead_encrypt_message(peer2_str_pubk, peer1, peer1 -> getMainSocket(), peer1_server_sym_key), destroy);
    socket1 = peer1 -> getMainSocket();
    socket2 = peer2 -> getMainSocket();
    // Start negotiations and then the chat
    for (;;) {
        // 1: Receive msg from peer1 and forword it to peer2 if verfication is ok
        ERR(received = recv_decrypt_aead_message(peer1, peer1_server_sym_key), destroy);
        print_bytes(received);
        cout << peer1 -> getUsername() << " recv_c: " << peer1 -> getServerRecvCounter() << endl;
        cout << peer1 -> getUsername() << " send_c: " << peer1 -> getServerSendCounter() << endl;
        // This peer exits by other peer logout
        if (strncmp((char*)received -> getMessage(), "__Exit__", 8) == 0) {
            cout << peer1 -> getUsername() << " logout." << endl;
            // Client AEAD message
            ERR(received = recv_decrypt_aead_message(peer1, peer1_server_sym_key), destroy);
            break;
        }
    
        // This peer decides to logout
        if (strncmp((char*)received -> getMessage(), "__exit__", 8) == 0) {
            ERR(send_aead_encrypt_message("__exit__", peer1, 
                socket1, peer1_server_sym_key), destroy);
            ERR(send_aead_encrypt_message("__Exit__", 
                peer2, socket2, peer2_server_sym_key), destroy);
            cout << peer1 -> getUsername() << " logout." << endl;
            break;
        }
        ERR(send_aead_encrypt_message(received, peer2, socket2, 
            peer2_server_sym_key), destroy);
    }
    ret = 1;
    pthread_mutex_lock(&mux);
    users[peer1 -> getUsername()] = peer1;
    peer1 -> resetChatCounter();
    peer1 -> setIsSender(false);
    peer1 -> eraseRequests();
    
    pthread_mutex_unlock(&mux);
destroy:
    if (received) {
        delete received;
    }
    if (peer1_server_sym_key) {
        delete peer1_server_sym_key;
    }
    if (peer2_str_pubk) {
        memset(peer2_str_pubk, 0, strlen(peer2_str_pubk));
        free(peer2_str_pubk);
    }
    if (peer2_pkey) {
        EVP_PKEY_free(peer2_pkey);
    }
    return ret;
}

// Increase the counter of user then send bytes message with AEAD
int send_aead_encrypt_message(Message<unsigned char> *plaintext,
    User *user,  int socket, Message<unsigned char> *key) {
    
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

// Increase the counter of user then send message with AEAD
int send_aead_encrypt_message(string input, User *user,  int socket, 
    Message<unsigned char> *key) {
    
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

// Read message AEAD; verifys authenticity; increase the recv counter of user and  
Message<unsigned char>* recv_decrypt_aead_message(User *user, 
    Message<unsigned char> *key) {
    
    Message<unsigned char> *plaintext = NULL;
    ERR(plaintext = recv_aead_msg(user -> getMainSocket(), 
        user -> getServerRecvCounter(), key), destroy);
    pthread_mutex_lock(&mux);
    user -> increaseServerRecvCounter();
    pthread_mutex_unlock(&mux);
destroy: 
    return plaintext;
}

// Delete user from map
void delete_user(User* u) {
    pthread_mutex_lock(&mux);
    users.erase(u -> getUsername());
    pthread_mutex_unlock(&mux);
}

// Return the list of user as string removing the actual one
string get_users_to_string(User *requester) {
    string online_users = "";
    // Get the online users
    pthread_mutex_lock(&mux);
    for (auto u : users) {
        if (u.second -> getMainSocket() != requester -> getMainSocket()) {
            online_users.append(u.first).append("\n");
        }
    }
    pthread_mutex_unlock(&mux);
    if (online_users.compare("") == 0) {
        online_users = "No users online";
    }
    return online_users;
}