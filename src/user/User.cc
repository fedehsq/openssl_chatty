#include "User.h"

// Check for errors
#define U_ERR(res, ret) { \
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
#define ERR_U(res) { \
    if (!(res)) { \
        std::cerr << "In " << __FILE__ << " error on line " << __LINE__ << ": "; \
        std::cerr << strerror(errno) << "\n"; \
        ERR_print_errors_fp(stderr); \
        clean(); \
        errno = 0; \
    } \
}

User::User(std::string username, int main_socket, int chat_socket, EVP_PKEY *public_key) {
    this -> username = username;
    this -> main_socket = main_socket;
    this -> chat_socket = chat_socket;
    this -> server_counter_recv = 0;
    this -> server_counter_send = 0;
    this -> peer_counter_recv = 0;
    this -> server_counter_send = 0;
    this -> is_sender = false;
    this -> requests = {};
    // deep copy public key
    unsigned char *key = NULL, *p = NULL;
    int key_size;
    ERR_U(key_size = i2d_PUBKEY(public_key, &key));
    p = key;
    ERR_U(this -> public_key = d2i_PUBKEY(NULL, 
    (const unsigned char **) &p, key_size));
    free(key);
}

User::~User() {
    if (public_key) {
        EVP_PKEY_free(public_key);
        public_key = NULL;
    }
    if (server_sym_key) {
        delete server_sym_key;
        server_sym_key = NULL;
    }
}

std::string User::getUsername() {
    return this -> username;
}

int User::getMainSocket() {
    return this -> main_socket;
}

int User::getChatSocket() {
    return this -> chat_socket;
}

int User::getServerSendCounter() {
    return this -> server_counter_send;
}

int User::getServerRecvCounter() {
    return this -> server_counter_recv;
}

void User::increaseServerSendCounter() {
    this -> server_counter_send++;
}

void User::increaseServerRecvCounter() {
    this -> server_counter_recv++;
}

int User::getPeerSendCounter() {
    return this -> peer_counter_send;
}

int User::getPeerRecvCounter() {
    return this -> peer_counter_recv;
}

void User::increasePeerSendCounter() {
    this -> peer_counter_send++;
}

void User::increasePeerRecvCounter() {
    this -> peer_counter_recv++;
}

void User::insertRequest(User *user) {
    this -> requests.push_back(user);
}

void User::resetChatCounter() {
    this -> peer_counter_recv = 0;
    this -> peer_counter_send = 0;
}

void User::eraseRequests() {
    requests.clear();
}

vector<User*> User::getRequests() {
    return this -> requests;
}

EVP_PKEY* User::getPublicKey() {
    // Deep copy of public key
    EVP_PKEY *pkey = NULL;
    int key_size;
    unsigned char *key = NULL, *p = NULL;
    U_ERR(key_size = i2d_PUBKEY(this -> public_key, &key), NULL);
    p = key;
    U_ERR(pkey = d2i_PUBKEY(NULL, (const unsigned char **)&p, key_size), NULL);
    free(key);
    return pkey;
}

bool User::getIsSender() {
    return this -> is_sender;
}

void User::setServerSymKey(Message<unsigned char> *key) {
    this -> server_sym_key = key -> clone();
}

Message<unsigned char>* User::getServerSymKey() {
    return this -> server_sym_key -> clone();
}

void User::setIsSender(bool b) {
    this -> is_sender = b;
}

User* User::clone() {
    User *user = NULL;
    U_ERR(user = new User(*this), NULL);
    return user;
}

void User::clean() {
    
}

void User::removeRequest(User *user){
    for(long unsigned int i = 0 ; i < requests.size(); i++){
        if((user -> getUsername().compare(requests[i] -> getUsername())) == 0){
            requests.erase(requests.begin() + i);
            puts("Remove");
            break;
        }
    }
}