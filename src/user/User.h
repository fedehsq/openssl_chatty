#include <iostream>
#include <sys/socket.h>
#include <list>

using namespace std;

// This class represent an online user
class User {
private:
    vector<User*> requests;
    std::string username;
    int main_socket, chat_socket;
    unsigned int server_counter_send, server_counter_recv;
    unsigned int peer_counter_send, peer_counter_recv;
    EVP_PKEY *public_key = NULL;
    Message<unsigned char> *server_sym_key = NULL;
    bool is_sender;

public:
    User(std::string username, int main_socket, int chat_socket, EVP_PKEY *public_key);
    ~User();

    std::string getUsername();

    int getMainSocket();

    int getChatSocket();

    EVP_PKEY *getPublicKey();

    bool getIsSender();

    int getServerSendCounter();

    int getServerRecvCounter();

    void increaseServerSendCounter();

    void increaseServerRecvCounter();

    int getPeerSendCounter();

    int getPeerRecvCounter();

    void increasePeerSendCounter();

    void increasePeerRecvCounter();

    void resetChatCounter();

    void eraseRequests();

    void setServerSymKey(Message<unsigned char> *key);

    void setIsSender(bool b);

    Message<unsigned char> *getServerSymKey();

    User *clone();

    void clean();

    void insertRequest(User *user);

    vector<User*> getRequests();

    void removeRequest(User *user);
};