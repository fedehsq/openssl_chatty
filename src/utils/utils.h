#ifndef utils_h
#define utils_h

#include <sys/types.h>
#include <sys/socket.h>
#include <stdarg.h>
#include "../ssl_utils/ssl_utils.h"
#include "../message/Message.h"
#include "../symmetric_encryption/SymmetricEncryption.cc"
#include "../user/User.cc"

#define MAX_SIZE 10000
#define CHUNK 256
#define SIGN_SIZE 256

using namespace std;

// Copy a Message* object in a buffer.
template <typename T>
int mmemcpy(void *dest, Message<T> *src);

// Taken an arbitrary number of buffers, delete them.
void bdestroy(int n, char **src, ...);

// Create a buffer concatenating an arbitrary number of
// Message* objects and return that buffer with associated length.
template <typename T>
unsigned char *concat(int *len, Message<T> *src, ...);

// Taken n number of message objects, delete them.
template <typename T>
void mdestroy(int n,  Message<T> **src, ...);

// Taken n number of objects, delete them.
template <typename T>
void odestroy(int n, T **src, ...);

// Create a Message* object concatenating an arbitrary number of 
// Message* objects and return that object.
template <typename T>
Message<T> *mconcat(Message<T> *src, ...);

// Takes the Message* msg from socket and split into 
// sub Message* objects adding them in a list and return it.
std::vector<Message<unsigned char>*> split(Message<unsigned char>   
    *socket_message, int size, ...);

// Read a message over socket and return it.
Message<unsigned char> *read_message(int socket);

// Extract from Message* the text and print that string. 
template <typename T>
void print_string(Message<T> *message);


// Given the message and the user, it encrypts plaintext with AEAD 
// adding counter to avoid replay attack.
// The ciphertext is sent to the peer.
// Return 0 for errors, 1 otherwise.
Message<unsigned char> *mk_aead_message(string input, 
    int send_counter, Message<unsigned char> *key);

Message<unsigned char> *get_aead_msg(int actual_counter,
    Message<unsigned char> *received_message, Message<unsigned char> *key);

// Receive a socket encrypted AEAD message from the peer.
// It decrypts AEAD message with key and 
// Return the decrypted plaintext, or NULL for error.
Message<unsigned char> *recv_aead_msg(int peer_socket, 
    Message<unsigned char> *key);

// Receive a socket encrypted AEAD message from the peer.
// Before decrypt the message, verify the freshness
// It decrypts AEAD message with key and 
// Return the decrypted plaintext, or NULL for error.
Message<unsigned char> *recv_aead_msg(int peer_socket, 
    int actual_counter, Message<unsigned char> *key);
// Receive a socket encrypted AEAD message from the peer.
// It decrypts AEAD message with key and 
// Return the decrypted plaintext, or NULL for error.
// Only for reader thread
Message<unsigned char> *recv_aead_msg(User *u);

#endif