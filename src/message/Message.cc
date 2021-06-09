#include "Message.h"

template <typename T>
Message<T>::Message(T *message, int len) {
    this -> message = (T*)calloc(len + 1, sizeof(T));
    if (!message) {
        std::cerr << "Error on line: " << __LINE__ << '\n';
        std::cerr << strerror(errno);
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < len; i++) {
        this -> message[i] = message[i];
    }
    this -> len = len;
};

template <typename T>
Message<T>::Message(int len) {
    this -> message = (T*)calloc(len + 1, sizeof(T));
    if (!message) {
        std::cerr << "Error on line: " << __LINE__ << '\n';
        std::cerr << strerror(errno);
        exit(EXIT_FAILURE);
    }
    this -> len = len;
};

template <typename T>
Message<T>::~Message() {
    memset(message, 0, len);
    free(message);
}

// Deep copy, to avoid security leaks
template <typename T>
T* Message<T>::getMessage() {
    T *message = (T*)calloc(len + 1, sizeof(T));
    memcpy(message, this -> message, len);
    return message;
}

// Update this
template <typename T>
void Message<T>::setMessage(T* message, int len) {
    memset(this -> message, 0, len);
    //free(this -> message);
    memcpy(this -> message, message, len);
    this -> len = len;
}

// Deep copy of this
template <typename T>
Message<T>* Message<T>::clone() {
    return new Message<T>(this -> message, this -> len);
}

// Return len
template <typename T>
int Message<T>::getLen() {
    return len;
}

// Set new length
template <typename T>
void Message<T>::setLen(int len) {
    this -> len = len;
}
