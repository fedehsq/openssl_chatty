#ifndef Message_h
#define Message_h
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <vector>

template <typename T>
// Class representing  encrypted message with its len
class Message {
    // Generic message (cipheretext, symmetric key, )
    T *message;
    // Len of mesasge
    int len;
    
public:

    // Pass message and its len
    Message(T *message, int len);

    // Pass message and its len
    Message(int len);

    ~Message();

    T* getMessage();

    Message<T> *clone();

    int getLen();

    void setLen(int len);

    void setMessage(T* message, int len);

};

#endif