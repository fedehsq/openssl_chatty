#include "utils.h"

// Check for errors
#define ERR(res, line_togo) { \
    if (!(res)) { \
        std::cerr << "In " << __FILE__ << " error on " << __LINE__; \
        if (errno) { \
            if (errno == EINTR) { \
                std::cerr << ": SIGINT received. Server is shutting down..."; \
            } else { \
                std::cerr << ": " << strerror(errno); \
            } \
        } \
        puts(""); \
        ERR_print_errors_fp(stderr); \
        goto line_togo; \
    } \
} \

#define N_ERR(res, line_togo) { \
    if (res == -1) { \
        std::cerr << "In " << __FILE__ << " error on " << __LINE__; \
        if (errno) { \
            if (errno == EINTR) { \
                std::cerr << ": SIGINT received. Server is shutting down..."; \
            } else { \
                std::cerr << ": " << strerror(errno); \
            } \
        } \
        puts(""); \
        ERR_print_errors_fp(stderr); \
        goto line_togo; \
    } \
} \

#define NO_0_ERR(res, line_togo) { \
    if (res != 0) { \
        std::cerr << "In " << __FILE__ << " error on line " << __LINE__; \
        if (errno) { \
            std::cerr << ": " << strerror(errno); \
        } \
        puts(""); \
        ERR_print_errors_fp(stderr); \
        goto line_togo; \
    } \
}

// Copy a Message* object in a buffer.
template <typename T>
int mmemcpy(void *dest, Message<T> *src) {
    T *t = NULL;
    ERR(t = src -> getMessage(), destroy);
    memcpy(dest, t, src -> getLen());
    free(t);
    return 1;
destroy:
    if (t) {
        free(t);
    }
    return 0;
}

void cpy_int_to_bytes(int x, unsigned char *b) {
    b[0] = x & 0xFF;
    b[1] = (x>>8) & 0xFF;
    b[2] = (x>>16) & 0xFF;
    b[3] = (x>>24) & 0xFF;
}


// Create a buffer concatenating an arbitrary number of Message* objects 
// and return that buffer with associated length.
template <typename T>
unsigned char *concat(int *len, Message<T> *src, ...) {
    // Sizes of messages to send
    vector<int> sizes = {};
    // 'Chars' buffer / dest
    unsigned char *chars = NULL, *dest = NULL;
    va_list va;
    va_start(va, src);
    // final size / sizes of each message
    int sz_dest, pos = 0;
    // final len
    *len = 0;
    while (src) {
        *len += src -> getLen();
        sizes.push_back(src -> getLen());
        ERR(chars = (unsigned char *)realloc(chars, (*len + 1) 
            * sizeof(unsigned char)), destroy);
        ERR(mmemcpy(chars + pos, src), destroy);
        pos = *len;
        src = va_arg(va, Message<T> *);
    }
    va_end(va);

    // We allocate a buffer in the following way: 
    // 4 bytes for the number of concatenated messages; 
    // then sizes.size() * sizeof(int) bytes for the length of each message; 
    // len bytes to insert th messages themselves
    sz_dest = (1 + sizes.size()) * sizeof(int);
    dest = (unsigned char*)calloc(sz_dest + (*len), 1);

    // Copy the number of messages as first part of message (first 4 bytes)
    cpy_int_to_bytes(sizes.size(), dest);

    // Copy the dimension of each message (starts from 4th byte!)
    for (long unsigned int i = 0; i < sizes.size(); i++) {
        cpy_int_to_bytes(sizes[i], &dest[(i + 1) * sizeof(int)]);
    }
    
    // Copy the messages starting from right position
    memcpy(dest + sz_dest, chars, *len);
    // Update the position
    *len += sz_dest;
    return dest;
destroy:
    if (chars) {
        free (chars);
    }
    return NULL;
}


/*
// Create a buffer concatenating an arbitrary number of Message* objects 
// and return that buffer with associated length.
template <typename T>
unsigned char *concat(int *len, Message<T> *src, ...) {
    // Sizes of messages to send
    vector<int> sizes = {};
    // Destination buffer
    unsigned char *dest = NULL;
    unsigned char *to_send = NULL;
    va_list va;
    va_start(va, src);
    int pos = 0;
    *len = 0;
    while (src) {
        *len += src -> getLen();
        sizes.push_back(src -> getLen());
        ERR(dest = (unsigned char *)realloc(dest, (*len + 1) 
            * sizeof(unsigned char)), destroy);
        ERR(mmemcpy(dest + pos, src), destroy);
        pos = *len;
        src = va_arg(va, Message<T> *);
    }
    va_end(va);

    to_send = (unsigned char*)calloc( (1 + sizes.size()) * sizeof(int) + (*len) * sizeof(unsigned char), sizeof(unsigned char));
    to_send[0] = sizes.size();
    for (int i = 0; i < sizes.size(); i++) {
        to_send[i + 1] = sizes[i];
    }
    memcpy(to_send + sizes.size() + 1, dest, *len);
    *len += sizes.size() + 1;
    return to_send;
destroy:
    if (dest) {
        free (dest);
    }
    return NULL;
}
*/

// Create a Message* object concatenating an arbitrary number of 
// Message* objects and return that object.
template <typename T>
Message<T> *mconcat(Message<T> *src, ...) {
    // Destination temporary buffer
    unsigned char *dest = NULL;;
    Message<T> *concat = NULL;
    va_list va;
    va_start(va, src);
    int pos = 0;
    int len = 0;
    while (src) {
        len += src -> getLen();
        ERR(dest = (unsigned char *)realloc(dest, (len + 1) 
            * sizeof(unsigned char)), destroy);
        ERR(mmemcpy(dest + pos, src), destroy);
        pos = len;
        src = va_arg(va, Message<T> *);
    }
    va_end(va);
    ERR(concat = new Message<T>(dest, len), destroy);
    free(dest);
    return concat;
destroy:
    if (dest) {
        free(dest);
    }
    if (concat) {
        free(concat);
    }
    return NULL;
}

// Taken an arbitrary number of message objects, delete them.
template <typename T>
void mdestroy(int n, Message<T> **src, ...) {
    va_list va;
    va_start(va, src);
    for (; n > 0; n--) {
        if (*src) {
            delete *src;
            *src = NULL;
        }
        src = va_arg(va, Message<T> **);
    }
    va_end(va);
}

// Taken an arbitrary number of objects, delete them.
template <typename T>
void odestroy(int n, T **src, ...) {
    va_list va;
    va_start(va, src);
    for (; n > 0; n--) {
        if (*src) {
            delete *src;
            *src = NULL;
        }
        src = va_arg(va, T **);
    }
    va_end(va);
}

// Taken an arbitrary number of buffers, delete them.
void bdestroy(int n, char **src, ...) {
    va_list va;
    va_start(va, src);
    for (; n > 0; n--) {
        if (*src) {
            memset(*src, 0, strlen(*src));
            free(*src);
            *src = NULL;
        }
        src = va_arg(va, char **);
    }
    va_end(va);
}

// Takes the Message* msg from socket and split into 
// sub Message* objects adding them in a list and return it.
std::vector<Message<unsigned char>*> split(Message<unsigned char>   
    *socket_message, int size, ...) {
    // Storing splitted messsages 
    std::vector<Message<unsigned char> *> messages;
    // Arbitrary pointer to message
    Message<unsigned char> *ptr = NULL;
    // Bytes of socket message
    unsigned char *received_message = NULL;
    // Messages size
    int from = 0;
    va_list va;
    va_start(va, size);
    // Mess len
    ERR(received_message = socket_message -> getMessage(), destroy);
    while (size) {
        ERR(ptr = 
            new Message<unsigned char>(received_message + from, size), destroy);
        messages.push_back(ptr);
        from += size;
        size = va_arg(va, int);
        #ifdef DEBUG
            print_bytes(ptr);
            puts("");
        #endif
    }
    va_end(va);
    free(received_message);
    return messages;
destroy:
    if (received_message) {
        free(received_message);
    }
    if (ptr) {
        delete ptr;
    }
    for (long unsigned int i = 0; i < messages.size(); i++) {
        delete messages[i];
    }
    return {};
}

// Takes the Message* msg from socket and split into 
// sub Message* objects adding them in a list and return it.
std::vector<Message<unsigned char>*> split(Message<unsigned char>   
    *socket_message, int size[], int n) {
    // Storing splitted messsages 
    std::vector<Message<unsigned char> *> messages;
    // Arbitrary pointer to message
    Message<unsigned char> *ptr = NULL;
    // Bytes of socket message
    unsigned char *received_message = NULL;
    // Messages size
    int from = 0;
    // Mess len
    ERR(received_message = socket_message -> getMessage(), destroy);
    for (int i = 0; i < n; i++) {
        ERR(ptr = 
            new Message<unsigned char>(received_message + from, size[i]), destroy);
        messages.push_back(ptr);
        from += size[i];
    }
    free(received_message);
    return messages;
destroy:
    if (received_message) {
        free(received_message);
    }
    if (ptr) {
        delete ptr;
    }
    for (long unsigned int i = 0; i < messages.size(); i++) {
        delete messages[i];
    }
    return {};
}


// Read a message over socket and return it.
Message<unsigned char> *read_message(int socket) {
    // Number of messages to receive / total size of messages / pointer
    int n_mess, read, sz = 0, pos = 0;
    // Array that contains each message size
    int *sizes = NULL;
    // Messages received
    unsigned char *received = NULL;
    Message<unsigned char> *message = NULL;
    
    // Read #of messages
    ERR(read = recv(socket, &n_mess, sizeof(int), 0), destroy);
    // Read size of each message
    ERR(sizes = (int *)calloc(n_mess, sizeof(int)), destroy);

    // Save each dimension
    for (int i = 0; i < n_mess; i++) {
        ERR(read = recv(socket, &sizes[i], sizeof(int), 0), destroy);
        sz += sizes[i];
    }

    // Buffer that receives the messages
    ERR(received = (unsigned char *)calloc(sz, 1), destroy);

    // Read messages
    for (int i = 0; i < n_mess; i++) {
        ERR(read = recv(socket, received + pos, sizes[i], 0), destroy);
        pos += read;
    }

    ERR(message = 
        new Message<unsigned char>(received, sz), destroy)
destroy:
    return message;
}


// Read a message over socket and return it.
vector<Message<unsigned char>*> read_split_message(int socket) {
    // Messages splitted
    vector<Message<unsigned char>*> splitted = {};
    // Number of messages to receive / total size of messages / pointer
    int n_mess, read, sz = 0, pos = 0;
    // Array that contains each message size
    int *sizes = NULL;
    // Messages received
    unsigned char *received = NULL;
    Message<unsigned char> *message = NULL;
    
    // Read #of messages
    ERR(read = recv(socket, &n_mess, sizeof(int), 0), destroy);
    // Read size of each message
    ERR(sizes = (int *)calloc(n_mess, sizeof(int)), destroy);

    // Save each dimension
    for (int i = 0; i < n_mess; i++) {
        ERR(read = recv(socket, &sizes[i], sizeof(int), 0), destroy);
        sz += sizes[i];
    }

    // Buffer that receives the messages
    ERR(received = (unsigned char *)calloc(sz, 1), destroy);

    // Read messages
    for (int i = 0; i < n_mess; i++) {
        ERR(read = recv(socket, received + pos, sizes[i], 0), destroy);
        pos += read;
    }

    ERR(message = 
            new Message<unsigned char>(received, sz), destroy);
    
    splitted = split(message, sizes, n_mess);
destroy:
    return splitted;
}

/*

// Read a message over socket and return it.
Message<unsigned char> *read_message(int socket) {
    unsigned char received_message[MAX_SIZE];
    int read = 0, message_size = 0;
    Message<unsigned char> *message = NULL;
    while ((read = recv(socket, received_message + message_size, 
        MAX_SIZE, 0)) > 0) {
        message_size += read;
        if (read < MAX_SIZE) {
            break;
        }
    }
    N_ERR(read, end);
    ERR(read, end);
    received_message[message_size] = (unsigned char)'\0';
    ERR(message = 
        new Message<unsigned char>(received_message, message_size), end)
    #ifdef DEBUG
        puts("read_from_socket");
        print_bytes(message);
    #endif
end:
    return message;
}
*/


// Extract, verify and remove the timestamp of an incoming Message.
// Every message in the session ends with timestamp, it is separated
// by 'text' message by an empty character: ' '.
// Return 1 if it is fresh, 0 otherwise.
template <typename T>
int verify_timestamp(Message<T> *message) {
    int ret;
    // Position moved on buffer
    int read = 1;
    // Get current timestamp
    unsigned long int timestamp = time(NULL);
    unsigned long int recv_timestamp;
    unsigned char *bytes = NULL, *p = NULL;
    ERR(bytes = message -> getMessage(), destroy);
    // Start to observe buffer from the end
    p = bytes + message -> getLen() - 1;
    
    while (*p--) {
        read++;
        if (*p == ' ') {
            // Extract received timestamp
            recv_timestamp = atol((const char *)p + 1);
            // Check for validity (less than a 5s)
            ret = timestamp - recv_timestamp <= 5 ? 1 : 0;
            break;
        }
    }
    // Remove timestamp
    memset(p, '\0', read);
    message -> setMessage(bytes, message -> getLen() - read);
destroy:
    if (bytes) {
        memset(bytes, 0, message -> getLen());
        free(bytes);
    }
    return ret;
}

// Extract from Message* the text and print that string. 
template <typename T>
void print_string(Message<T> *message) {
    char *msg = (char *) message -> getMessage();
    std::cout << msg << std::endl;
    free(msg);
}

/*
// It extract AEAD message from a received socket message.
// It decrypts AEAD message with key and 
// verify if the timestamp in the message is 'fresh'.
// Return decrypted message, or NULL for error.
Message<unsigned char> *get_aead_message(
    Message<unsigned char> *received_message, 
    Message<unsigned char> *key) {
    
    Message<unsigned char> *ret = NULL;
    // Encrypt / decrypt messages
    SymmetricEncryption *sym = NULL;
    // Splitter messages
    vector<Message<unsigned char>*> messages = {};
    // Ciphertext generated by algo / received
    Message<unsigned char> *ciphertext = NULL;
    // plaintext / decrypted
    Message<unsigned char> *plaintext = NULL;
    // IV generated for every message
    Message<unsigned char> *iv = NULL;
    // Tag generated by encryption / received
    Message<unsigned char> *tag = NULL;

    ERR(sym = new SymmetricEncryption(EVP_aes_256_gcm()), destroy);

    messages = split(received_message, 
    // Iv lenght fixed
    EVP_CIPHER_iv_length(EVP_aes_256_gcm()),
    // Tag length fixed
    16,
    // Ciphertext length not fixed
    received_message -> getLen() 
    // Clear aead
    - EVP_CIPHER_iv_length(EVP_aes_256_gcm())
    // Tag length
    - 16,
    0);
    iv = messages[0];
    tag = messages[1];
    ciphertext = messages[2];
    #ifdef DEBUG
        puts("iv:");
        print_bytes(iv);
        puts("\nct:");
        print_bytes(ciphertext);
        puts("\ntag:");
        print_bytes(tag);
        puts("\nkey:");
        print_bytes(key);
    #endif
    // Decrypt ciphertext
    ERR(sym -> AEADdecrypt(ciphertext, key, iv, iv, tag), destroy);
    ERR(plaintext = sym -> getDecrypted(), destroy);
    // Verify and remove the timestamp
    verify_timestamp(plaintext);
    ret = plaintext;
destroy:
    if (sym) {
        delete sym;
    }
    if (ciphertext) {
        delete ciphertext;
    }
    if (iv) {
        delete iv;
    }
    if (tag) {
        delete tag;
    }
    return ret;

}
*/

// Receive a socket encrypted AEAD message from the peer.
// It decrypts AEAD message with key and 
// verify if the timestamp in the message is 'fresh'.
// Return the decrypted plaintext, or NULL for error.
Message<unsigned char> *get_aead_msg(int actual_counter,
    Message<unsigned char> *received_message, Message<unsigned char> *key) {
    
    Message<unsigned char> *ret = NULL;
    // Encrypt / decrypt messages
    SymmetricEncryption *sym = NULL;
    // Splitter messages
    vector<Message<unsigned char>*> messages = {};
    // Ciphertext generated by algo / received
    Message<unsigned char> *ciphertext = NULL;
    // plaintext / decrypted
    Message<unsigned char> *plaintext = NULL;
    // IV generated for every message
    Message<unsigned char> *iv = NULL;
    // Tag generated by encryption / received
    Message<unsigned char> *tag = NULL;
    // aad (counter) received
    Message<unsigned char> *aad = NULL;
    int recv_counter;
    unsigned char *counter_bytes;

    ERR(sym = new SymmetricEncryption(EVP_aes_256_gcm()), destroy);

    // 1: server sends to the client online users. [iv, tag, ciphertext]
    messages = split(received_message, 
        // Iv lenght fixed
        EVP_CIPHER_iv_length(EVP_aes_256_gcm()),
        // aad (counter)
        sizeof(int),
        // Tag length fixed
        16,
        // Ciphertext length not fixed
        received_message -> getLen() 
        // Iv lenght fixed
        - EVP_CIPHER_iv_length(EVP_aes_256_gcm())
        // Clear aad i.e counter (4 bytes)
        - sizeof(int)
        // Tag length
        - 16,
        0);
    iv = messages[0];
    aad = messages[1];
    tag = messages[2];
    ciphertext = messages[3];

    // Convert recv counter (aad) in int
    counter_bytes = aad -> getMessage();
    memcpy(&recv_counter, counter_bytes, sizeof(int));
    if (recv_counter == actual_counter + 1) {
        // Decrypt ciphertext
        ERR(sym -> AEADdecrypt(ciphertext, key, iv, aad, tag), destroy);
        ERR(plaintext = sym -> getDecrypted(), destroy);
        ret = plaintext;
    } else {
        puts("replay attack detected!");
        cout << "recv: " << recv_counter << "act: " << actual_counter << endl;
    }
destroy:
    if (sym) {
        delete sym;
    }
    if (ciphertext) {
        delete ciphertext;
    }
    if (iv) {
        delete iv;
    }
    if (tag) {
        delete tag;
    }
    return ret;
}



// Receive a socket encrypted AEAD message from the peer.
// Before decrypt the message, verify the freshness
// It decrypts AEAD message with key and 
// Return the decrypted plaintext, or NULL for error.
Message<unsigned char> *recv_aead_msg(int peer_socket, 
    int actual_counter, Message<unsigned char> *key) {
    Message<unsigned char> *ret = NULL;
    // Store socket data
    Message<unsigned char>* received_message = NULL;
    // Encrypt / decrypt messages
    SymmetricEncryption *sym = NULL;
    // Splitter messages
    vector<Message<unsigned char>*> messages = {};
    // Ciphertext generated by algo / received
    Message<unsigned char> *ciphertext = NULL;
    // plaintext / decrypted
    Message<unsigned char> *plaintext = NULL;
    // IV generated for every message
    Message<unsigned char> *iv = NULL;
    // Tag generated by encryption / received
    Message<unsigned char> *tag = NULL;
    // Received tag
    Message<unsigned char> *aad = NULL;
    int recv_counter;
    unsigned char *counter_bytes;

    ERR(sym = new SymmetricEncryption(EVP_aes_256_gcm()), destroy);

    // 1: server sends to the client online users. [iv, aad(counter), tag, ciphertext]
    if ((messages = read_split_message(peer_socket)).empty()) {
        goto destroy;
    }
    iv = messages[0];
    aad = messages[1];
    tag = messages[2];
    ciphertext = messages[3];

    // Convert recv counter (aad) in int
    counter_bytes = aad -> getMessage();
    memcpy(&recv_counter, counter_bytes, sizeof(int));
    if (recv_counter == actual_counter + 1) {
        // Decrypt ciphertext
        ERR(sym -> AEADdecrypt(ciphertext, key, iv, aad, tag), destroy);
        ERR(plaintext = sym -> getDecrypted(), destroy);
        ret = plaintext;
    } else {
        cout << "recv counter " << recv_counter << " actual counter " << actual_counter << endl;
        puts("Replay attack detected!");
    }
destroy:
    if (received_message) {
        delete received_message;
    }
    if (sym) {
        delete sym;
    }
    if (ciphertext) {
        delete ciphertext;
    }
    if (iv) {
        delete iv;
    }
    if (tag) {
        delete tag;
    }
    return ret;
}
    
// Receive a socket encrypted AEAD message from the peer.
// Before decrypt the message, verify the freshness
// It decrypts AEAD message with key and 
// Return the decrypted plaintext, or NULL for error.
Message<unsigned char> *recv_aead_msg(User *u, int peer_socket, 
    int actual_counter, Message<unsigned char> *key) {
    Message<unsigned char> *ret = NULL;
    // Store socket data
    Message<unsigned char>* received_message = NULL;
    // Encrypt / decrypt messages
    SymmetricEncryption *sym = NULL;
    // Splitter messages
    vector<Message<unsigned char>*> messages = {};
    // Ciphertext generated by algo / received
    Message<unsigned char> *ciphertext = NULL;
    // plaintext / decrypted
    Message<unsigned char> *plaintext = NULL;
    // IV generated for every message
    Message<unsigned char> *iv = NULL;
    // Tag generated by encryption / received
    Message<unsigned char> *tag = NULL;
    // Received tag
    Message<unsigned char> *aad = NULL;
    int recv_counter;
    unsigned char *counter_bytes;

    ERR(sym = new SymmetricEncryption(EVP_aes_256_gcm()), destroy);

    // 1: server sends to the client online users. [iv, aad(counter), tag, ciphertext]
    if ((messages = read_split_message(peer_socket)).empty()) {
        goto destroy;
    }
    iv = messages[0];
    aad = messages[1];
    tag = messages[2];
    ciphertext = messages[3];

    // Convert recv counter (aad) in int
    counter_bytes = aad -> getMessage();
    memcpy(&recv_counter, counter_bytes, sizeof(int));
    if (recv_counter == u -> getServerRecvCounter() + 1) {
        // Decrypt ciphertext
        ERR(sym -> AEADdecrypt(ciphertext, key, iv, aad, tag), destroy);
        ERR(plaintext = sym -> getDecrypted(), destroy);
        ret = plaintext;
    } else {
        cout << "recv counter " << recv_counter << " actual counter " << actual_counter << endl;
        puts("Replay attack detected!");
    }
destroy:
    if (received_message) {
        delete received_message;
    }
    if (sym) {
        delete sym;
    }
    if (ciphertext) {
        delete ciphertext;
    }
    if (iv) {
        delete iv;
    }
    if (tag) {
        delete tag;
    }
    return ret;
}

// Receive a socket encrypted AEAD message from the peer.
// Before decrypt the message, verify the freshness
// It decrypts AEAD message with key and 
// Return the decrypted plaintext, or NULL for error.
Message<unsigned char> *recv_aead_msg(User *user) {
    Message<unsigned char> *ret = NULL;
    // Store socket data
    Message<unsigned char>* received_message = NULL;
    // Encrypt / decrypt messages
    SymmetricEncryption *sym = NULL;
    // Splitter messages
    vector<Message<unsigned char>*> messages = {};
    // Ciphertext generated by algo / received
    Message<unsigned char> *ciphertext = NULL;
    Message<unsigned char> *key = NULL;
    // plaintext / decrypted
    Message<unsigned char> *plaintext = NULL;
    // IV generated for every message
    Message<unsigned char> *iv = NULL;
    // Tag generated by encryption / received
    Message<unsigned char> *tag = NULL;
    // Received tag
    Message<unsigned char> *aad = NULL;
    int recv_counter;
    unsigned char *counter_bytes;

    ERR(sym = new SymmetricEncryption(EVP_aes_256_gcm()), destroy);
    ERR(key = user -> getServerSymKey(), destroy);

    // 1: server sends to the client online users. [iv, aad(counter), tag, ciphertext]
    if ((messages = read_split_message(user -> getChatSocket())).empty()) {
        goto destroy;
    }
    iv = messages[0];
    aad = messages[1];
    tag = messages[2];
    ciphertext = messages[3];

    // Convert recv counter (aad) in int
    counter_bytes = aad -> getMessage();
    memcpy(&recv_counter, counter_bytes, sizeof(int));
    if (recv_counter == user -> getServerRecvCounter() + 1) {
        // Decrypt ciphertext
        ERR(sym -> AEADdecrypt(ciphertext, key, iv, aad, tag), destroy);
        ERR(plaintext = sym -> getDecrypted(), destroy);
        ret = plaintext;
    } else {
        cout << "recv counter " << recv_counter << " actual counter " << user -> getServerRecvCounter() << endl;
        puts("Replay attack detected!");
    }
destroy:
    if (received_message) {
        delete received_message;
    }
    if (sym) {
        delete sym;
    }
    if (ciphertext) {
        delete ciphertext;
    }
    if (iv) {
        delete iv;
    }
    if (tag) {
        delete tag;
    }
    return ret;
}

// Given the message and the user, it encrypts plaintext with AEAD 
// adding counter to avoid replay attack.
// The ciphertext is sent to the peer.
// Return 0 for errors, 1 otherwise.
int send_aead_msg(string input, int socket, 
    int send_counter, Message<unsigned char> *key) {
    
    int ret = 0;
    // Encrypt / decrypt messages
    SymmetricEncryption *sym = NULL;
    // Client sym key
    // Ciphertext generated by algo
    Message<unsigned char> *ciphertext = NULL;
    // IV generated for every message
    Message<unsigned char> *iv = NULL;
    // AAD (counter) to send
    Message<unsigned char> *aad = NULL;
    // Tag generated by algo
    Message<unsigned char> *tag = NULL;
    // Plaintext to send
    Message<unsigned char> *plaintext = NULL;
    // To send over socket
    unsigned char *to_send = NULL, counter[4];
    int to_send_size;

    // Convert send_counter to bytes
    cpy_int_to_bytes(send_counter, counter);

    ERR(sym = new SymmetricEncryption(EVP_aes_256_gcm()), destroy);

    ERR(plaintext = new Message<unsigned char>((unsigned char *)input.c_str(), input.length()), destroy);
    
    ERR(iv = generate_random_bytes(EVP_CIPHER_iv_length(EVP_aes_256_gcm())), destroy);
    ERR(aad = new Message<unsigned char>(counter, 4), destroy);
    // Encrypt message
    ERR(sym -> AEADencrypt(plaintext, key, iv, aad), destroy);
    ERR(ciphertext = sym -> getCiphertext(), destroy);
    ERR(tag = sym -> getTag(), destroy);
    // Build message to send
    to_send = concat(&to_send_size, iv, aad, tag, ciphertext, NULL);
    ERR(send(socket, to_send, to_send_size, 0), destroy);
    ret = 1;
destroy:
    if (sym) {
        delete sym;
    }
    if (ciphertext) {
        delete ciphertext;
    }
    if (iv) {
        delete iv;
    }
    if (tag) {
        delete tag;
    }
    if (plaintext) {
        delete plaintext;
    }
    if (to_send) {
        memset(to_send, 0, to_send_size);
        free(to_send);
    }
    return ret;
}

// Given the message and the user, it encrypts plaintext with AEAD 
// adding counter to avoid replay attack.
// The ciphertext is sent to the peer.
// Return 0 for errors, 1 otherwise.
Message<unsigned char> *mk_aead_message(string input, 
    int send_counter, Message<unsigned char> *key) {
    
    Message<unsigned char> *ret = NULL;
    // Encrypt / decrypt messages
    SymmetricEncryption *sym = NULL;
    // Client sym key
    // Ciphertext generated by algo
    Message<unsigned char> *ciphertext = NULL;
    // To send over socket
    Message<unsigned char> *to_send = NULL;
    // IV generated for every message
    Message<unsigned char> *iv = NULL;
    // AAD (counter) to send
    Message<unsigned char> *aad = NULL;
    // Tag generated by algo
    Message<unsigned char> *tag = NULL;
    // Plaintext to send
    Message<unsigned char> *plaintext = NULL;
    unsigned char counter[4];

    // Convert send_counter to bytes
    cpy_int_to_bytes(send_counter, counter);

    ERR(sym = new SymmetricEncryption(EVP_aes_256_gcm()), destroy);

    ERR(plaintext = new Message<unsigned char>((unsigned char *)input.c_str(), input.length()), destroy);
    
    ERR(iv = generate_random_bytes(EVP_CIPHER_iv_length(EVP_aes_256_gcm())), destroy);
    ERR(aad = new Message<unsigned char>(counter, 4), destroy);
    // Encrypt message
    ERR(sym -> AEADencrypt(plaintext, key, iv, aad), destroy);
    ERR(ciphertext = sym -> getCiphertext(), destroy);
    ERR(tag = sym -> getTag(), destroy);
    // Build message to send
    ERR(to_send = mconcat(iv, aad, tag, ciphertext, NULL), destroy);
    ret = to_send;
destroy:
    if (sym) {
        delete sym;
    }
    if (ciphertext) {
        delete ciphertext;
    }
    if (iv) {
        delete iv;
    }
    if (tag) {
        delete tag;
    }
    if (plaintext) {
        delete plaintext;
    }
    return ret;
}

// Given the message as bytes and the user, it encrypts plaintext with AEAD 
// adding counter to avoid replay attack.
// The ciphertext is sent to the peer.
// Return 0 for errors, 1 otherwise.
int send_aead_msg(Message<unsigned char> *plaintext, int socket, 
    int send_counter, Message<unsigned char> *key) {
    
    int ret = 0;
    // Encrypt / decrypt messages
    SymmetricEncryption *sym = NULL;
    // Client sym key
    // Ciphertext generated by algo
    Message<unsigned char> *ciphertext = NULL;
    // IV generated for every message
    Message<unsigned char> *iv = NULL;
    // AAD (counter) to send
    Message<unsigned char> *aad = NULL;
    // Tag generated by algo
    Message<unsigned char> *tag = NULL;
    // To send over socket
    unsigned char *to_send = NULL, counter[4];
    int to_send_size;

    // Convert send_counter to bytes
    cpy_int_to_bytes(send_counter, counter);

    ERR(sym = new SymmetricEncryption(EVP_aes_256_gcm()), destroy);
    
    ERR(iv = generate_random_bytes(EVP_CIPHER_iv_length(EVP_aes_256_gcm())), destroy);
    ERR(aad = new Message<unsigned char>(counter, 4), destroy);
    // Encrypt message
    ERR(sym -> AEADencrypt(plaintext, key, iv, aad), destroy);
    ERR(ciphertext = sym -> getCiphertext(), destroy);
    ERR(tag = sym -> getTag(), destroy);
    // Build message to send
    to_send = concat(&to_send_size, iv, aad, tag, ciphertext, NULL);
    ERR(send(socket, to_send, to_send_size, 0), destroy);
    ret = 1;
destroy:
    if (sym) {
        delete sym;
    }
    if (ciphertext) {
        delete ciphertext;
    }
    if (iv) {
        delete iv;
    }
    if (tag) {
        delete tag;
    }
    if (to_send) {
        memset(to_send, 0, to_send_size);
        free(to_send);
    }
    return ret;
}