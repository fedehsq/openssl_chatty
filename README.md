# openSSL chatty
## Description
A multithread client-server chat application. Every communication between peers is encrypted using OpenSSL API.
For more details, visit [instructions]() and [report]()

## How it works
There are 3 users registered to the server.
If you want create your own customers, you should generate a pair of 2048-bit RSA keys and the private key must be protected by password.
The server has a public certificate that is granted to be safe by the CA SimpleAuthority.

## Prerequisites 
The programs needs the installation of [OpenSSL](https://github.com/openssl/openssl), a TLS/SSL and crypto library.

### Install OpenSSL on Ubuntu/Debian
First of all, install build dependencies, then clone OpenSSL and configure it.

```bash
sudo apt-get -y install build-essential checkinstall git zlib1g-dev
git clone --depth 1 --branch OpenSSL_1_1_1g https://github.com/openssl/openssl.git
cd openssl
./config zlib '-Wl,-rpath,$(LIBRPATH)'
```

After you have built and tested, install OpenSSL and configure the shared libs.

```bash
make
make test
sudo make install
sudo ldconfig -v
```
Finally, check the OpenSSL version to make sure you have successfully completed all the steps.

```bash
openssl version
```

### Install SimpleAuthority
If you want to generate your own certificate, you should download the program at the following link:
[SimpleAuthority](https://simpleauthority.com/)


## 2048-bit RSA Generation
How to generate a pair of 2048-bit RSA keys using OpenSSL command-line tools. 

* **RSA private key**: the following command generate a .pem file, protected by a user-chosen password, containing a 2048-bit key.

```bash
openssl genrsa -aes256 -out private_key.pem 2048
```
* **RSA public key**: a private key in OpenSSL is represented with a strcuture that contains also the public key, so the following command extract the public key from the private key.
```bash
openssl rsa -pubout -aes256 -in private_key.pem -out public_key.pem
```

## Usage
Before running the programs, you have first to compile them with `-lcrypto` and `-lpthread` to include the right library.

```bash
cd src/server
g++ server.cc -lcrypto -lpthread
./a.out

cd src/client
g++ client.cc -lcrypto -lpthread
./a.out
```