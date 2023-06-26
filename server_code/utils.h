//TODO: unsigned nei messaggi

#ifndef UTILS_H
#define UTILS_H

#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cstring>
#include <dirent.h>
#include <list>
#include <iomanip>
#include <fstream>
#include <dirent.h>
#include <sstream>
#include <map>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <thread>
#include <mutex>
#include <vector>
#include <queue>
#include <condition_variable>
#include <memory>
#include <cstdarg>
#include <sys/stat.h>
#include <regex>

const int CHUNK_SIZE = 1000000;
const size_t MAX_PATH = 512;
const size_t NONCE_LEN = 16;
const size_t TAG_LEN = 16;
const size_t IV_LEN = EVP_CIPHER_iv_length(EVP_aes_256_gcm());
const std::string USERNAMES_FILE = "users.csv";
const std::regex pattern("[A-Za-z0-9_. -]+");

// SESSION STRUCT
struct Session
{
    std::string username;
    unsigned char nonceClient[NONCE_LEN];
    unsigned char *nonceServer[NONCE_LEN];
    unsigned char aes_key[32];
    EVP_PKEY *pubkey;
    EVP_PKEY *eph_key_priv;
    EVP_PKEY *eph_key_pub;
    int socket;
    unsigned int client_counter;
    unsigned int server_counter;
};

bool send_message(Session *client_session, const std::string payload);
bool send_message(Session *session, const std::string payload, bool send_esito, int esito);
bool receive_message(Session *server_session, std::string *payload);
bool receive_message(Session *server_session, std::string *payload, bool receive_esito, int *esito);
class CommandServer
{
public:
    virtual ~CommandServer() = default;
    virtual bool execute(Session *session, const std::string command) = 0;
};

class UploadServer : public CommandServer
{
public:
    bool execute(Session *session, const std::string command) override;
};

class DownloadServer : public CommandServer
{
public:
    bool execute(Session *session, const std::string command) override;
};

class DeleteServer : public CommandServer
{
public:
    bool execute(Session *session, const std::string command) override;
};

class ListServer : public CommandServer
{
public:
    bool execute(Session *session, const std::string command) override;
};

class RenameServer : public CommandServer
{
public:
    bool execute(Session *session, const std::string command) override;
};

class LogoutServer : public CommandServer
{
public:
    bool execute(Session *session, const std::string command) override;
};
// USER
bool isRegistered(std::string username);

// MANAGE MESSAGES
bool send_message1(Session *server_session);
bool receive_message2(Session *server_session);
bool send_message3(Session *server_session, EVP_PKEY *server_private_key);
bool receive_message4(Session *server_session);

// MEMORY HANDLER

#ifndef BUFFER_UTILS_H
#define BUFFER_UTILS_H

template <typename T>
void delete_buffers(T *buffer);

template <typename T, typename... Ts>
void delete_buffers(T *buffer, Ts *...buffers);

#include "buffer_utils.tpp"

#endif

int safe_size_t_to_int(size_t value);
size_t int_to_size_t(int value);
void serialize_int(int input, unsigned char *output);
void serialize_longint(long int value, unsigned char *buffer, size_t buffer_size);
bool deserialize_longint(const unsigned char *buffer, long int *result);

int recv_all(int socket, void *buffer, ssize_t len);
void log_error(const std::string &msg);

// CERTIFICATES

int load_certificate(std::string filename, X509 **certificate);

// ASYMMETRIC KEYS

EVP_PKEY *load_public_key(const char *public_key_file);
EVP_PKEY *load_private_key(const char *private_key_file);
int serialize_public_key(EVP_PKEY *public_key, unsigned char **serialized_key);
EVP_PKEY *deserialize_public_key(unsigned char *serialized_key, int key_len);

// DIGITAL SIGNATURE

int create_digital_signature(EVP_PKEY *private_key, const unsigned char *data, int data_len, unsigned char *signature);
int verify_digital_signature(EVP_PKEY *public_key, const unsigned char *signature, int signature_len, const unsigned char *data, int data_len);

// AES-GCM 256

int aesgcm_encrypt(unsigned char *plaintext, int plaintext_len,
                   unsigned char *aad, int aad_len,
                   unsigned char *key,
                   unsigned char *iv, int iv_len,
                   unsigned char *ciphertext,
                   unsigned char *tag);

int aesgcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                   unsigned char *aad, int aad_len,
                   unsigned char *tag,
                   unsigned char *key,
                   unsigned char *iv, int iv_len,
                   unsigned char *plaintext);

bool rsaEncrypt(const unsigned char* plaintext, size_t plaintextLength, EVP_PKEY* publicKey, unsigned char*& ciphertext, size_t& ciphertextLength);

EVP_PKEY* duplicate_key(EVP_PKEY* pkey);

#endif
