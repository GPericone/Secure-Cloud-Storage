#ifndef UTILS_H
#define UTILS_H

#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstring>
#include <openssl/evp.h>
#include <map>
#include <limits.h>
#include <unistd.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <dirent.h>
#include <iomanip>
#include <fstream>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <list>
#include <sstream>
#include <vector>
#include <condition_variable>
#include <memory>
#include <cstdarg>
#include <sys/stat.h>
#include <regex>

const std::regex username_pattern("[A-Za-z]+");
extern bool DEBUG_MODE;
const int CHUNK_SIZE = 1000000;
const size_t MAX_PATH = 512;
const size_t NONCE_LEN = 16;
const size_t TAG_LEN = 16;
const int IV_LEN = EVP_CIPHER_iv_length(EVP_aes_256_gcm());
const size_t USERNAMESIZE = 25;

const std::string instruction = "The communication is secure, now you can execute the following operations:\n\n"
                                "- upload: to upload a file from your computer to the server, use the command 'upload' followed by the name of the file you want to upload. The server will save the file with the name specified by you. If this is not possible, the file will not be uploaded. The size limit for the uploaded file is 4GB.\n"
                                "- download: to download a file from the server, use the command 'download' followed by the name of the file you want to download. If this is not possible, the file will not be downloaded.\n"
                                "- delete: to delete a file from the server, use the command 'delete' followed by the name of the file you want to delete. The server will ask you for confirmation before proceeding with the deletion of the file.\n"
                                "- list: to get the list of files available on your folder on the server, use the command 'list'.\n"
                                "- rename: to rename a file on the server, use the command 'rename' followed by the name of the file you want to rename and the new name you want to assign to it. If this is not possible, the name of the file will not be changed.\n"
                                "- logout: to close the connection with the server correctly, use the command 'logout'.\n\n"
                                "Enter the command after the character \">\" and press enter to send it to the server.\n\n";

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
    unsigned int server_counter;
    unsigned int client_counter;
};

class CommandClient
{
public:
    virtual ~CommandClient() = default;
    virtual bool validate_command(Session *session, const std::string command) = 0;
    virtual bool execute(Session *session, const std::string command) = 0;
};

class UploadClient : public CommandClient
{
public:
    bool validate_command(Session *session, const std::string command) override;
    bool execute(Session *session, const std::string command) override;
};

class DownloadClient : public CommandClient
{
public:
    bool validate_command(Session *session, const std::string command) override;
    bool execute(Session *session, const std::string command) override;
};

class DeleteClient : public CommandClient
{
public:
    bool validate_command(Session *session, const std::string command) override;
    bool execute(Session *session, const std::string command) override;
};

class ListClient : public CommandClient
{
public:
    bool validate_command(Session *session, const std::string command) override;
    bool execute(Session *session, const std::string command) override;
};

class RenameClient : public CommandClient
{
public:
    bool validate_command(Session *session, const std::string command) override;
    bool execute(Session *session, const std::string command) override;
};

class LogoutClient : public CommandClient
{
public:
    bool validate_command(Session *session, const std::string command) override;
    bool execute(Session *session, const std::string command) override;
};

bool send_message(Session *client_session, const std::string payload);
bool send_message(Session *session, const std::string payload, bool send_not_last_message, unsigned int not_last_message);
bool receive_message(Session *server_session, std::string *payload);
bool receive_message(Session *server_session, std::string *payload, bool receive_not_last_message, unsigned int *not_last_message);

// MANAGE MESSAGES
bool receive_message1(Session *client_session);
bool send_message2(Session *client_session);
bool receive_message3(Session *client_session);
bool send_message4(Session *client_session);

// MEMORY HANDLER

#ifndef BUFFER_UTILS_H
#define BUFFER_UTILS_H

template <typename T>
void delete_buffers(T *buffer);

template <typename T, typename... Ts>
void delete_buffers(T *buffer, Ts *...buffers);

#include "buffer_utils.tpp"

#endif

// CONVERSIONS

int size_t_to_int(size_t value);
size_t int_to_size_t(int value);
void serialize_int(int input, unsigned char *output);
void serialize_longint(long int value, unsigned char *buffer, size_t buffer_size);
bool deserialize_longint(const unsigned char *buffer, long int *result);
int longint_to_int(long int value);


bool recv_all(int socket, void *buffer, ssize_t len);
void log_error(const std::string &msg, bool debug);

// CERTIFICATES

bool load_certificate(std::string filename, X509 **certificate);
bool load_crl(std::string filename, X509_CRL **crl);
bool create_store(X509_STORE **store, X509 *CA_certificate, X509_CRL *crl);
bool verify_certificate(X509_STORE *store, X509 *certificate);

// ASYMMETRIC CRYPTOGRAPHY

EVP_PKEY *load_private_key(const char *private_key_file);
bool generateEphKeys(EVP_PKEY **k_priv, EVP_PKEY **k_pub);
int serialize_public_key(EVP_PKEY *public_key, unsigned char **serialized_key);
bool rsaDecrypt(const unsigned char *ciphertext, size_t ciphertextLength, EVP_PKEY *privateKey, unsigned char *&plaintext, int &plaintextLength);
EVP_PKEY *duplicate_key(EVP_PKEY *pkey, bool is_private);

// DIGITAL SIGNATURE

int create_digital_signature(EVP_PKEY *private_key, const unsigned char *data, size_t data_len, unsigned char *signature);
int verify_digital_signature(EVP_PKEY *public_key, const unsigned char *signature, unsigned int signature_len, const unsigned char *data, size_t data_len);

// AES-GCM 256

int aesgcm_encrypt(const unsigned char *plaintext,
                   int plaintext_len,
                   const unsigned char *aad, int aad_len,
                   const unsigned char *key,
                   const unsigned char *iv,
                   unsigned char *ciphertext,
                   unsigned char *tag);

int aesgcm_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                   const unsigned char *aad, int aad_len,
                   unsigned char *tag,
                   const unsigned char *key,
                   const unsigned char *iv,
                   unsigned char *plaintext);
               

#endif
