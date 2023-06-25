#ifndef UTILS_H
#define UTILS_H

#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
// #include <string.h>
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
//
#include <list>
#include <sstream>
#include <vector>
#include <condition_variable>
#include <memory>
#include <cstdarg>
#include <sys/stat.h>
#include <regex>

const int CHUNK_SIZE = 1000000;
const size_t MAX_PATH = 512;
const size_t NONCE_LEN = 16;
const size_t TAG_LEN = 16;
const int IV_LEN = EVP_CIPHER_iv_length(EVP_aes_256_gcm());
const size_t USERNAMESIZE = 25;
const std::string instruction = "La comunicazione è stata messa in sicurezza, adesso è possibile eseguire le seguenti operazioni:\n\n"
                            "- upload: per caricare un file dal tuo computer al server, utilizza il comando 'Upload' seguito dal nome del file che vuoi caricare. Il server salverà il file con il nome specificato da te. Se ciò non fosse possibile, il file non verrà caricato. Il limite di dimensione per il file caricato è di 4GB.\n"
                            "- download: per scaricare un file dal server, utilizza il comando 'Download' seguito dal nome del file che vuoi scaricare. Il nome del file scaricato sarà lo stesso usato dal server per salvarlo. Se ciò non fosse possibile, il file non verrà scaricato.\n"
                            "- delete: per eliminare un file dal server, utilizza il comando 'Delete' seguito dal nome del file che vuoi eliminare. Il server ti chiederà conferma prima di procedere con l'eliminazione del file.\n"
                            "- list: per ottenere la lista dei file disponibili sul server, utilizza il comando 'List'. La lista verrà stampata sullo schermo del client.\n"
                            "- rename: per rinominare un file sul server, utilizza il comando 'Rename' seguito dal nome del file che vuoi rinominare e dal nuovo nome che vuoi assegnargli. Se ciò non fosse possibile, il nome del file non verrà cambiato.\n"
                            "- logout: per chiudere la connessione con il server in modo corretto, utilizza il comando 'LogOut'.\n\n"
                            "Inserisci il comando dopo il carattere \">\" e premi invio per spedirlo al server.\n\n";

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
    virtual bool execute(Session *session, const std::string command) = 0;
};

class UploadClient : public CommandClient
{
public:
    bool execute(Session *session, const std::string command) override;
};

class DownloadClient : public CommandClient
{
public:
    bool execute(Session *session, const std::string command) override;
};

class DeleteClient : public CommandClient
{
public:
    bool execute(Session *session, const std::string command) override;
};

class ListClient : public CommandClient
{
public:
    bool execute(Session *session, const std::string command) override;
};

class RenameClient : public CommandClient
{
public:
    bool execute(Session *session, const std::string command) override;
};

class LogoutClient : public CommandClient
{
public:
    bool execute(Session *session, const std::string command) override;
};

bool send_message(Session *client_session, const std::string payload);
bool send_message(Session *session, const std::string payload, bool send_esito, unsigned int esito);
bool receive_message(Session *server_session, std::string *payload);
bool receive_message(Session *server_session, std::string *payload, bool receive_esito, unsigned int *esito);

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

int size_t_to_int(size_t value);
void serialize_int(int input, unsigned char *output);
void serialize_longint(long int value, unsigned char *buffer, size_t buffer_size);

bool recv_all(int socket, void *buffer, ssize_t len);
void log_error(const std::string &msg);

// CERTIFICATES

bool load_certificate(std::string filename, X509 **certificate);
bool load_crl(std::string filename, X509_CRL **crl);
bool create_store(X509_STORE **store, X509 *CA_certificate, X509_CRL *crl);
bool verify_certificate(X509_STORE *store, X509 *certificate);

// ASYMMETRIC KEYS

EVP_PKEY *load_private_key(const char *private_key_file);
bool generateEphKeys(EVP_PKEY **k_priv, EVP_PKEY **k_pub);
int serialize_public_key(EVP_PKEY *public_key, unsigned char **serialized_key);

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

bool rsaDecrypt(const unsigned char *ciphertext, size_t ciphertextLength, EVP_PKEY *privateKey, unsigned char *&plaintext, int &plaintextLength);

EVP_PKEY* duplicate_key(EVP_PKEY* pkey, bool is_private);

#endif
