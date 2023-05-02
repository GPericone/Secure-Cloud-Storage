#ifndef UTILS_H
#define UTILS_H

#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cstring>
#include <dirent.h>
#include <list>
#include <filesystem>
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

using namespace std;

// #define USERNAMESIZE 25
// #define NONCE_LEN 16

const int MAX_BUF_SIZE = 65536;
const size_t MAX_PATH = 512;
const size_t NONCE_LEN = 16;
const size_t TAG_LEN = 16;
const size_t IV_LEN = EVP_CIPHER_iv_length(EVP_aes_256_gcm());
const size_t USERNAMESIZE = 25;
const std::string F_NAME = "users.csv";

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
    // TODO: Aggiungere i counter per le funzioni
};

// NONCE LIST
class NonceList
{
private:
    std::list<unsigned char *> nonce_list;

    // Compare two nonces
    static bool compare_nonces(const unsigned char *a, const unsigned char *b)
    {
        return std::strcmp(reinterpret_cast<const char *>(a), reinterpret_cast<const char *>(b)) == 0;
    }

public:
    // Insert a nonce into the list
    void insert(const unsigned char *nonce)
    {
        unsigned char *nonce_copy = new unsigned char[std::strlen(reinterpret_cast<const char *>(nonce)) + 1];
        std::strcpy(reinterpret_cast<char *>(nonce_copy), reinterpret_cast<const char *>(nonce));
        nonce_list.push_back(nonce_copy);
    }

    // Check if a nonce is in the list
    bool contains(const unsigned char *nonce) const
    {
        for (const unsigned char *stored_nonce : nonce_list)
        {
            if (compare_nonces(stored_nonce, nonce))
            {
                return true;
            }
        }
        return false;
    }

    ~NonceList()
    {
        for (unsigned char *nonce : nonce_list)
        {
            delete[] nonce;
        }
    }
};

// USER
bool isRegistered(std::string_view username);

// MANAGE MESSAGES
bool send_message1(Session *client_session);
bool receive_message1(Session *server_session, NonceList nonce_list);
bool send_message2(Session *server_session, EVP_PKEY *client_public_key, EVP_PKEY *server_private_key);
bool receive_message2(Session *client_session, EVP_PKEY *client_private_key);
bool send_message3(Session *client_session);
bool receive_message3(Session *server_session);

// MEMORY HANDLER

void free_allocated_buffers(unsigned char *buffer_array[]);
int allocate_and_store_buffer(unsigned char *buffer_array[], int socket, size_t new_size, unsigned char **new_buf_ptr);
void serialize_int(int val, unsigned char *c);
void serialize_longint(long int val, unsigned char *c);

int recv_all(int socket, void *buffer, ssize_t len);
void log_error(const std::string &msg);

// CERTIFICATES

int load_certificate(std::string filename, X509 **certificate);
int load_crl(std::string filename, X509_CRL **crl);
int create_store(X509_STORE **store, X509 *CA_certificate, X509_CRL *crl);
int verify_certificate(X509_STORE *store, X509 *certificate);
EVP_PKEY *load_public_key(const char *public_key_file);
EVP_PKEY *load_private_key(const char *private_key_file);
bool generateEphKeys(EVP_PKEY **eph_key_priv, EVP_PKEY **eph_key_pub, int key_size);
int serialize_public_key(EVP_PKEY* public_key, unsigned char** serialized_key);

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

// DIGITAL ENVELOPE

int envelope_encrypt(EVP_PKEY *public_key,
                     unsigned char *plaintext,
                     int pt_len,
                     unsigned char *sym_key_enc,
                     int sym_key_len,
                     unsigned char *iv,
                     unsigned char *ciphertext);

int envelope_decrypt(EVP_PKEY *private_key,
                     unsigned char *ciphertext,
                     int ct_len,
                     unsigned char *sym_key_enc,
                     int sym_key_len,
                     unsigned char *iv,
                     unsigned char *plaintext);
#endif

// #include <map>

// // Crea una mappa per indicizzare le sessioni per nome utente
// std::map<unsigned char, Sessione> sessioni;

// // Aggiungi una sessione alla mappa
// Sessione miaSessione = { 'user123', 'nonce123', 'aeskey123', 123 };
// sessioni[miaSessione.username] = miaSessione;

// // Accedi alla sessione per nome utente
// Sessione sessioneUtente = sessioni['user123'];