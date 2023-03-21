#ifndef UTILS_H
#define UTILS_H

#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cstring>
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

#define USERNAMESIZE 25
#define NONCE_LEN 16

const int MAX_BUF_SIZE = 65536;

extern int cl_index_free_buf;
extern unsigned char *cl_free_buf[MAX_BUF_SIZE];
extern int sv_index_free_buf;
extern unsigned char *sv_free_buf[MAX_BUF_SIZE];

// MEMORY HANDLER

// void free_var(int side);
// void memory_handler(int side, int socket, int new_size, unsigned char **new_buf);
void free_allocated_buffers(unsigned char *buffer_array[]);
int allocate_and_store_buffer(unsigned char *buffer_array[], int socket, int new_size, unsigned char **new_buf_ptr);
void serialize_int(int val, unsigned char *c);
void serialize_longint(long int val, unsigned char *c);

// CERTIFICATES

int load_certificate(std::string filename, X509 **certificate);
int load_crl(std::string filename, X509_CRL **crl);
int create_store(X509_STORE **store, X509 *CA_certificate, X509_CRL *crl);
int verify_certificate(X509_STORE *store, X509 *certificate);
EVP_PKEY *load_public_key(const char *public_key_file);

// AES-128 GCM

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