#ifndef CLOUDSTORAGEPROJECT_DATA_STRUCT_H
#define CLOUDSTORAGEPROJECT_DATA_STRUCT_H

/*		DATA STRUCTURES -- CLOUD STORAGE PROJECT -- APPLIED CRIPTOGRAPHY		*/

#include <stdio.h>
#include <cstdlib>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <iostream>
#include <string>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iomanip>
#include <fstream>
#include <openssl/err.h>
#include <openssl/pem.h>

#define PORT 4242

//  START MACRO COMMANDS
#define MAN 1
#define LIST 2
#define UPLOAD 3
#define DOWNLOAD 4
#define RENAME 5
#define DELETE 6
#define LOGOUT 7
//  END MACRO COMMANDS

//  START SIZE LMIT
#define MAX_FILE_NAME 24
//  END SIZE LIMIT

#define MAX_PATH 512
#define TAG_LEN 16
#define IV_LEN 12
#define NONCE_LEN 16
#define DUMMY_BYTE 'x'
#define OFFSET 48
#define CHUNK 1048576

// CL & SV IDENTIFIER
#define CLIENT 1
#define SERVER 0
// END

using namespace std;

// STRUCT MANAGING MEMORY
extern unsigned char *sv_free_buf[65536];
extern int sv_index_free_buf;

extern unsigned char *cl_free_buf[65536];
extern int cl_index_free_buf;

typedef struct _user
{
    int u_cl_socket;
    int u_sv_socket;
    unsigned int c_counter;
    unsigned int s_counter;
    char username[11];
    unsigned char *session_key;

    _user *next;
} user;
// END STRUCT

//	START CRYPTO UTILITY FUNCTIONS DECLARATIONS
void error_handler(const string);
int gcm_encrypt(unsigned char *, int,
                unsigned char *, int,
                unsigned char *,
                unsigned char *, int,
                unsigned char *,
                unsigned char *);
int gcm_decrypt(unsigned char *, int,
                unsigned char *, int,
                unsigned char *,
                unsigned char *,
                unsigned char *, int,
                unsigned char *);
int envelope_encrypt(EVP_PKEY *, unsigned char *, int, unsigned char *, int, unsigned char *, unsigned char *);
int envelope_decrypt(EVP_PKEY *, unsigned char *, int, unsigned char *, int, unsigned char *, unsigned char *);
int digital_sign(EVP_PKEY *, unsigned char *, int, unsigned char *);
int digital_sign_verify(EVP_PKEY *, unsigned char *, int, unsigned char *, int);
int certificate_validation(string, string, X509 *);
void eph_keys_gen(EVP_PKEY **, EVP_PKEY **);
//	END CRYPTO UTILITY FUNCTIONS DECLARATIONS

//	START UTILITY FUNCTIONS
void print_manual();

int check_cmd(unsigned char *, int);
int blacklisting_cmd(string);
int get_cmd(char *);
void stampa(user *);

void serialize_int(int, unsigned char *);
void serialize_longint(long int, unsigned char *);
int read_byte(int, void *, ssize_t);
int get_num_file(const char *);

void free_var(int);
void memory_handler(int, int, int, unsigned char **);

int split_file(unsigned char *, unsigned char **);

unsigned char *serialize_certificate(string, int *);
void deserialize_certificate(X509 *, unsigned char *, int);
int serialize_pubkey(EVP_PKEY *, unsigned char **);

void pubkey_to_PKEY(EVP_PKEY **, unsigned char *, int);
void privkey_to_PKEY(EVP_PKEY **, unsigned char *, int);

int c_authenticate(int, user **);
int s_authenticate(int, user **);

int is_auth(int, user *);
user *get_user(int, user *);
void logout(int, user **);

void print_Server_cert_info(X509 *);
void delete_key(unsigned char *, int);
//	END UTILITY FUNCTIONS

#endif // CLOUDSTORAGEPROJECT_DATA_STRUCT_H