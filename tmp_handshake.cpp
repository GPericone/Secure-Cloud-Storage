#include "utils.h"

int send_message1(int socket)
{
    std::string username;
    std::cout << "Enter your username" << std::endl;
    std::cin >> username;

    if (username.empty() || username.size() > USERNAMESIZE)
    {
        log_error("Invalid username");
        return -1;
    }

    // Generate nonce with OpenSSL

    unsigned char* nonce = NULL;
    allocate_and_store_buffer(cl_free_buf, socket, NONCE_LEN, &nonce);
    if (RAND_bytes(nonce, NONCE_LEN) != 1)
    {
        log_error("Error generating nonce");
        return -1;
    }

    // Calculate payload size

    unsigned char *payload_size_byte, *message;
    size_t payload_size = username.size() + NONCE_LEN;

    // Create message buffer

    allocate_and_store_buffer(cl_free_buf, socket, payload_size, &payload_size_byte);
    serialize_int(payload_size, payload_size_byte);

    // Serialize payload size and copy into message buffer

    int message_size = sizeof(int) + NONCE_LEN + username.size();
    allocate_and_store_buffer(cl_free_buf, socket, message_size, &message);

    // Copy nonce and username into message buffer

    memcpy(message, payload_size_byte, sizeof(int));
    memcpy((unsigned char *)&message[sizeof(int)], nonce, NONCE_LEN);
    // vedere con il cast in unsigned char di username funziona (da char a unsigned char)
    memcpy((unsigned char *)&message[sizeof(int) + NONCE_LEN], username.c_str(), username.size());

    // Send message
    int bytes_sent = send(socket, message, message_size, 0);

    if (bytes_sent < 0)
    {
        free_allocated_buffers(cl_free_buf);
        log_error("Error sending message");
        return -1;
    }

    return 0;
}

int receive_message1(int socket)
{
    int payload_len, user_len, ret;
    unsigned char *username, *nonce;
    unsigned char *payload_len_byte;
    char *abs_path;

    abs_path = (char *)malloc(MAX_PATH);
    getcwd(abs_path, MAX_PATH);

    //	READ PAYLOAD_LEN
    allocate_and_store_buffer(sv_free_buf, socket, sizeof(int), &payload_len_byte);
    if ((ret = recv_all(socket, (void *)payload_len_byte, sizeof(int))) != sizeof(int))
    {
        log_error("Failed to read payload length");
        free_allocated_buffers(sv_free_buf);
        close(socket);
        return -1;
    }

    // Deserializzazione di payload_len_byte
    memcpy(&payload_len, payload_len_byte, sizeof(int));

    //	READ USER & NONCE
    user_len = payload_len - NONCE_LEN;

    allocate_and_store_buffer(sv_free_buf, socket, user_len, &username);
    allocate_and_store_buffer(sv_free_buf, socket, NONCE_LEN, &nonce);

    // pensare ad una lista di nonce da controllare per evitare il replay attack
    if ((ret = recv_all(socket, (void *)nonce, NONCE_LEN)) != NONCE_LEN)
    {
        log_error("Failed to receive the nonce");
        free_allocated_buffers(sv_free_buf);
        close(socket);
        return -1;
    }

    if ((ret = recv_all(socket, (void *)username, user_len)) != user_len)
    {
        log_error("Failed to receive the username");
        free_allocated_buffers(sv_free_buf);
        close(socket);
        return -1;
    }

    //	CHECK USERNAME
    string username_str(reinterpret_cast<char *>(username));
    string dir_name = strncat(abs_path, "/server_src/", strlen("/server_src/"));

    DIR *dir;
    struct dirent *en;
    int check = 0;
    dir = opendir(dir_name.c_str());
    if (dir)
    {
        while ((en = readdir(dir)) != NULL)
        {
            if (!strncmp(en->d_name, username_str.c_str(), username_str.size() + 1))
                check = 1;
        }
    }
    closedir(dir);
    if (check == 0)
    {
        log_error("Username not found...");
        free_allocated_buffers(sv_free_buf);
        close(socket);
        return -1;
    }
}

// VERSIONE ALTERNATIVA receive_message1

// int receive_message1(int socket)
// {

//     // Read payload length
//     int payload_len;
//     if (recv(socket, &payload_len, sizeof(payload_len), 0) != sizeof(payload_len)) {
//         std::cerr << "Failed to read payload length" << std::endl;
//         return -1;
//     }

//     // Read username and nonce
//     std::vector<unsigned char> buf(payload_len);
//     if (recv(socket, buf.data(), buf.size(), 0) != buf.size()) {
//         std::cerr << "Failed to read payload" << std::endl;
//         return -1;
//     }

//     const unsigned char* nonce = buf.data();
//     const unsigned char* username = buf.data() + NONCE_LEN;
//     const int username_len = payload_len - NONCE_LEN;

//     // Check username
//     std::string username_str(reinterpret_cast<const char*>(username), username_len);
//     std::string dir_name = "/server_src/";
//     char abs_path[MAX_PATH];
//     if (getcwd(abs_path, MAX_PATH) == nullptr) {
//         std::cerr << "Failed to get current directory" << std::endl;
//         return -1;
//     }
//     dir_name = std::strcat(abs_path, dir_name.c_str());

//     DIR* dir = opendir(dir_name.c_str());
//     if (dir == nullptr) {
//         std::cerr << "Failed to open directory" << std::endl;
//         return -1;
//     }

//     bool check = false;
//     while (const dirent* en = readdir(dir)) {
//         if (std::strncmp(en->d_name, username_str.c_str(), username_len) == 0) {
//             check = true;
//             break;
//         }
//     }
//     closedir(dir);

//     if (!check) {
//         std::cerr << "Username not found" << std::endl;
//         return -1;
//     }

//     // Success
//     return 0;
// }

// int receive_message1(int socket)
// {

//     // Read payload length
//     int payload_len;
//     if (recv(socket, &payload_len, sizeof(payload_len), 0) != sizeof(payload_len)) {
//         std::cerr << "Failed to read payload length" << std::endl;
//         return -1;
//     }

//     // Read username and nonce
//     std::vector<unsigned char> buf(payload_len);
//     if (recv(socket, buf.data(), buf.size(), 0) != buf.size()) {
//         std::cerr << "Failed to read payload" << std::endl;
//         return -1;
//     }

//     const unsigned char* nonce = buf.data();
//     const unsigned char* username = buf.data() + NONCE_LEN;
//     const int username_len = payload_len - NONCE_LEN;

//     // Check username
//     std::string username_str(reinterpret_cast<const char*>(username), username_len);
//     std::string dir_name = "/server_src/";
//     char abs_path[MAX_PATH];
//     if (getcwd(abs_path, MAX_PATH) == nullptr) {
//         std::cerr << "Failed to get current directory" << std::endl;
//         return -1;
//     }
//     dir_name = std::strcat(abs_path, dir_name.c_str());

//     DIR* dir = opendir(dir_name.c_str());
//     if (dir == nullptr) {
//         std::cerr << "Failed to open directory" << std::endl;
//         return -1;
//     }

//     bool check = false;
//     while (const dirent* en = readdir(dir)) {
//         if (std::strncmp(en->d_name, username_str.c_str(), username_len) == 0) {
//             check = true;
//             break;
//         }
//     }
//     closedir(dir);

//     if (!check) {
//         std::cerr << "Username not found" << std::endl;
//         return -1;
//     }

//     // Success
//     return 0;
// }


int send_message2(int socket, EVP_PKEY* client_public_key, unsigned char *nonceC)
{
    char *abs_path;
    abs_path = (char *)malloc(MAX_PATH);
    getcwd(abs_path, MAX_PATH);
    std::string path = std::string(abs_path) + "/server_src/cert/servercert.pem";

    // Carica il certificato
    X509 *certificate = nullptr;
    if (load_certificate(path, &certificate) != 0) {
        std::cerr << "Failed to load the certificate" << std::endl;
        return -1;
    }

    // Serializza il certificato usando i2d_X509
    unsigned char *buffer = nullptr;
    int cert_len = i2d_X509(certificate, &buffer);
    if (cert_len < 0) {
        log_error("Failed to serialize the certificate");
        free_allocated_buffers(sv_free_buf);
        return -1;
    }

    unsigned char *cert_len_byte = nullptr;
    allocate_and_store_buffer(sv_free_buf, socket, sizeof(int), &cert_len_byte);
    serialize_int(cert_len, cert_len_byte);
    
    unsigned char *nonceS = nullptr;
    allocate_and_store_buffer(sv_free_buf, socket, NONCE_LEN, &nonceS);
    if (RAND_bytes(nonceS, NONCE_LEN) != 1)
    {
        log_error("Error generating nonce");
        return -1;
    }

    // Libera le risorse
    X509_free(certificate);
    OPENSSL_free(buffer);
    free(abs_path);
}

// int send_message2(int socket, std::string username, X509* certificate, EVP_PKEY* server_private_key, unsigned char nonceC[])
// {
//     // 1. Load client public key from .pem file
//     std::string client_public_key_file_str = "clients/keys/publickey" + username + ".pem";
//     const char* client_public_key_file = client_public_key_file_str.c_str();
//     EVP_PKEY* client_public_key = load_public_key(client_public_key_file);
//     if (!client_public_key)
//     {
//         return -1;
//     }

//     // 2. Generate nonceS
//     unsigned char nonceS[NONCE_LEN];
//     if (RAND_bytes(nonceS, NONCE_LEN) != 1)
//     {
//         std::cerr << "Error generating nonceS" << std::endl;
//         EVP_PKEY_free(client_public_key);
//         return -1;
//     }

//     // 3. Create AES-256 session key
//     unsigned char session_key[32];
//     if (RAND_bytes(session_key, sizeof(session_key)) != 1)
//     {
//         std::cerr << "Error generating session key" << std::endl;
//         EVP_PKEY_free(client_public_key);
//         return -1;
//     }

//     // 4. Prepare the envelope
//     unsigned char plaintext[32 + NONCE_LEN];
//     memcpy(plaintext, session_key, sizeof(session_key));
//     memcpy(plaintext + sizeof(session_key), nonceC, NONCE_LEN);

//     unsigned char encrypted_envelope[256];
//     unsigned char sym_key_enc[EVP_PKEY_size(client_public_key)];
//     int sym_key_len;
//     unsigned char iv[EVP_MAX_IV_LENGTH];
//     int encrypted_envelope_len;

//     // 5. Encrypt the envelope
//     encrypted_envelope_len = envelope_encrypt(client_public_key, plaintext, sizeof(plaintext), sym_key_enc, sym_key_len, iv, encrypted_envelope);
//     EVP_PKEY_free(client_public_key);

//     if (encrypted_envelope_len < 0)
//     {
//         return -1;
//     }

//     // 6. Serialize the certificate
//     unsigned char* cert_buf;
//     int cert_len = i2d_X509(certificate, &cert_buf);
//     if (cert_len < 0)
//     {
//         std::cerr << "Error serializing certificate" << std::endl;
//         return -1;
//     }

//     // 7. Create and send message
//     size_t payload_size = sizeof(int) + cert_len + sizeof(int) + encrypted_envelope_len + sizeof(nonceS);
//     size_t message_size = sizeof(int) + payload_size;
//     unsigned char* message = new unsigned char[message_size];

//     // Copy payload data into message buffer
//     int offset = sizeof(int);
//     memcpy(message + offset, &cert_len, sizeof(int));
//     offset += sizeof(int);
//     memcpy(message + offset, cert_buf, cert_len);
//     offset += cert_len;
//     memcpy(message + offset, &encrypted_envelope_len, sizeof(int));
//     offset += sizeof(int);
//     memcpy(message + offset, encrypted_envelope, encrypted_envelope_len);
//     offset += encrypted_envelope_len;
//     memcpy(message + offset, nonceS, sizeof(nonceS));

//     // Set total message size
//     int message_size_n = htonl(static_cast<int>(message_size));
//     memcpy(message, &message_size_n, sizeof(int));

//     // Send message
//     int bytes_sent = send(socket, message, message_size, 0);
//     if (bytes_sent < 0)
//     {
//         std::cerr << "Error sending message" << std::endl;
//     }

//     delete[] message;
//     OPENSSL_free(cert_buf);

//     return bytes_sent;
// }

// int send_message3(int socket, unsigned char* nonceS, EVP_PKEY* client_private_key)
// {

//     int ret;

//     // Encrypt the nonceS with the client's private key
//     unsigned char encrypted_nonceS[RSA_size(client_private_key)];
//     int encrypted_nonceS_len;

//     ret = RSA_private_encrypt(NONCE_LEN, nonceS, encrypted_nonceS,
//                               EVP_PKEY_get0_RSA(client_private_key), RSA_PKCS1_PADDING);

//     if (ret < 0) {
//         std::cerr << "Error encrypting NonceS" << std::endl;
//         return -1;
//     }
//     encrypted_nonceS_len = ret;

//     // Calculate payload size
//     size_t payload_size = encrypted_nonceS_len;

//     // Create message buffer
//     size_t message_size = sizeof(int) + payload_size;
//     unsigned char* message = new unsigned char[message_size];

//     // Serialize payload size and copy into message buffer
//     int payload_size_network_byte_order = htonl(payload_size);
//     memcpy(message, &payload_size_network_byte_order, sizeof(int));

//     // Copy encrypted_nonceS into message buffer
//     memcpy(message + sizeof(int), encrypted_nonceS, encrypted_nonceS_len);

//     // Send message
//     int bytes_sent = send(socket, message, message_size, 0);
//     delete[] message;

//     if (bytes_sent < 0) {
//         std::cerr << "Error sending message" << std::endl;
//         return -1;
//     }

//     return 0;
// }