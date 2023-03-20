#include "utils.h"

int send_message1(int socket)
{
    std::string username;
    std::cout << "Enter your username" << std::endl;
    std::cin >> username;

    // Definire la costante USERNAMESIZE nell'header
    if (username.empty() || username.size() > USERNAMESIZE)
    {
        std::cout << "Invalid username" << std::endl;
        return -1;
    }

    // Generate nonce with OpenSSL
    unsigned char nonce[NONCE_LEN];
    if (RAND_bytes(nonce, NONCE_LEN) != 1)
    {
        std::cout << "Error generating nonce" << std::endl;
        return -1;
    }

    // Calculate payload size
    unsigned char *payload_size_byte, *message;
    size_t payload_size = username.size() + NONCE_LEN;

    // Create message buffer
    // size_t message_size = sizeof(int) + payload_size;
    memory_handler(1, socket, payload_size, &payload_size_byte);
    serialize_int(payload_size, payload_size_byte);

    // Serialize payload size and copy into message buffer
    // int payload_size_network_byte_order = htonl(payload_size);

    // memcpy(message, &payload_size_network_byte_order, sizeof(int));

    int message_size = sizeof(int) + NONCE_LEN + username.size();
    memory_handler(1, socket, message_size, &message);

    // Copy nonce and username into message buffer

    memcpy(message, payload_size_byte, sizeof(int));
    memcpy((unsigned char *)&message[sizeof(int)], nonce, NONCE_LEN);
    memcpy((unsigned char *)&message[sizeof(int) + NONCE_LEN], username.c_str(), username.size());

    // Send message
    int bytes_sent = send(socket, message, message_size, 0);

    if (bytes_sent < 0)
    {
        free_var(1);
        std::cout << "Error sending message" << std::endl;
        return -1;
    }

    return 0;
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