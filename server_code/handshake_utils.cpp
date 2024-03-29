#include "utils.h"

/**
 * @brief Server sends a nonce to the client
 * 
 * @param server_session server's session struct
 * @return true if the message is sent correctly, false otherwise
 */
bool send_message1(Session *server_session)
{
    // Generate nonce
    unsigned char *nonceS = new unsigned char[NONCE_LEN];
    if (RAND_bytes(nonceS, NONCE_LEN) != 1)
    {
        log_error("Error generating nonce");
        delete_buffers(nonceS);
        return false;
    }

    // Add nonce to server session
    memcpy(server_session->nonceServer, nonceS, NONCE_LEN);

    // Send message to the server over the socket
    if (send(server_session->socket, nonceS, NONCE_LEN, 0) < 0)
    {
        log_error("Error sending message");
        delete_buffers(nonceS);
        return false;
    }
    std::cout << "Nonce sent to client" << std::endl;
    delete_buffers(nonceS);
    return true;
}

/**
 * @brief Server receives a nonce, a username and an ephemeral key from the client.
 * It checks if the user is registered, if the nonce is correct and if the ephemeral key is valid.
 * All the informations are signed by the client. The server verifies the signature.
 * 
 * @param server_session server's session struct
 * @return true if the message is received correctly, false otherwise
 */
bool receive_message2(Session *server_session)
{  
    // Read nonce
    unsigned char *nonce = new unsigned char[NONCE_LEN];
    if (!recv_all(server_session->socket, (void *)nonce, NONCE_LEN))
    {
        log_error("Failed to receive the nonce");
        delete_buffers(nonce);
        return false;
    }

    // Read username length from the socket and deserialize it
    unsigned int user_len;
    unsigned char *username_len_byte = new unsigned char[sizeof(int)];
    if (!recv_all(server_session->socket, (void *)username_len_byte, sizeof(int)))
    {
        log_error("Failed to read username length");
        delete_buffers(nonce, username_len_byte);
        return false;
    }
    memcpy(&user_len, username_len_byte, sizeof(int));

    // Read username from the socket
    unsigned char *username = new unsigned char[user_len];
    if (!recv_all(server_session->socket, (void *)username, user_len))
    {
        log_error("Failed to receive the username");
        delete_buffers(nonce, username_len_byte, username);
        return false;
    }

    // Convert username from unsigned char to string
    auto username_str = std::string(reinterpret_cast<char *>(username), user_len);

    // Check if the username is valid
    if (username_str.empty() || username_str.size() > USERNAMESIZE || !std::regex_match(username_str, username_pattern))
    {
        log_error("Invalid username");
        delete_buffers(nonce, username_len_byte, username);
        return false;
    }

    // Check if the user is registered
    if (!isRegistered(username_str))
    {
        log_error("User not registered");
        delete_buffers(nonce, username_len_byte, username);
        return false;
    }

    // Read key length from the socket and deserialize it
    unsigned int key_len;
    unsigned char *key_len_byte = new unsigned char[sizeof(int)];
    if (!recv_all(server_session->socket, (void *)key_len_byte, sizeof(int)))
    {
        log_error("Failed to read key length");
        delete_buffers(nonce, username_len_byte, username, key_len_byte);
        return false;
    }
    memcpy(&key_len, key_len_byte, sizeof(int));

    // Read serialized ephemeral key from the socket
    unsigned char *serialized_eph_key_pub = new unsigned char[key_len];
    if (!recv_all(server_session->socket, (void *)serialized_eph_key_pub, key_len))
    {
        log_error("Failed to receive the ephemeral key");
        delete_buffers(nonce, username_len_byte, username, key_len_byte, serialized_eph_key_pub);
        return false;
    }

    // Deserialize the ephemeral key
    EVP_PKEY *eph_key_pub = nullptr;
    if ((eph_key_pub = deserialize_public_key(serialized_eph_key_pub, key_len)) == nullptr)
    {
        log_error("Failed to deserialize the ephemeral key");
        delete_buffers(nonce, username_len_byte, username, key_len_byte, serialized_eph_key_pub);
        return false;
    }

    // receive nonceS
    unsigned char *nonceS = new unsigned char[NONCE_LEN];
    if (!recv_all(server_session->socket, (void *)nonceS, NONCE_LEN))
    {
        log_error("Failed to receive the nonceS");
        delete_buffers(nonce, username_len_byte, username, key_len_byte, serialized_eph_key_pub, nonceS);
        EVP_PKEY_free(eph_key_pub);
        return false;
    }

    // check nonceS
    if (memcmp(nonceS, server_session->nonceServer, NONCE_LEN) != 0)
    {
        log_error("NonceS is not equal to nonceServer");
        delete_buffers(nonce, username_len_byte, username, key_len_byte, serialized_eph_key_pub, nonceS);
        EVP_PKEY_free(eph_key_pub);
        return false;
    }

    // Read signature length from the socket and deserialize it
    unsigned int signature_len;
    unsigned char *signature_len_byte = new unsigned char[sizeof(int)];
    if (!recv_all(server_session->socket, (void *)signature_len_byte, sizeof(int)))
    {
        log_error("Failed to read signature length");
        delete_buffers(nonce, username_len_byte, username, key_len_byte, serialized_eph_key_pub, nonceS, signature_len_byte);
        EVP_PKEY_free(eph_key_pub);
        return false;
    }
    memcpy(&signature_len, signature_len_byte, sizeof(int));

    // Read signature from the socket
    unsigned char *signature = new unsigned char[signature_len];
    if (!recv_all(server_session->socket, (void *)signature, signature_len))
    {
        log_error("Failed to receive the signature");
        delete_buffers(nonce, username_len_byte, username, key_len_byte, serialized_eph_key_pub, nonceS, signature_len_byte, signature);
        EVP_PKEY_free(eph_key_pub);
        return false;
    }

    // Load the client public key in order to verify the signature
    char abs_path[MAX_PATH];
    getcwd(abs_path, MAX_PATH);
    std::string path = std::string(abs_path) + "/server_file/public_keys/" + username_str + "_public_key.pem";
    EVP_PKEY *client_public_key = load_public_key(path.c_str());
    if (client_public_key == nullptr)
    {
        log_error("Failed to load the client public key");
        delete_buffers(nonce, username_len_byte, username, key_len_byte, serialized_eph_key_pub, nonceS, signature_len_byte, signature);
        EVP_PKEY_free(eph_key_pub);
        return false;
    }

    // Calculate the length of the data to verify and allocate the buffer
    int to_verify_len = NONCE_LEN + sizeof(int) + user_len + sizeof(int) + key_len + NONCE_LEN;
    unsigned char *to_verify = new unsigned char[to_verify_len];

    // Copy nonce, username, key length and ephemeral public key into the buffer to verify
    // TO_VERIFY: nonce | username_len | username | key_len | ephemeral_key | nonceS
    memcpy(to_verify, nonce, NONCE_LEN);
    memcpy(to_verify + NONCE_LEN, username_len_byte, sizeof(int));
    memcpy(to_verify + NONCE_LEN + sizeof(int), username, user_len);
    memcpy(to_verify + NONCE_LEN + sizeof(int) + user_len, key_len_byte, sizeof(int));
    memcpy(to_verify + NONCE_LEN + sizeof(int) + user_len + sizeof(int), serialized_eph_key_pub, key_len);
    memcpy(to_verify + NONCE_LEN + sizeof(int) + user_len + sizeof(int) + key_len, nonceS, NONCE_LEN);

    // Verify the signature
    if ((verify_digital_signature(client_public_key, signature, signature_len, to_verify, to_verify_len)) != 1)
    {
        log_error("Failed to verify the signature");
        delete_buffers(nonce, username_len_byte, username, key_len_byte, serialized_eph_key_pub, nonceS, signature_len_byte, signature, to_verify);
        EVP_PKEY_free(client_public_key);
        EVP_PKEY_free(eph_key_pub);
        return false;
    }
    
    // Add nonce to server session in order to retrieve it later
    memcpy(server_session->nonceClient, nonce, NONCE_LEN);

    // Print the username of the connected user
    std::cout << "User " << username_str << "connected" << std::endl;
    // Add username and ephemeral key to server session
    server_session->username = username_str;
    
    std::cout << "Username: " << server_session->username << std::endl;
    server_session->eph_key_pub = duplicate_key(eph_key_pub);

    // Free buffers
    delete_buffers(nonce, username_len_byte, username, key_len_byte, serialized_eph_key_pub, nonceS, signature_len_byte, signature, to_verify);
    EVP_PKEY_free(client_public_key);
    EVP_PKEY_free(eph_key_pub);
    return true;
}

/**
 * @brief The server sends the certificate, generates a session key and sends it encrypted with the ephemeral client public key.
 * The server also signs the encrypted session key and the nonceClient and sends the signature to the client.
 * 
 * @param server_session server's session struct
 * @param server_private_key server's private key
 * @return true if the message has been sent successfully, false otherwise
 */
bool send_message3(Session *server_session, EVP_PKEY *server_private_key)
{
    // CERTIFICATE

    // Get the absolute path of the certificate file
    char abs_path[MAX_PATH];
    getcwd(abs_path, MAX_PATH);
    std::string path = std::string(abs_path) + "/server_file/cert/server_cert.pem";

    // Load the certificate
    X509 *certificate = nullptr;
    if (!load_certificate(path, &certificate))
    {
        log_error("Failed to load the certificate");
        return false;
    }

    // Serialize the certificate
    unsigned char *certificate_byte = nullptr;
    int cert_len = i2d_X509(certificate, &certificate_byte);
    if (cert_len < 0)
    {
        log_error("Failed to serialize the certificate");
        X509_free(certificate);
        return false;
    }

    // Serialize the certificate length
    unsigned char *cert_len_byte = new unsigned char[sizeof(int)];
    serialize_int(cert_len, cert_len_byte);

    // SESSION KEY
    // Generate an AES key for session communications
    unsigned char *plaintext = new unsigned char[EVP_CIPHER_key_length(EVP_aes_256_gcm())];
    if (!RAND_bytes(plaintext, EVP_CIPHER_key_length(EVP_aes_256_gcm())))
    {
        log_error("Error generating AES key");
        delete_buffers(cert_len_byte, plaintext);
        X509_free(certificate);
        OPENSSL_free(certificate_byte);
        return false;
    }

    // Add session key to server session
    memcpy(server_session->aes_key, plaintext, EVP_CIPHER_key_length(EVP_aes_256_gcm()));

    // Allocate buffers for the ciphertext, envelope IV, and encrypted envelope key
    unsigned char *ciphertext;
    int ciphertext_len;
    // Encrypt the session key with the client's public key
    if (!rsaEncrypt(plaintext, EVP_CIPHER_key_length(EVP_aes_256_gcm()), server_session->eph_key_pub, ciphertext, ciphertext_len))
    {
        log_error("Error encrypting the session key");
        delete_buffers(cert_len_byte, plaintext);
        X509_free(certificate);
        OPENSSL_free(certificate_byte);
        return false;
    }
    // DIGITAL SIGNATURE
    // Serialize the ciphertext length and the encrypted envelope key length
    unsigned char *ciphertext_len_byte = new unsigned char[sizeof(long int)];
    serialize_longint(ciphertext_len, ciphertext_len_byte, sizeof(long int));

    // Allocate the buffer for the to_sign data
    // to_sign: ciphertext_len + ciphertext + nonceC
    size_t to_sign_len = sizeof(long int) + ciphertext_len + NONCE_LEN;
    unsigned char *to_sign = new unsigned char[to_sign_len];

    // Copy the data to the to_sign buffer
    memcpy(to_sign, ciphertext_len_byte, sizeof(long int));
    memcpy(to_sign + sizeof(long int), ciphertext, ciphertext_len);
    memcpy(to_sign + sizeof(long int) + ciphertext_len, server_session->nonceClient, NONCE_LEN);

    // Create the digital signature
    int signature_len = EVP_PKEY_size(server_private_key);
    unsigned char *signature = new unsigned char[signature_len];
    if (create_digital_signature(server_private_key, to_sign, size_t_to_int(to_sign_len), signature) != signature_len)
    {
        log_error("Failed to create digital signature");
        delete_buffers(cert_len_byte, plaintext, ciphertext, ciphertext_len_byte, to_sign, signature);
        X509_free(certificate);
        OPENSSL_free(certificate_byte);
        return false;
    }

    // Allocate the buffer for the payload size
    // payload: cert len | certificate | to sign len | to sign | signature len | signature | nonceS
    unsigned char *to_sign_len_byte = new unsigned char[sizeof(int)];
    unsigned char *signature_len_byte = new unsigned char[sizeof(int)];

    // Serialize the payload size, the to_sign length, and the signature length
    serialize_longint(to_sign_len, to_sign_len_byte, sizeof(long int));
    serialize_int(signature_len, signature_len_byte);

    // Allocate the message buffer
    size_t message_size = sizeof(int) + cert_len + sizeof(long int) + to_sign_len + sizeof(int) + int_to_size_t(signature_len);
    unsigned char *message = new unsigned char[message_size];

    // Copy the data to the message buffer
    memcpy(message, cert_len_byte, sizeof(int));
    memcpy(message + sizeof(int), certificate_byte, cert_len);
    memcpy(message + sizeof(int) + cert_len, to_sign_len_byte, sizeof(long int));
    memcpy(message + sizeof(int) + cert_len + sizeof(long int), to_sign, to_sign_len);
    memcpy(message + sizeof(int) + cert_len + sizeof(long int) + to_sign_len, signature_len_byte, sizeof(int));
    memcpy(message + sizeof(int) + cert_len + sizeof(long int) + to_sign_len + sizeof(int), signature, signature_len);

    if (send(server_session->socket, message, message_size, 0) < 0)
    {
        log_error("Error sending message");
        delete_buffers(cert_len_byte, plaintext, ciphertext, ciphertext_len_byte, to_sign, signature, to_sign_len_byte, signature_len_byte, message);
        X509_free(certificate);
        OPENSSL_free(certificate_byte);
        return false;
    }

    // Free the buffers
    delete_buffers(cert_len_byte, plaintext, ciphertext, ciphertext_len_byte, to_sign, signature, to_sign_len_byte, signature_len_byte, message);
    X509_free(certificate);
    OPENSSL_free(certificate_byte);

    return true;
}

/**
 * @brief The server receives the dummy byte encrypted with the session key and checks if it is correct using the tag
 * 
 * @param server_session the server's session struct
 * @return true if the message was received and decrypted successfully, false otherwise
 */
bool receive_message4(Session *server_session)
{
    // Allocate buffers for the ciphertext and plaintext
    unsigned char *ciphertext = new unsigned char[1];
    unsigned char *plaintext = new unsigned char[1];

    // Receive the ciphertext
    if (!recv_all(server_session->socket, (void *)ciphertext, 1))
    {
        log_error("Error receiving ciphertext");
        delete_buffers(ciphertext, plaintext);
        return false;
    }
    unsigned char *aad = new unsigned char[0];
    // Allocate buffers for the tag
    unsigned char *tag = new unsigned char[TAG_LEN];

    // Receive the tag
    if (!recv_all(server_session->socket, (void *)tag, TAG_LEN))
    {
        log_error("Error receiving tag");
        delete_buffers(ciphertext, plaintext, tag, aad);
        return false;
    }

    // Allocate buffers for the IV
    unsigned char *iv = new unsigned char[IV_LEN];

    // Receive the IV
    if (!recv_all(server_session->socket, (void *)iv, IV_LEN))
    {
        log_error("Error receiving IV");
        delete_buffers(ciphertext, plaintext, tag, iv, aad);
        return false;
    }

    // Decrypt the message
    int plaintext_len = aesgcm_decrypt(ciphertext, 1, aad, 0, tag, server_session->aes_key, iv, plaintext);
    if (plaintext_len < 0)
    {
        log_error("Error decrypting message");
        delete_buffers(ciphertext, plaintext, aad, tag, iv);
        return false;
    }

    // Check if the plaintext is equal to the dummy byte
    if (plaintext[0] != 1)
    {
        log_error("Error: plaintext is not equal to the dummy byte");
        delete_buffers(ciphertext, plaintext, aad, tag, iv);
        return false;
    }

    // Free the buffers
    delete_buffers(ciphertext, plaintext, aad, tag, iv);
    return true;
}
