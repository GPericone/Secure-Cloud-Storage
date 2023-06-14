#include "utils.h"

bool send_message0(Session *server_session)
{
    // genera il nonce del server e lo invia
    unsigned char *nonceS = new unsigned char[NONCE_LEN];
    if (RAND_bytes(nonceS, NONCE_LEN) != 1)
    {
        log_error("Error generating nonce");
        return false;
    }

    // Add nonce to server session
    memcpy(server_session->nonceServer, nonceS, NONCE_LEN);

    // Send message to the server over the socket
    if (int bytes_sent = send(server_session->socket, nonceS, NONCE_LEN, 0); bytes_sent < 0)
    {
        log_error("Error sending message");
        return false;
    }
    printf("Nonce sent to client\n");
    return true;
}

bool receive_message0(Session *client_session)
{
    // riceve il nonce del server e lo salva
    unsigned char *nonceS = new unsigned char[NONCE_LEN];
    if (int bytes_received = recv(client_session->socket, nonceS, NONCE_LEN, 0); bytes_received < 0)
    {
        log_error("Error receiving message");
        return false;
    }
    memcpy(client_session->nonceServer, nonceS, NONCE_LEN);
    printf("Nonce received from server\n");
    return true;
}

/**
 * @brief Sends a message containing the client's username, a nonce, the client's ephemeral public key and a signature of this informations.
 *
 * This function sends a message to the server over the specified socket.
 * The message includes the user's username, a nonce, and the user's ephemeral public key.
 * The message is signed using the user's private key.
 *
 * @param client_session The client's session, containing the socket and where the username, nonce, and ephemeral key will be stored.
 *
 * @return true on success, false on failure.
 */
bool send_message1(Session *client_session)
{
    // Prompt the user for their username
    std::string username;
    std::cout << "Enter your username" << std::endl;
    std::cin >> username;

    // Check username
    if (username.empty() || username.size() > USERNAMESIZE)
    {
        log_error("Invalid username");
        return false;
    }

    // Load the client private key
    char abs_path[MAX_PATH];
    getcwd(abs_path, MAX_PATH);
    std::string path = std::string(abs_path) + "/client_file/keys/" + username + "_private_key.pem";
    EVP_PKEY *client_private_key = load_private_key(path.c_str());
    if (client_private_key == nullptr)
    {
        log_error("Failed to load the client private key");
        return false;
    }

    // Generate ephemeral keys
    EVP_PKEY *eph_key_priv = nullptr;
    EVP_PKEY *eph_key_pub = nullptr;

    if (!generateEphKeys(&eph_key_priv, &eph_key_pub))
    {
        log_error("Error generating ephemeral keys");
        EVP_PKEY_free(client_private_key);
        return false;
    }

    // Serialize the username length
    unsigned char *username_len_byte = new unsigned char[sizeof(int)];
    serialize_int(safe_size_t_to_int(username.size()), username_len_byte);

    // Add username and ephemeral keys to client session
    client_session->username = username;
    client_session->eph_key_priv = EVP_PKEY_dup(eph_key_priv);
    client_session->eph_key_pub = EVP_PKEY_dup(eph_key_pub);

    // Generate a client nonce
    unsigned char *nonce = new unsigned char[NONCE_LEN];
    if (RAND_bytes(nonce, NONCE_LEN) != 1)
    {
        log_error("Error generating nonce");
        delete_buffers(username_len_byte, nonce);
        EVP_PKEY_free(client_private_key);
        EVP_PKEY_free(eph_key_priv);
        EVP_PKEY_free(eph_key_pub);
        return false;
    }
    // Add nonce to client session in order to check if it is the same as the one received from the server
    memcpy(client_session->nonceClient, nonce, NONCE_LEN);

    // Serialize the ephemeral public key
    unsigned char *serialized_eph_key_pub = new unsigned char[2048];
    int key_len = serialize_public_key(eph_key_pub, &serialized_eph_key_pub);

    // Calculate signature length and allocate the buffer
    int signature_len = EVP_PKEY_size(client_private_key);
    unsigned char *signature = new unsigned char[signature_len];

    // Calculate the length of the data to sign and allocate the buffer
    int to_sign_len = NONCE_LEN + sizeof(int) + safe_size_t_to_int(username.size()) + sizeof(int) + key_len + NONCE_LEN;
    unsigned char *to_sign = new unsigned char[to_sign_len];

    // Serialize the key length
    unsigned char *key_len_byte = new unsigned char[sizeof(int)];
    serialize_int(key_len, key_len_byte);

    // Copy nonce, username, key length and ephemeral public key into the buffer to sign
    // to_sign: nonce | username_len | username | key_len | ephemeral_key | nonceS
    memcpy(to_sign, nonce, NONCE_LEN);
    memcpy(to_sign + NONCE_LEN, username_len_byte, sizeof(int));
    memcpy(to_sign + NONCE_LEN + sizeof(int), username.c_str(), username.size());
    memcpy(to_sign + NONCE_LEN + sizeof(int) + username.size(), key_len_byte, sizeof(int));
    memcpy(to_sign + NONCE_LEN + sizeof(int) + username.size() + sizeof(int), serialized_eph_key_pub, key_len);
    memcpy(to_sign + NONCE_LEN + sizeof(int) + username.size() + sizeof(int) + key_len, client_session->nonceServer, NONCE_LEN);

    // Sign the buffer
    if (create_digital_signature(client_private_key, to_sign, to_sign_len, signature) != signature_len)
    {
        log_error("Failed to create digital signature");
        delete_buffers(username_len_byte, nonce, serialized_eph_key_pub, signature, to_sign, key_len_byte);
        EVP_PKEY_free(client_private_key);
        EVP_PKEY_free(eph_key_priv);
        EVP_PKEY_free(eph_key_pub);
        return false;
    }

    // Serialize signature length
    unsigned char *signature_len_byte = new unsigned char[sizeof(int)];
    serialize_int(signature_len, signature_len_byte);

    // Calculate payload size
    int payload_size = to_sign_len + sizeof(int) + signature_len;

    // Serialize payload size
    unsigned char *payload_size_byte = new unsigned char[sizeof(int)];
    serialize_int(payload_size, payload_size_byte);

    // Calculate message size and allocate the buffer
    int message_size = sizeof(int) + payload_size;
    unsigned char *message = new unsigned char[message_size];

    // Copy payload size, buffer to sign and signature into the message
    // message: payload_size | nonce | username_len | username | key_len | ephemeral_key | signature_len | signature
    memcpy(message, payload_size_byte, sizeof(int));
    memcpy(message + sizeof(int), to_sign, to_sign_len);
    memcpy(message + sizeof(int) + to_sign_len, signature_len_byte, sizeof(int));
    memcpy(message + sizeof(int) + to_sign_len + sizeof(int), signature, signature_len);

    // Send message to the server over the socket
    if (int bytes_sent = send(client_session->socket, message, message_size, 0); bytes_sent < 0)
    {
        log_error("Error sending message");
        delete_buffers(username_len_byte, nonce, serialized_eph_key_pub, signature, to_sign, key_len_byte, signature_len_byte, payload_size_byte, message);
        EVP_PKEY_free(client_private_key);
        EVP_PKEY_free(eph_key_priv);
        EVP_PKEY_free(eph_key_pub);
        return false;
    }

    // Free buffers
    delete_buffers(username_len_byte, nonce, serialized_eph_key_pub, signature, to_sign, key_len_byte, signature_len_byte, payload_size_byte, message);
    EVP_PKEY_free(client_private_key);
    EVP_PKEY_free(eph_key_priv);
    EVP_PKEY_free(eph_key_pub);
    return true;
}

/**
 * @brief Receives a message containing the client's username, a nonce, the client's ephemeral public key and a signature of this informations.
 *
 * This function receives a message from the client over the specified socket.
 * The message includes the user's username, a nonce, and the user's ephemeral public key.
 * The message is signed using the user's private key.
 *
 * @param server_session The server's session, containing the socket and where the username, nonce, and ephemeral key will be stored.
 * @param nonce_list The list of nonces, used to prevent replay attacks.
 *
 * @return true on success, false on failure.
 */
bool receive_message1(Session *server_session, NonceList nonce_list)
{

    // Read payload length from the socket and deserialize it
    int payload_len;
    unsigned char *payload_len_byte = new unsigned char[sizeof(int)];
    if ((recv_all(server_session->socket, (void *)payload_len_byte, sizeof(int))) != sizeof(int))
    {
        log_error("Failed to read payload length");
        delete_buffers(payload_len_byte);
        return false;
    }
    memcpy(&payload_len, payload_len_byte, sizeof(int));

    // Read nonce
    unsigned char *nonce = new unsigned char[NONCE_LEN];
    if ((recv_all(server_session->socket, (void *)nonce, NONCE_LEN)) != NONCE_LEN)
    {
        log_error("Failed to receive the nonce");
        delete_buffers(payload_len_byte, nonce);
        return false;
    }

    // Read username length from the socket and deserialize it
    int user_len;
    unsigned char *username_len_byte = new unsigned char[sizeof(int)];
    if ((recv_all(server_session->socket, (void *)username_len_byte, sizeof(int))) != sizeof(int))
    {
        log_error("Failed to read username length");
        delete_buffers(payload_len_byte, nonce, username_len_byte);
        return false;
    }
    memcpy(&user_len, username_len_byte, sizeof(int));

    // Read username from the socket
    unsigned char *username = new unsigned char[user_len];
    if ((recv_all(server_session->socket, (void *)username, user_len)) != user_len)
    {
        log_error("Failed to receive the username");
        delete_buffers(payload_len_byte, nonce, username_len_byte, username);
        return false;
    }

    // Convert username from unsigned char to string
    auto username_str = std::string(reinterpret_cast<char *>(username), user_len);

    // Check if the user is registered
    if (!isRegistered(username_str))
    {
        log_error("User not registered");
        delete_buffers(payload_len_byte, nonce, username_len_byte, username);
        return false;
    }

    // Read key length from the socket and deserialize it
    int key_len;
    unsigned char *key_len_byte = new unsigned char[sizeof(int)];
    if ((recv_all(server_session->socket, (void *)key_len_byte, sizeof(int))) != sizeof(int))
    {
        log_error("Failed to read key length");
        delete_buffers(payload_len_byte, nonce, username_len_byte, username, key_len_byte);
        return false;
    }
    memcpy(&key_len, key_len_byte, sizeof(int));

    // Read serialized ephemeral key from the socket
    unsigned char *serialized_eph_key_pub = new unsigned char[key_len];
    if ((recv_all(server_session->socket, (void *)serialized_eph_key_pub, key_len)) != key_len)
    {
        log_error("Failed to receive the ephemeral key");
        delete_buffers(payload_len_byte, nonce, username_len_byte, username, key_len_byte, serialized_eph_key_pub);
        return false;
    }

    // Deserialize the ephemeral key
    EVP_PKEY *eph_key_pub = nullptr;
    if ((eph_key_pub = deserialize_public_key(serialized_eph_key_pub, key_len)) == nullptr)
    {
        log_error("Failed to deserialize the ephemeral key");
        delete_buffers(payload_len_byte, nonce, username_len_byte, username, key_len_byte, serialized_eph_key_pub);
        return false;
    }

    // receive nonceS
    unsigned char *nonceS = new unsigned char[NONCE_LEN];
    if ((recv_all(server_session->socket, (void *)nonceS, NONCE_LEN)) != NONCE_LEN)
    {
        log_error("Failed to receive the nonceS");
        delete_buffers(payload_len_byte, nonce, username_len_byte, username, key_len_byte, serialized_eph_key_pub, nonceS);
        EVP_PKEY_free(eph_key_pub);
        return false;
    }

    // check nonceS
    if (memcmp(nonceS, server_session->nonceServer, NONCE_LEN) != 0)
    {
        log_error("NonceS is not equal to nonceServer");
        delete_buffers(payload_len_byte, nonce, username_len_byte, username, key_len_byte, serialized_eph_key_pub, nonceS);
        EVP_PKEY_free(eph_key_pub);
        return false;
    }

    // Read signature length from the socket and deserialize it
    int signature_len;
    unsigned char *signature_len_byte = new unsigned char[sizeof(int)];
    if ((recv_all(server_session->socket, (void *)signature_len_byte, sizeof(int))) != sizeof(int))
    {
        log_error("Failed to read signature length");
        delete_buffers(payload_len_byte, nonce, username_len_byte, username, key_len_byte, serialized_eph_key_pub, nonceS, signature_len_byte);
        EVP_PKEY_free(eph_key_pub);
        return false;
    }
    memcpy(&signature_len, signature_len_byte, sizeof(int));

    // Read signature from the socket
    unsigned char *signature = new unsigned char[signature_len];
    if ((recv_all(server_session->socket, (void *)signature, signature_len)) != signature_len)
    {
        log_error("Failed to receive the signature");
        delete_buffers(payload_len_byte, nonce, username_len_byte, username, key_len_byte, serialized_eph_key_pub, nonceS, signature_len_byte, signature);
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
        delete_buffers(payload_len_byte, nonce, username_len_byte, username, key_len_byte, serialized_eph_key_pub, nonceS, signature_len_byte, signature);
        EVP_PKEY_free(eph_key_pub);
        return false;
    }

    // Calculate the length of the data to verify and allocate the buffer
    int to_verify_len = NONCE_LEN + sizeof(int) + user_len + sizeof(int) + key_len + NONCE_LEN;
    unsigned char *to_verify = new unsigned char[to_verify_len];

    // Copy nonce, username, key length and ephemeral public key into the buffer to verify
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
        delete_buffers(payload_len_byte, nonce, username_len_byte, username, key_len_byte, serialized_eph_key_pub, nonceS, signature_len_byte, signature, to_verify);
        EVP_PKEY_free(client_public_key);
        EVP_PKEY_free(eph_key_pub);
        return false;
    }

    // Check if the nonce is already present in the nonce list
    if (nonce_list.contains(nonce))
    {
        log_error("Nonce already present");
        delete_buffers(payload_len_byte, nonce, username_len_byte, username, key_len_byte, serialized_eph_key_pub, nonceS, signature_len_byte, signature, to_verify);
        EVP_PKEY_free(client_public_key);
        EVP_PKEY_free(eph_key_pub);
        return false;
    }

    // Add nonce to nonce list in order to prevent replay attacks
    nonce_list.insert(nonce);

    // Add nonce to server session in order to retrieve it later
    memcpy(server_session->nonceClient, nonce, NONCE_LEN);

    // Print the username of the connected user
    printf("User %s connected\n", username_str.c_str());
    // Add username and ephemeral key to server session
    server_session->username = username_str;
    server_session->eph_key_pub = EVP_PKEY_dup(eph_key_pub);

    // Free buffers
    delete_buffers(payload_len_byte, nonce, username_len_byte, username, key_len_byte, serialized_eph_key_pub, nonceS, signature_len_byte, signature, to_verify);
    EVP_PKEY_free(client_public_key);
    EVP_PKEY_free(eph_key_pub);
    return true;
}

/**
 * @brief Sends a message containing the server's certificate, a nonce, a session key and a digital envelope containing the session key.
 *
 * This function sends a message to the client over the specified socket.
 * The message includes the server's certificate, a nonce, a session key and a digital envelope containing the session key.
 * The message is encrypted using the client's ephemeral public key.
 *
 * @param server_session The server's session, containing the socket and the server's ephemeral private key.
 * @param server_private_key The server's private key, used to sign the message.
 *
 * @return true  on success, false on failure.
 */
bool send_message2(Session *server_session, EVP_PKEY *server_private_key)
{
    // CERTIFICATE

    // Get the absolute path of the certificate file
    char abs_path[MAX_PATH];
    getcwd(abs_path, MAX_PATH);
    std::string path = std::string(abs_path) + "/server_file/cert/server_cert.pem";

    // Load the certificate
    X509 *certificate = nullptr;
    if (load_certificate(path, &certificate) != 0)
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

    // DIGITAL ENVELOPE
    // Allocate buffers for the ciphertext, envelope IV, and encrypted envelope key
    unsigned char *ciphertext;
    size_t ciphertext_len;
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
    unsigned char *ciphertext_len_byte = new unsigned char[sizeof(int)];
    serialize_int(ciphertext_len, ciphertext_len_byte);

    // Allocate the buffer for the to_sign data
    // to_sign: ciphertext_len + ciphertext + nonceC
    int to_sign_len = sizeof(int) + ciphertext_len + NONCE_LEN;
    unsigned char *to_sign = new unsigned char[to_sign_len];

    // Copy the data to the to_sign buffer
    memcpy(to_sign, ciphertext_len_byte, sizeof(int));
    memcpy(to_sign + sizeof(int), ciphertext, ciphertext_len);
    memcpy(to_sign + sizeof(int) + ciphertext_len, server_session->nonceClient, NONCE_LEN);

    // Create the digital signature
    int signature_len = EVP_PKEY_size(server_private_key);
    unsigned char *signature = new unsigned char[signature_len];
    if (create_digital_signature(server_private_key, to_sign, to_sign_len, signature) != signature_len)
    {
        log_error("Failed to create digital signature");
        delete_buffers(cert_len_byte, plaintext, ciphertext, ciphertext_len_byte, to_sign, signature);
        X509_free(certificate);
        OPENSSL_free(certificate_byte);
        return false;
    }

    // Allocate the buffer for the payload size
    // payload: cert len | certificate | to sign len | to sign | signature len | signature | nonceS
    unsigned char *payload_size_byte = new unsigned char[sizeof(int)];
    unsigned char *to_sign_len_byte = new unsigned char[sizeof(int)];
    unsigned char *signature_len_byte = new unsigned char[sizeof(int)];

    size_t payload_size = sizeof(int) + cert_len + sizeof(int) + to_sign_len + sizeof(int) + signature_len;

    // Serialize the payload size, the to_sign length, and the signature length
    serialize_int(safe_size_t_to_int(payload_size), payload_size_byte);
    serialize_int(to_sign_len, to_sign_len_byte);
    serialize_int(signature_len, signature_len_byte);

    // Allocate the message buffer
    size_t message_size = payload_size + sizeof(int);
    unsigned char *message = new unsigned char[message_size];

    // Copy the data to the message buffer
    memcpy(message, payload_size_byte, sizeof(int));
    memcpy(message + sizeof(int), cert_len_byte, sizeof(int));
    memcpy(message + sizeof(int) + sizeof(int), certificate_byte, cert_len);
    memcpy(message + sizeof(int) + sizeof(int) + cert_len, to_sign_len_byte, sizeof(int));
    memcpy(message + sizeof(int) + sizeof(int) + cert_len + sizeof(int), to_sign, to_sign_len);
    memcpy(message + sizeof(int) + sizeof(int) + cert_len + sizeof(int) + to_sign_len, signature_len_byte, sizeof(int));
    memcpy(message + sizeof(int) + sizeof(int) + cert_len + sizeof(int) + to_sign_len + sizeof(int), signature, signature_len);

    if (send(server_session->socket, message, message_size, 0) < 0)
    {
        log_error("Error sending message");
        delete_buffers(cert_len_byte, plaintext, ciphertext, ciphertext_len_byte, to_sign, signature, payload_size_byte, to_sign_len_byte, signature_len_byte, message);
        X509_free(certificate);
        OPENSSL_free(certificate_byte);
        return false;
    }

    // Free the buffers
    delete_buffers(cert_len_byte, plaintext, ciphertext, ciphertext_len_byte, to_sign, signature, payload_size_byte, to_sign_len_byte, signature_len_byte, message);
    X509_free(certificate);
    OPENSSL_free(certificate_byte);

    return true;
}

/**
 * @brief Receives a message containing the server's certificate, a nonce, a session key and a digital envelope containing the session key.
 *
 * This function receives a message from the server over the specified socket.
 * The message includes the server's certificate, a nonce, a session key and a digital envelope containing the session key.
 * The message is encrypted using the client's ephemeral public key.
 *
 * @param client_session The client's session, containing the socket and the client's ephemeral private key.
 *
 * @return true on success, false on failure.
 */
bool receive_message2(Session *client_session)
{

    // Receive the payload length and deserialize it
    int payload_len;
    unsigned char *payload_len_byte = new unsigned char[sizeof(int)];
    // allocate_and_store_buffer(cl_free_buf, client_session->socket, sizeof(int), &payload_len_byte);
    if ((recv_all(client_session->socket, (void *)payload_len_byte, sizeof(int))) != sizeof(int))
    {
        log_error("Error receiving payload length");
        delete_buffers(payload_len_byte);
        return false;
    }
    memcpy(&payload_len, payload_len_byte, sizeof(int));

    // Receive the certificate length and deserialize it
    int cert_len;
    unsigned char *cert_len_byte = new unsigned char[sizeof(int)];
    if ((recv_all(client_session->socket, (void *)cert_len_byte, sizeof(int))) != sizeof(int))
    {
        log_error("Error receiving certificate length");
        delete_buffers(payload_len_byte, cert_len_byte);
        return false;
    }
    memcpy(&cert_len, cert_len_byte, sizeof(int));

    // Receive the certificate and deserialize it
    unsigned char *certificate_byte = new unsigned char[cert_len];
    if ((recv_all(client_session->socket, (void *)certificate_byte, cert_len)) != cert_len)
    {
        log_error("Error receiving certificate");
        delete_buffers(payload_len_byte, cert_len_byte, certificate_byte);
        return false;
    }
    X509 *certificate = nullptr;
    certificate = d2i_X509(&certificate, (const unsigned char **)&certificate_byte, cert_len);
    if (certificate == nullptr)
    {
        log_error("Error deserializing certificate");
        delete_buffers(payload_len_byte, cert_len_byte);
        return false;
    }

    // Receive the digital to_sign length and deserialize it
    int to_sign_len;
    unsigned char *to_sign_len_byte = new unsigned char[sizeof(int)];
    if ((recv_all(client_session->socket, (void *)to_sign_len_byte, sizeof(int))) != sizeof(int))
    {
        log_error("Error receiving to_sign length");
        delete_buffers(payload_len_byte, cert_len_byte, to_sign_len_byte);
        X509_free(certificate);
        return false;
    }
    memcpy(&to_sign_len, to_sign_len_byte, sizeof(int));

    // Receive the digital to_sign
    unsigned char *to_sign = new unsigned char[to_sign_len];
    if ((recv_all(client_session->socket, (void *)to_sign, to_sign_len)) != to_sign_len)
    {
        log_error("Error receiving to_sign");
        delete_buffers(payload_len_byte, cert_len_byte, to_sign_len_byte, to_sign);
        X509_free(certificate);
        return false;
    }

    // Receive the signature length and deserialize it
    int signature_len;
    unsigned char *signature_len_byte = new unsigned char[sizeof(int)];
    if ((recv_all(client_session->socket, (void *)signature_len_byte, sizeof(int))) != sizeof(int))
    {
        log_error("Error receiving signature length");
        delete_buffers(payload_len_byte, cert_len_byte, to_sign_len_byte, to_sign, signature_len_byte);
        X509_free(certificate);
        return false;
    }
    memcpy(&signature_len, signature_len_byte, sizeof(int));

    // Receive the signature
    unsigned char *signature = new unsigned char[signature_len];
    if ((recv_all(client_session->socket, (void *)signature, signature_len)) != signature_len)
    {
        log_error("Error receiving signature");
        delete_buffers(payload_len_byte, cert_len_byte, to_sign_len_byte, to_sign, signature_len_byte, signature);
        X509_free(certificate);
        return false;
    }

    // Check the validity of the certificate
    // Load the CA certificate and CRL
    X509 *CA_certificate = nullptr;
    X509_CRL *crl = nullptr;

    // Get the current working directory
    char abs_path[MAX_PATH];
    if (getcwd(abs_path, MAX_PATH) == nullptr)
    {
        log_error("Error getting current working directory");
        delete_buffers(payload_len_byte, cert_len_byte, to_sign_len_byte, to_sign, signature_len_byte, signature);
        X509_free(certificate);
        return false;
    }

    std::string CA_cert_path = std::string(abs_path) + "/client_file/CA/cert.pem";
    std::string CRL_path = std::string(abs_path) + "/client_file/CA/crl.pem";
    if (load_certificate(CA_cert_path, &CA_certificate) != 0 || load_crl(CRL_path, &crl) != 0)
    {
        log_error("Error loading CA certificate or CRL");
        delete_buffers(payload_len_byte, cert_len_byte, to_sign_len_byte, to_sign, signature_len_byte, signature);
        X509_free(certificate);
        return false;
    }

    // Create a store with the CA certificate and CRL
    X509_STORE *store = nullptr;
    if (create_store(&store, CA_certificate, crl) != 0)
    {
        log_error("Error creating store");
        delete_buffers(payload_len_byte, cert_len_byte, to_sign_len_byte, to_sign, signature_len_byte, signature);
        X509_free(certificate);
        X509_free(CA_certificate);
        X509_CRL_free(crl);
        return false;
    }

    // Verify the certificate using the created store
    int result = verify_certificate(store, certificate);
    if (result == 0)
    {
        std::cout << "Certificate is authentic" << std::endl;
    }
    else
    {
        log_error("Certificate is not authentic");
        delete_buffers(payload_len_byte, cert_len_byte, to_sign_len_byte, to_sign, signature_len_byte, signature);
        X509_free(certificate);
        X509_free(CA_certificate);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        return false;
    }

    // Extract the public key from the certificate
    EVP_PKEY *server_public_key = X509_get_pubkey(certificate);
    if (server_public_key == nullptr)
    {
        log_error("Error extracting public key from certificate");
        delete_buffers(payload_len_byte, cert_len_byte, to_sign_len_byte, to_sign, signature_len_byte, signature);
        X509_free(certificate);
        X509_free(CA_certificate);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        return false;
    }

    // Verify the signature using the server's public key
    if (verify_digital_signature(server_public_key, signature, signature_len, to_sign, to_sign_len) != 1)
    {
        log_error("Error verifying signature");
        delete_buffers(payload_len_byte, cert_len_byte, to_sign_len_byte, to_sign, signature_len_byte, signature);
        X509_free(certificate);
        X509_free(CA_certificate);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        EVP_PKEY_free(server_public_key);
        return false;
    }

    int ciphertext_len = 0;
    // Deserialize the ciphertext length
    memcpy(&ciphertext_len, to_sign, sizeof(int));
    // Deserialize the ciphertext
    unsigned char *ciphertext = new unsigned char[ciphertext_len];
    memcpy(ciphertext, to_sign + sizeof(int), ciphertext_len);
    // Deserialize the nonceC
    unsigned char *nonceC = new unsigned char[NONCE_LEN];
    memcpy(nonceC, to_sign + sizeof(int) + ciphertext_len, NONCE_LEN);

    // Check if the nonceC is equal to the one sent before by the client
    if (memcmp(client_session->nonceClient, nonceC, NONCE_LEN))
    {
        log_error("Error: nonceC is not equal to the nonce sent before");
        delete_buffers(payload_len_byte, cert_len_byte, to_sign_len_byte, to_sign, signature_len_byte, signature, ciphertext, nonceC);
        X509_free(certificate);
        X509_free(CA_certificate);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        EVP_PKEY_free(server_public_key);
        return false;
    }

    // Decrypt ciphertext
    unsigned char *plaintext;
    size_t plaintext_len;

    if (!rsaDecrypt(ciphertext, ciphertext_len, client_session->eph_key_priv, plaintext, plaintext_len))
    {
        log_error("Error decrypting ciphertext");
        delete_buffers(payload_len_byte, cert_len_byte, to_sign_len_byte, to_sign, signature_len_byte, signature, ciphertext, nonceC);
        X509_free(certificate);
        X509_free(CA_certificate);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        EVP_PKEY_free(server_public_key);
        return false;
    }

    // Copy the session key to the client session
    memcpy(client_session->aes_key, plaintext, plaintext_len);

    // Free buffers
    delete_buffers(payload_len_byte, cert_len_byte, to_sign_len_byte, to_sign, signature_len_byte, signature, ciphertext, nonceC);
    X509_free(certificate);
    X509_free(CA_certificate);
    X509_CRL_free(crl);
    X509_STORE_free(store);
    EVP_PKEY_free(server_public_key);

    return true;
}

/**
 * @brief Sends an encrypted message to the server using AES-GCM.
 *
 * This function encrypts a dummy byte using AES-GCM and sends it to the server over the specified socket.
 * The message is encrypted using the session key.
 * In this way, the server knows that the client has successfully decrypted the digital envelope and has obtained the session key.
 *
 * @param client_session The client's session, containing the socket and the session key.
 *
 * @return true on success, false on failure.
 */
bool send_message3(Session *client_session)
{

    // Allocate buffers for the plaintext, AAD, IV, tag, and ciphertext
    unsigned char *plaintext = new unsigned char[1];
    unsigned char *aad = new unsigned char[0];
    unsigned char *iv = new unsigned char[IV_LEN];
    unsigned char *tag = new unsigned char[TAG_LEN];
    unsigned char *ciphertext = new unsigned char[1];

    // Set the plaintext to a dummy byte
    plaintext[0] = 1;

    // Generate a random IV
    if (!RAND_bytes(iv, safe_size_t_to_int(IV_LEN)))
    {
        log_error("Error generating IV");
        delete_buffers(plaintext, aad, iv, tag, ciphertext);
        return false;
    }

    // Encrypt the message using AES-GCM
    int ciphertext_len = aesgcm_encrypt(plaintext, 1, aad, 0, client_session->aes_key, iv, safe_size_t_to_int(IV_LEN), ciphertext, tag);
    if (ciphertext_len < 0)
    {
        log_error("Error encrypting message");
        delete_buffers(plaintext, aad, iv, tag, ciphertext);
        return false;
    }

    // PAYLOAD STRUCTURE: ciphertext | tag | iv
    size_t message_size = ciphertext_len + TAG_LEN + IV_LEN;

    // Allocate the message buffer
    unsigned char *message = new unsigned char[message_size];
    // Copy the data to the message buffer
    memcpy(message, ciphertext, ciphertext_len);
    memcpy(message + ciphertext_len, tag, TAG_LEN);
    memcpy(message + ciphertext_len + TAG_LEN, iv, IV_LEN);

    // Send the message
    if (send(client_session->socket, message, message_size, 0) < 0)
    {
        log_error("Error sending message");
        delete_buffers(plaintext, aad, iv, tag, ciphertext, message);
        return false;
    }

    // Free the buffers
    delete_buffers(plaintext, aad, iv, tag, ciphertext, message);
    return true;
}

/**
 * @brief Receives an encrypted message from the server using AES-GCM.
 *
 * @param server_session The server's session, containing the socket and the session key.
 *
 * @return true on success, false on failure.
 */
bool receive_message3(Session *server_session)
{
    // Allocate buffers for the ciphertext and plaintext
    unsigned char *ciphertext = new unsigned char[1];
    unsigned char *plaintext = new unsigned char[1];

    // Receive the ciphertext
    if (recv_all(server_session->socket, (void *)ciphertext, 1) != 1)
    {
        log_error("Error receiving ciphertext");
        delete_buffers(ciphertext, plaintext);
        return false;
    }
    unsigned char *aad = new unsigned char[0];
    // Allocate buffers for the tag
    unsigned char *tag = new unsigned char[TAG_LEN];

    // Receive the tag
    if (recv_all(server_session->socket, (void *)tag, TAG_LEN) != TAG_LEN)
    {
        log_error("Error receiving tag");
        delete_buffers(ciphertext, plaintext, tag);
        return false;
    }

    // Allocate buffers for the IV
    unsigned char *iv = new unsigned char[IV_LEN];

    // Receive the IV
    if (recv_all(server_session->socket, (void *)iv, IV_LEN) != (int)IV_LEN)
    {
        log_error("Error receiving IV");
        delete_buffers(ciphertext, plaintext, tag, iv);
        return false;
    }

    // Decrypt the message
    int plaintext_len = aesgcm_decrypt(ciphertext, 1, aad, 0, tag, server_session->aes_key, iv, safe_size_t_to_int(IV_LEN), plaintext);
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
