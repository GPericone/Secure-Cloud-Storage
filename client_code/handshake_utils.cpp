#include "utils.h"

/**
 * @brief The client receives the server's nonce
 *
 * @param client_session the client's session struct
 * @return true if the message is received correctly, false otherwise
 */
bool receive_message1(Session *client_session)
{
    // Allocate memory for the server's nonce
    unsigned char *nonceS = new unsigned char[NONCE_LEN];

    // Receive the nonce from the server
    if (!recv_all(client_session->socket, nonceS, NONCE_LEN))
    {
        // If the receive operation fails, log an error message and return false
        log_error("Error receiving message", true);
        return false;
    }

    // Copy the server's nonce into the client's session
    memcpy(client_session->nonceServer, nonceS, NONCE_LEN);

    // Return true to indicate that the operation was successful
    return true;
}

/**
 * @brief The client sends its username, its nonce and ephemeral public key to the server.
 * It also signs the message with its private key.
 *
 * @param client_session the client's session struct
 * @return true if the message is sent correctly, false otherwise
 */
bool send_message2(Session *client_session)
{
    // Prompt the user for their username
    std::string username;
    std::cout << "Enter your username" << std::endl;
    std::cin >> username;

    // Check username length and format
    // The username must be between 1 and USERNAME_SIZE characters long and must contain only alphabetical characters
    if (username.empty() || username.size() > USERNAMESIZE || !std::regex_match(username, username_pattern))
    {
        log_error("Invalid username", false);
        return false;
    }
    // Load the client private key
    char abs_path[MAX_PATH];
    if (!getcwd(abs_path, MAX_PATH))
    {
        log_error("Error getting current working directory", true);
        return false;
    };
    std::string path = std::string(abs_path) + "/client_file/keys/" + username + "_private_key.pem";
    EVP_PKEY *client_private_key = load_private_key(path.c_str());
    if (client_private_key == nullptr)
    {
        log_error("Failed to load the client private key", true);
        return false;
    }

    // Generate ephemeral keys
    EVP_PKEY *eph_key_priv = nullptr;
    EVP_PKEY *eph_key_pub = nullptr;

    if (!generateEphKeys(&eph_key_priv, &eph_key_pub))
    {
        log_error("Error generating ephemeral keys", true);
        EVP_PKEY_free(client_private_key);
        return false;
    }

    // Serialize the username length
    unsigned char *username_len_byte = new unsigned char[sizeof(int)];
    // We can safely cast the username size to int because we already checked that it is between 1 and USERNAME_SIZE
    serialize_int(size_t_to_int(username.size()), username_len_byte);

    // Add username and ephemeral keys to client session
    client_session->username = username;
    client_session->eph_key_priv = duplicate_key(eph_key_priv, true);
    client_session->eph_key_pub = duplicate_key(eph_key_pub, false);

    // Generate a client nonce
    unsigned char *nonce = new unsigned char[NONCE_LEN];
    if (RAND_bytes(nonce, NONCE_LEN) != 1)
    {
        log_error("Error generating nonce", true);
        delete_buffers(username_len_byte, nonce);
        EVP_PKEY_free(client_private_key);
        EVP_PKEY_free(eph_key_priv);
        EVP_PKEY_free(eph_key_pub);
        return false;
    }
    // Add nonce to client session in order to check if it is the same as the one received from the server
    memcpy(client_session->nonceClient, nonce, NONCE_LEN);

    // Serialize the ephemeral public key
    // We give the buffer a size of 2048 bytes because the serialized key can be up to 2048 bytes long
    unsigned char *serialized_eph_key_pub = new unsigned char[2048];
    // The real dimension of the serialized key is returned by the function
    int key_len = serialize_public_key(eph_key_pub, &serialized_eph_key_pub);

    // Calculate signature length and allocate the buffer
    int signature_len = EVP_PKEY_size(client_private_key);
    unsigned char *signature = new unsigned char[signature_len];

    // Calculate the length of the data to sign and allocate the buffer
    size_t to_sign_len = NONCE_LEN + sizeof(int) + username.size() + sizeof(int) + int_to_size_t(key_len) + NONCE_LEN;
    unsigned char *to_sign = new unsigned char[to_sign_len];

    // Serialize the key length
    unsigned char *key_len_byte = new unsigned char[sizeof(int)];
    serialize_int(key_len, key_len_byte);

    // Copy nonce, username, key length and ephemeral public key into the buffer to sign
    // TO_SIGN: nonce | username_len | username | key_len | ephemeral_key | nonceS
    memcpy(to_sign, nonce, NONCE_LEN);
    memcpy(to_sign + NONCE_LEN, username_len_byte, sizeof(int));
    memcpy(to_sign + NONCE_LEN + sizeof(int), username.c_str(), username.size());
    memcpy(to_sign + NONCE_LEN + sizeof(int) + username.size(), key_len_byte, sizeof(int));
    memcpy(to_sign + NONCE_LEN + sizeof(int) + username.size() + sizeof(int), serialized_eph_key_pub, key_len);
    memcpy(to_sign + NONCE_LEN + sizeof(int) + username.size() + sizeof(int) + key_len, client_session->nonceServer, NONCE_LEN);

    // Sign the buffer
    if (create_digital_signature(client_private_key, to_sign, to_sign_len, signature) != signature_len)
    {
        log_error("Failed to create digital signature", true);
        delete_buffers(username_len_byte, nonce, serialized_eph_key_pub, signature, to_sign, key_len_byte);
        EVP_PKEY_free(client_private_key);
        EVP_PKEY_free(eph_key_priv);
        EVP_PKEY_free(eph_key_pub);
        return false;
    }

    // Serialize signature length
    unsigned char *signature_len_byte = new unsigned char[sizeof(int)];
    serialize_int(signature_len, signature_len_byte);

    // Calculate message size
    size_t message_size = to_sign_len + sizeof(int) + int_to_size_t(signature_len);
    unsigned char *message = new unsigned char[message_size];

    // Create the message
    // MESSAGE: to_sign | signature_len | signature
    memcpy(message, to_sign, to_sign_len);
    memcpy(message + to_sign_len, signature_len_byte, sizeof(int));
    memcpy(message + to_sign_len + sizeof(int), signature, signature_len);

    // Send message to the server over the socket
    if (send(client_session->socket, message, message_size, 0) < 0)
    {
        log_error("Error sending message", true);
        delete_buffers(username_len_byte, nonce, serialized_eph_key_pub, signature, to_sign, key_len_byte, signature_len_byte, message);
        EVP_PKEY_free(client_private_key);
        EVP_PKEY_free(eph_key_priv);
        EVP_PKEY_free(eph_key_pub);
        return false;
    }

    // Free buffers
    delete_buffers(username_len_byte, nonce, serialized_eph_key_pub, signature, to_sign, key_len_byte, signature_len_byte, message);
    EVP_PKEY_free(client_private_key);
    EVP_PKEY_free(eph_key_priv);
    EVP_PKEY_free(eph_key_pub);
    return true;
}

/**
 * @brief The client receives the certificate, the session key encrypted with its public ephemeral key and the nonceClient that was sent to the server.
 * The session key encrypted and the nonceClient are signed with the server's private key.
 *
 * @param client_session the client's session struct
 * @return true if the message is received correctly, false otherwise
 */
bool receive_message3(Session *client_session)
{
    // Receive the certificate length and deserialize it
    int cert_len;
    unsigned char *cert_len_byte = new unsigned char[sizeof(int)];
    if (!recv_all(client_session->socket, (void *)cert_len_byte, sizeof(int)))
    {
        log_error("Error receiving certificate length", true);
        delete_buffers(cert_len_byte);
        return false;
    }
    memcpy(&cert_len, cert_len_byte, sizeof(int));

    // Receive the certificate and deserialize it
    unsigned char *certificate_byte = new unsigned char[cert_len];
    if (!recv_all(client_session->socket, (void *)certificate_byte, cert_len))
    {
        log_error("Error receiving certificate", true);
        delete_buffers(cert_len_byte, certificate_byte);
        return false;
    }
    X509 *certificate = nullptr;
    certificate = d2i_X509(&certificate, (const unsigned char **)&certificate_byte, cert_len);
    if (certificate == nullptr)
    {
        log_error("Error deserializing certificate", true);
        delete_buffers(cert_len_byte);
        return false;
    }

    // Receive the digital to_sign length and deserialize it
    long int to_sign_len;
    unsigned char *to_sign_len_byte = new unsigned char[sizeof(long int)];
    if (!recv_all(client_session->socket, (void *)to_sign_len_byte, sizeof(long int)))
    {
        log_error("Error receiving to_sign length", true);
        delete_buffers(cert_len_byte, to_sign_len_byte);
        X509_free(certificate);
        return false;
    }
    memcpy(&to_sign_len, to_sign_len_byte, sizeof(int));
    deserialize_longint(to_sign_len_byte, &to_sign_len);

    // Receive the digital to_sign
    unsigned char *to_sign = new unsigned char[to_sign_len];
    if (!recv_all(client_session->socket, (void *)to_sign, to_sign_len))
    {
        log_error("Error receiving to_sign", true);
        delete_buffers(cert_len_byte, to_sign_len_byte, to_sign);
        X509_free(certificate);
        return false;
    }

    // Receive the signature length and deserialize it
    unsigned int signature_len;
    unsigned char *signature_len_byte = new unsigned char[sizeof(int)];
    if (!recv_all(client_session->socket, (void *)signature_len_byte, sizeof(int)))
    {
        log_error("Error receiving signature length", true);
        delete_buffers(cert_len_byte, to_sign_len_byte, to_sign, signature_len_byte);
        X509_free(certificate);
        return false;
    }
    memcpy(&signature_len, signature_len_byte, sizeof(int));

    // Receive the signature
    unsigned char *signature = new unsigned char[signature_len];
    if (!recv_all(client_session->socket, (void *)signature, signature_len))
    {
        log_error("Error receiving signature", true);
        delete_buffers(cert_len_byte, to_sign_len_byte, to_sign, signature_len_byte, signature);
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
        log_error("Error getting current working directory", true);
        delete_buffers(cert_len_byte, to_sign_len_byte, to_sign, signature_len_byte, signature);
        X509_free(certificate);
        return false;
    }

    // Load the CA certificate and CRL
    std::string CA_cert_path = std::string(abs_path) + "/client_file/CA/cert.pem";
    std::string CRL_path = std::string(abs_path) + "/client_file/CA/crl.pem";
    if (!load_certificate(CA_cert_path, &CA_certificate) || !load_crl(CRL_path, &crl))
    {
        log_error("Error loading CA certificate or CRL", true);
        delete_buffers(cert_len_byte, to_sign_len_byte, to_sign, signature_len_byte, signature);
        X509_free(certificate);
        return false;
    }

    // Create a store with the CA certificate and CRL
    X509_STORE *store = nullptr;
    if (!create_store(&store, CA_certificate, crl))
    {
        log_error("Error creating store", true);
        delete_buffers(cert_len_byte, to_sign_len_byte, to_sign, signature_len_byte, signature);
        X509_free(certificate);
        X509_free(CA_certificate);
        X509_CRL_free(crl);
        return false;
    }

    // Verify the certificate using the created store
    if (!verify_certificate(store, certificate))
    {
        log_error("Certificate is not authentic", true);
        delete_buffers(cert_len_byte, to_sign_len_byte, to_sign, signature_len_byte, signature);
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
        log_error("Error extracting public key from certificate", true);
        delete_buffers(cert_len_byte, to_sign_len_byte, to_sign, signature_len_byte, signature);
        X509_free(certificate);
        X509_free(CA_certificate);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        return false;
    }

    // Verify the signature using the server's public key
    if (verify_digital_signature(server_public_key, signature, signature_len, to_sign, to_sign_len) != 1)
    {
        log_error("Error verifying signature", true);
        delete_buffers(cert_len_byte, to_sign_len_byte, to_sign, signature_len_byte, signature);
        X509_free(certificate);
        X509_free(CA_certificate);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        EVP_PKEY_free(server_public_key);
        return false;
    }

    size_t ciphertext_len = 0;
    // Deserialize the ciphertext length
    memcpy(&ciphertext_len, to_sign, sizeof(long int));
    // Deserialize the ciphertext
    unsigned char *ciphertext = new unsigned char[ciphertext_len];
    memcpy(ciphertext, to_sign + sizeof(long int), ciphertext_len);
    // Deserialize the nonceC
    unsigned char *nonceC = new unsigned char[NONCE_LEN];
    memcpy(nonceC, to_sign + sizeof(long int) + ciphertext_len, NONCE_LEN);

    // Check if the nonceC is equal to the one sent before by the client
    if (memcmp(client_session->nonceClient, nonceC, NONCE_LEN))
    {
        log_error("Error: nonceC is not equal to the nonce sent before", true);
        delete_buffers(cert_len_byte, to_sign_len_byte, to_sign, signature_len_byte, signature, ciphertext, nonceC);
        X509_free(certificate);
        X509_free(CA_certificate);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        EVP_PKEY_free(server_public_key);
        return false;
    }

    // Decrypt ciphertext
    unsigned char *plaintext;
    int plaintext_len;

    if (!rsaDecrypt(ciphertext, ciphertext_len, client_session->eph_key_priv, plaintext, plaintext_len))
    {
        log_error("Error decrypting ciphertext", true);
        delete_buffers(cert_len_byte, to_sign_len_byte, to_sign, signature_len_byte, signature, ciphertext, plaintext, nonceC);
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
    delete_buffers(cert_len_byte, to_sign_len_byte, to_sign, signature_len_byte, signature, ciphertext, plaintext, nonceC);
    X509_free(certificate);
    X509_free(CA_certificate);
    X509_CRL_free(crl);
    X509_STORE_free(store);
    EVP_PKEY_free(server_public_key);

    return true;
}

/**
 * @brief The client sends a message to the server using the session key, so that the server can verify that the client has the session key.
 * The client encrypt a dummy byte using AES-GCM and sends the ciphertext, the IV, and the tag to the server.
 *
 * @param client_session the client's session struct
 * @return true if the message is sent correctly, false otherwise
 */
bool send_message4(Session *client_session)
{

    // Allocate buffers for the plaintext, AAD, IV, tag, and ciphertext
    unsigned char *plaintext = new unsigned char[1];
    // We don't use AAD in this case
    unsigned char *aad = new unsigned char[0];
    unsigned char *iv = new unsigned char[IV_LEN];
    unsigned char *tag = new unsigned char[TAG_LEN];
    unsigned char *ciphertext = new unsigned char[1];

    // Set the plaintext to a dummy byte
    plaintext[0] = 1;

    // Generate a random IV
    if (!RAND_bytes(iv, IV_LEN))
    {
        log_error("Error generating IV", true);
        delete_buffers(plaintext, aad, iv, tag, ciphertext);
        return false;
    }

    // Encrypt the message using AES-GCM
    int ciphertext_len = aesgcm_encrypt(plaintext, 1, aad, 0, client_session->aes_key, iv, ciphertext, tag);
    if (ciphertext_len < 0)
    {
        log_error("Error encrypting message", true);
        delete_buffers(plaintext, aad, iv, tag, ciphertext);
        return false;
    }

    // MESSAGE STRUCTURE: ciphertext | tag | iv
    size_t message_size = int_to_size_t(ciphertext_len) + TAG_LEN + int_to_size_t(IV_LEN);

    // Allocate the message buffer
    unsigned char *message = new unsigned char[message_size];
    // Copy the data to the message buffer
    memcpy(message, ciphertext, ciphertext_len);
    memcpy(message + ciphertext_len, tag, TAG_LEN);
    memcpy(message + ciphertext_len + TAG_LEN, iv, IV_LEN);

    // Send the message
    if (send(client_session->socket, message, message_size, 0) < 0)
    {
        log_error("Error sending message", true);
        delete_buffers(plaintext, aad, iv, tag, ciphertext, message);
        return false;
    }

    // Free the buffers
    delete_buffers(plaintext, aad, iv, tag, ciphertext, message);
    return true;
}
