#include "utils.h"

// TODO: Aggiungere la gestione dei vari errori con la free e la close(socket) di tutto all'interno del main
// TODO: Gestire la pulizia in caso di return 0, salvare tutte le informazioni utili dentro la classe sessione prima di liberare la memoria

/**
 * @brief Sends the user's username and nonce to the server over the specified socket.
 *
 * This function prompts the user to enter their username, generates a nonce using OpenSSL,
 * and sends the username and nonce as a single message to the server over the specified socket.
 *
 * @param socket The socket through which the message will be sent.
 * @return 0 on success, -1 on failure.
 */
int send_message1(int socket)
{
    // Prompt the user for their username
    std::string username;
    std::cout << "Enter your username" << std::endl;
    std::cin >> username;

    if (username.empty() || username.size() > USERNAMESIZE)
    {
        log_error("Invalid username");
        return -1;
    }

    // Generate a client nonce
    unsigned char *nonce = NULL;
    allocate_and_store_buffer(cl_free_buf, socket, NONCE_LEN, &nonce);
    if (RAND_bytes(nonce, NONCE_LEN) != 1)
    {
        log_error("Error generating nonce");
        return -1;
    }

    // Calculate payload size
    unsigned char *payload_size_byte, *message;
    int payload_size = username.size() + NONCE_LEN;

    // Create message buffer
    allocate_and_store_buffer(cl_free_buf, socket, sizeof(int), &payload_size_byte);
    serialize_int(payload_size, payload_size_byte);

    // Serialize payload size and copy into message buffer
    int message_size = sizeof(int) + payload_size;
    allocate_and_store_buffer(cl_free_buf, socket, message_size, &message);

    // Copy nonce and username into message buffer
    memcpy(message, payload_size_byte, sizeof(int));
    memcpy(message + sizeof(int), nonce, NONCE_LEN);
    memcpy(message + sizeof(int) + NONCE_LEN, username.c_str(), username.size());

    // Send message
    int bytes_sent = send(socket, message, message_size, 0);

    if (bytes_sent < 0)
    {
        log_error("Error sending message");
        return -1;
    }

    free_allocated_buffers(cl_free_buf);
    return 0;
}

/**
 * @brief Receives a message containing the user's username and nonce from the specified socket.
 *
 * This function reads the payload length, username, and nonce from the specified socket.
 * It is intended to be used in conjunction with the send_message1 function.
 *
 * @param socket The socket through which the message will be received.
 * @param nonce_list The list of nonces received from the clients.
 * @return 0 on success, -1 on failure.
 */
int receive_message1(int socket, NonceList nonce_list)
{
    int payload_len, user_len, ret;
    unsigned char *username, *nonce;
    unsigned char *payload_len_byte;

    // Read payload length
    allocate_and_store_buffer(sv_free_buf, socket, sizeof(int), &payload_len_byte);
    if ((ret = recv_all(socket, (void *)payload_len_byte, sizeof(int))) != sizeof(int))
    {
        log_error("Failed to read payload length");
        return -1;
    }

    // Deserialize payload_len_byte
    memcpy(&payload_len, payload_len_byte, sizeof(int));

    user_len = payload_len - NONCE_LEN;

    allocate_and_store_buffer(sv_free_buf, socket, user_len, &username);
    allocate_and_store_buffer(sv_free_buf, socket, NONCE_LEN, &nonce);

    if ((ret = recv_all(socket, (void *)nonce, NONCE_LEN)) != NONCE_LEN)
    {
        log_error("Failed to receive the nonce");
        return -1;
    }

    // Check nonce
    if (nonce_list.contains(nonce))
    {
        log_error("Nonce already present");
        return -1;
    }

    if ((ret = recv_all(socket, (void *)username, user_len)) != user_len)
    {
        log_error("Failed to receive the username");
        return -1;
    }

    // Check username
    // TODO: check username using isAuthenticated function

    return 0;
}

/**
 * @brief Sends an encrypted message containing the server's certificate, AES key, IV, and nonces to the client.
 *
 * This function sends an encrypted message to the client over the specified socket.
 * The message includes the server's certificate, an AES key for further
 * secure communication, and nonces for both the client and server. The message is
 * encrypted using envelope encryption, and a digital signature is generated for
 * message integrity and authenticity.
 *
 * @param socket The socket through which the message will be sent.
 * @param client_public_key The client's public key, used for envelope encryption.
 * @param server_private_key The server's private key, used for signing the message.
 * @param nonceC The client's nonce, included in the message for replay attack protection.
 * @return 0 on success, -1 on failure.
 */
int send_message2(int socket, EVP_PKEY *client_public_key, EVP_PKEY *server_private_key, unsigned char *nonceC)
{
    // Check for valid input parameters
    if (!client_public_key || !server_private_key || !nonceC)
    {
        log_error("Invalid input parameters");
        return -1;
    }

    // CERTIFICATE

    char abs_path[MAX_PATH];
    getcwd(abs_path, MAX_PATH);
    std::string path = std::string(abs_path) + "/server_file/cert/server_cert.pem";

    // Load the certificate
    X509 *certificate = nullptr;
    if (load_certificate(path, &certificate) != 0)
    {
        log_error("Failed to load the certificate");
        return -1;
    }

    // Serialize the certificate using i2d_X509
    unsigned char *certificate_byte = nullptr;
    int cert_len = i2d_X509(certificate, &certificate_byte);
    if (cert_len < 0)
    {
        log_error("Failed to serialize the certificate");
        return -1;
    }

    unsigned char *cert_len_byte = nullptr;
    allocate_and_store_buffer(sv_free_buf, socket, sizeof(int), &cert_len_byte);
    serialize_int(cert_len, cert_len_byte);

    // NONCE

    // Generate a server nonce
    unsigned char *nonceS = nullptr;
    allocate_and_store_buffer(sv_free_buf, socket, NONCE_LEN, &nonceS);
    if (RAND_bytes(nonceS, NONCE_LEN) != 1)
    {
        log_error("Error generating nonce");
        return -1;
    }

    // SESSION KEY

    // Generate an AES key for session communications
    unsigned char *plaintext = nullptr;
    allocate_and_store_buffer(sv_free_buf, socket, EVP_CIPHER_key_length(EVP_aes_256_gcm()), &plaintext);

    if (!RAND_bytes(plaintext, EVP_CIPHER_key_length(EVP_aes_256_gcm())))
    {
        log_error("Error generating AES key");
        return -1;
    }

    // DIGITAL ENVELOPE

    // Allocate buffers for the ciphertext, envelope IV, and encrypted envelope key.
    unsigned char *ciphertext = nullptr;
    unsigned char *envelope_iv = nullptr;
    unsigned char *encrypted_envelope_key = nullptr;
    allocate_and_store_buffer(sv_free_buf, socket, EVP_CIPHER_key_length(EVP_aes_256_gcm()) + EVP_CIPHER_block_size(EVP_aes_256_cbc()), &ciphertext);
    allocate_and_store_buffer(sv_free_buf, socket, EVP_CIPHER_iv_length(EVP_aes_256_cbc()), &envelope_iv);
    int encrypted_envelope_key_len = 0;

    // Create the digital envelope
    int ciphertext_len = envelope_encrypt(client_public_key, plaintext, EVP_CIPHER_key_length(EVP_aes_256_gcm()), encrypted_envelope_key, encrypted_envelope_key_len, envelope_iv, ciphertext);
    if (ciphertext_len < 0)
    {
        log_error("An error occurred during envelope encryption");
        return -1;
    }

    // DIGITAL SIGNATURE

    // Allocate a buffer for the signature and
    unsigned char *to_sign = nullptr;
    unsigned char *ciphertext_len_byte, *encrypted_envelope_key_len_byte;
    allocate_and_store_buffer(sv_free_buf, socket, sizeof(int), &ciphertext_len_byte);
    allocate_and_store_buffer(sv_free_buf, socket, sizeof(int), &encrypted_envelope_key_len_byte);
    // TO_SIGN STRUCTURE: ciphertext_len | ciphertext | encrypted_envelope_key_len | encrypted_envelope_key | envelope_iv | nonceC
    serialize_int(ciphertext_len, ciphertext_len_byte);
    serialize_int(encrypted_envelope_key_len, encrypted_envelope_key_len_byte);
    int to_sign_len = sizeof(int) + ciphertext_len + sizeof(int) + encrypted_envelope_key_len + EVP_CIPHER_iv_length(EVP_aes_256_cbc()) + sizeof(nonceC);
    allocate_and_store_buffer(sv_free_buf, socket, to_sign_len, &to_sign);

    // Copy the data to the to_sign buffer
    memcpy(to_sign, ciphertext_len_byte, sizeof(int));
    memcpy(to_sign + sizeof(int), ciphertext, ciphertext_len);
    memcpy(to_sign + sizeof(int) + ciphertext_len, encrypted_envelope_key_len_byte, sizeof(int));
    memcpy(to_sign + sizeof(int) + ciphertext_len + sizeof(int), encrypted_envelope_key, encrypted_envelope_key_len);
    memcpy(to_sign + sizeof(int) + ciphertext_len + sizeof(int) + encrypted_envelope_key_len, envelope_iv, EVP_CIPHER_iv_length(EVP_aes_256_cbc()));
    memcpy(to_sign + sizeof(int) + ciphertext_len + sizeof(int) + encrypted_envelope_key_len + EVP_CIPHER_iv_length(EVP_aes_256_cbc()), nonceC, sizeof(nonceC));

    // Create the digital signature
    unsigned char *signature = nullptr;
    // The signature length is the same as the private key length
    int signature_len = EVP_PKEY_size(server_private_key);
    allocate_and_store_buffer(sv_free_buf, socket, signature_len, &signature);
    int ret = create_digital_signature(server_private_key, to_sign, to_sign_len, signature);
    if (ret <= 0)
    {
        log_error("Failed to create digital signature");
        return -1;
    }

    // DEBUG:

    if (ret == signature_len)
    {
        std::cout << "Ret equal to signature ret: " << ret << std::endl;
    }
    else
    {
        std::cout << "Signature length: " << ret << " (expected " << signature_len << ")" << std::endl;
    }

    // Se i due valori sono uguali imposto un controllo generale che questi coincidano sempre, altrimenti la firma non è stata eseguita correttamente

    // END DEBUG

    // PAYLOAD STRUCTURE: cert len | certificate | to sign len | to sign | signature len | signature | nonceS
    unsigned char *to_sign_len_byte, *signature_len_byte, *payload_size_byte, *message;
    size_t payload_size = sizeof(int) + cert_len + to_sign_len + signature_len + sizeof(nonceS);

    allocate_and_store_buffer(sv_free_buf, socket, sizeof(int), &payload_size_byte);
    allocate_and_store_buffer(sv_free_buf, socket, sizeof(int), &to_sign_len_byte);
    allocate_and_store_buffer(sv_free_buf, socket, sizeof(int), &signature_len_byte);
    serialize_int(payload_size, payload_size_byte);
    serialize_int(to_sign_len, to_sign_len_byte);
    serialize_int(signature_len, signature_len_byte);

    // Allocate the message buffer
    size_t message_size = payload_size + sizeof(int);
    allocate_and_store_buffer(sv_free_buf, socket, message_size, &message);

    // Copy the data to the message buffer
    memcpy(message, payload_size_byte, sizeof(int));
    memcpy(message + sizeof(int), cert_len_byte, sizeof(int));
    memcpy(message + sizeof(int) + sizeof(int), certificate_byte, cert_len);
    memcpy(message + sizeof(int) + sizeof(int) + cert_len, to_sign_len_byte, sizeof(int));
    memcpy(message + sizeof(int) + sizeof(int) + cert_len + sizeof(int), to_sign, to_sign_len);
    memcpy(message + sizeof(int) + sizeof(int) + cert_len + sizeof(int) + to_sign_len, signature_len_byte, sizeof(int));
    memcpy(message + sizeof(int) + sizeof(int) + cert_len + sizeof(int) + to_sign_len + sizeof(int), signature, signature_len);
    memcpy(message + sizeof(int) + sizeof(int) + cert_len + sizeof(int) + to_sign_len + sizeof(int) + signature_len, nonceS, NONCE_LEN);

    // Send the message
    int bytes_sent = send(socket, message, message_size, 0);

    if (bytes_sent < 0)
    {
        log_error("Error sending message");
        return -1;
    }

    // Free the buffers
    free_allocated_buffers(sv_free_buf);
    X509_free(certificate);
    OPENSSL_free(certificate_byte);

    return 0;
}

/**
 * @brief Receives and processes an encrypted message from a socket containing session key information.
 * 
 * This function receives and processes an encrypted message from the specified socket, which contains
 * the session key information. The message components include the payload, certificate, envelope,
 * signature, and nonce. The function verifies the authenticity of the server's certificate and the
 * signature before decrypting the envelope using the client's private key. The session key is then
 * extracted from the decrypted envelope. If successful, the function returns 0; otherwise, it
 * returns -1 in case of errors.
 *
 * @param socket           Socket from which the encrypted message and associated data are received.
 * @param client_private_key Pointer to the EVP_PKEY containing the client's private key for decryption.
 *
 * @return          Returns 0 if the message is successfully received, processed, and decrypted,
 *                  or -1 in case of errors.
 */
int receive_message2(int socket, EVP_PKEY *client_private_key)
{
    int ret, payload_len, cert_len, envelope_len, signature_len;
    unsigned char *envelope, *signature, *nonceS;
    X509 *certificate = nullptr;

    // RECEIVE THE PAYLOAD

    unsigned char *payload_len_byte;
    allocate_and_store_buffer(cl_free_buf, socket, sizeof(int), &payload_len_byte);
    if ((ret = recv_all(socket, (void *)payload_len_byte, sizeof(int))) != sizeof(int))
    {
        log_error("Error receiving payload length");
        return -1;
    }

    // Deserialize the payload length
    memcpy(&payload_len, payload_len_byte, sizeof(int));

    // RECEIVE THE CERTIFICATE

    unsigned char *cert_len_byte;
    allocate_and_store_buffer(cl_free_buf, socket, sizeof(int), &cert_len_byte);
    if ((ret = recv_all(socket, (void *)cert_len_byte, sizeof(int))) != sizeof(int))
    {
        log_error("Error receiving certificate length");
        return -1;
    }

    // Deserialize the certificate length
    memcpy(&cert_len, cert_len_byte, sizeof(int));

    unsigned char *certficate_byte;
    allocate_and_store_buffer(cl_free_buf, socket, cert_len, &certficate_byte);
    if ((ret = recv_all(socket, (void *)certficate_byte, cert_len)) != cert_len)
    {
        log_error("Error receiving certificate");
        return -1;
    }

    // Deserialize the certificate
    certificate = d2i_X509(&certificate, &certficate_byte, cert_len);
    if (certificate == nullptr)
    {
        log_error("Error deserializing certificate");
        return -1;
    }

    // RECEIVE THE ENVELOPE

    unsigned char *envelope_len_byte;
    allocate_and_store_buffer(cl_free_buf, socket, sizeof(int), &envelope_len_byte);
    if ((ret = recv_all(socket, (void *)envelope_len_byte, sizeof(int))) != sizeof(int))
    {
        log_error("Error receiving envelope length");
        return -1;
    }

    // Deserialize the envelope length
    memcpy(&envelope_len, envelope_len_byte, sizeof(int));

    allocate_and_store_buffer(cl_free_buf, socket, envelope_len, &envelope);
    if ((ret = recv_all(socket, (void *)envelope, envelope_len)) != envelope_len)
    {
        log_error("Error receiving envelope");
        return -1;
    }

    // RECEIVE THE SIGNATURE

    unsigned char *signature_len_byte;
    allocate_and_store_buffer(cl_free_buf, socket, sizeof(int), &signature_len_byte);
    if ((ret = recv_all(socket, (void *)signature_len_byte, sizeof(int))) != sizeof(int))
    {
        log_error("Error receiving signature length");
        return -1;
    }

    // Deserialize the signature length
    memcpy(&signature_len, signature_len_byte, sizeof(int));

    allocate_and_store_buffer(cl_free_buf, socket, signature_len, &signature);
    if ((ret = recv_all(socket, (void *)signature, signature_len)) != signature_len)
    {
        log_error("Error receiving signature");
        return -1;
    }

    // RECEIVE THE NONCE

    allocate_and_store_buffer(cl_free_buf, socket, NONCE_LEN, &nonceS);
    if ((ret = recv_all(socket, (void *)nonceS, NONCE_LEN)) != NONCE_LEN)
    {
        log_error("Error receiving nonce");
        return -1;
    }

    // CHECK THE CERTIFICATE

    // Load the CA certificate and CRL
    X509 *CA_certificate = nullptr;
    X509_CRL *crl = nullptr;

    // Get the current working directory
    char abs_path[MAX_PATH];
    if (getcwd(abs_path, MAX_PATH) == nullptr)
    {
        log_error("Error getting current working directory");
        return -1;
    }

    std::string CA_cert_path = std::string(abs_path) + "/client_file/CA/cert.pem";
    std::string CRL_path = std::string(abs_path) + "/client_file/CA/crl.pem";

    if (load_certificate(CA_cert_path, &CA_certificate) != 0 || load_crl(CRL_path, &crl) != 0)
    {
        log_error("Error loading CA certificate or CRL");
        return -1;
    }

    // Create a store with the CA certificate and CRL
    X509_STORE *store = nullptr;
    if (create_store(&store, CA_certificate, crl) != 0)
    {
        log_error("Error creating store");
        return -1;
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
        X509_free(CA_certificate);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        return -1;
    }

    EVP_PKEY *server_public_key = X509_get_pubkey(certificate);
    if (server_public_key == nullptr)
    {
        log_error("Error extracting public key from certificate");
        // Clean up resources before returning
        X509_free(CA_certificate);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        return -1;
    }

    // CHECK THE SIGNATURE

    // Verify the signature using the server's public key
    if (verify_digital_signature(server_public_key, signature, signature_len, envelope, envelope_len) != 1)
    {
        log_error("Error verifying signature");
        // Clean up resources before returning
        X509_free(CA_certificate);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        EVP_PKEY_free(server_public_key);
        return -1;
    }

    // DECRYPT THE ENVELOPE

    unsigned char *envelope_ciphertext, *envelope_key, *envelope_iv, *nonceC;
    int envelope_ciphertext_len, envelope_key_len, envelope_iv_len;

    // Deserialize the envelope ciphertext
    memcpy(&envelope_ciphertext_len, envelope, sizeof(int));
    allocate_and_store_buffer(cl_free_buf, socket, envelope_ciphertext_len, &envelope_ciphertext);
    memcpy(envelope_ciphertext, envelope + sizeof(int), envelope_ciphertext_len);

    // Deserialize the envelope key
    memcpy(&envelope_key_len, envelope + sizeof(int) + envelope_ciphertext_len, sizeof(int));
    allocate_and_store_buffer(cl_free_buf, socket, envelope_key_len, &envelope_key);
    memcpy(&envelope_key, envelope + sizeof(int) + envelope_ciphertext_len + sizeof(int), envelope_key_len);

    // Deserialize the envelope IV
    memcpy(&envelope_iv_len, envelope + sizeof(int) + envelope_ciphertext_len + sizeof(int) + envelope_key_len, sizeof(int));
    allocate_and_store_buffer(cl_free_buf, socket, envelope_iv_len, &envelope_iv);
    memcpy(envelope_iv, envelope + sizeof(int) + envelope_ciphertext_len + sizeof(int) + envelope_key_len + sizeof(int), envelope_iv_len);

    // Deserialize the nonceC
    allocate_and_store_buffer(cl_free_buf, socket, NONCE_LEN, &nonceC);
    memcpy(nonceC, envelope + sizeof(int) + envelope_ciphertext_len + sizeof(int) + envelope_key_len + sizeof(int) + envelope_iv_len, NONCE_LEN);

    // TODO: Check if nonceC is equal to the nonce sent before

    // Decrypt the envelope
    unsigned char *envelope_plaintext;
    int envelope_plaintext_len;

    // TODO:

    envelope_plaintext_len = envelope_decrypt(client_private_key, envelope_ciphertext, envelope_ciphertext_len, envelope_key, envelope_key_len, envelope_iv, envelope_plaintext);
    if (envelope_plaintext_len == -1)
    {
        log_error("Error decrypting envelope");
        // Clean up resources before returning
        X509_free(CA_certificate);
        X509_CRL_free(crl);
        X509_STORE_free(store);
        EVP_PKEY_free(server_public_key);
        return -1;
    }

    // TODO: Salvo l'envelope_plaintext nella struttura Session (è la chiave di sessione)

    // Clean up resources

    X509_free(CA_certificate);
    X509_CRL_free(crl);
    X509_STORE_free(store);
    EVP_PKEY_free(server_public_key);

    return 0;
}

/**
 * @brief Sends an encrypted message containing the server-generated nonce (nonceS) to the specified socket.
 *
 * This function encrypts the server-generated nonce (nonceS) using AES-GCM-256 with the provided AES key and IV.
 * It then sends the encrypted message to the specified socket. The encrypted message has the structure: ciphertext | tag.
 * The encryption uses the provided AES key and IV, and does not include any Additional Authenticated Data (AAD).
 *
 * @param socket The socket to send the encrypted message to.
 * @param nonceS A pointer to the unsigned char array containing the server-generated nonce.
 * @param aes_key A pointer to the unsigned char array containing the AES-GCM-256 key.
 *
 * @return 0 on success, -1 on error.
 */
int send_message3(int socket, unsigned char *nonceS, unsigned char *aes_key)
{
    unsigned char *plaintext, *ciphertext, *tag, *aad, *iv;
    size_t aad_len = NONCE_LEN;
    // Dummy byte to avoid empty plaintext
    plaintext[0] = 1;

    allocate_and_store_buffer(cl_free_buf, socket, aad_len, &aad);
    allocate_and_store_buffer(cl_free_buf, socket, IV_LEN, &iv);
    allocate_and_store_buffer(cl_free_buf, socket, TAG_LEN, &tag);

    memcpy(aad, nonceS, aad_len);
    if (!RAND_bytes(iv, IV_LEN))
    {
        log_error("Error generating IV");
        return -1;
    }

    int ciphertext_len = aesgcm_encrypt(plaintext, 1, aad, aad_len, aes_key, iv, IV_LEN, ciphertext, tag);

    if (ciphertext_len < 0)
    {
        log_error("Error encrypting message");
        return -1;
    }

    // PAYLOAD STRUCTURE: ciphertext | tag
    unsigned char *message;
    size_t message_size = ciphertext_len + aad_len + TAG_LEN + IV_LEN;

    allocate_and_store_buffer(cl_free_buf, socket, message_size, &message);
    memcpy(message, ciphertext, ciphertext_len);
    memcpy(message + ciphertext_len, aad, aad_len);
    memcpy(message + ciphertext_len + aad_len, tag, TAG_LEN);
    memcpy(message + ciphertext_len + aad_len + TAG_LEN, iv, IV_LEN);

    // Send the message

    int bytes_sent = send(socket, message, message_size, 0);

    if (bytes_sent < 0)
    {
        log_error("Error sending message");
        return -1;
    }

    // Free the buffers
    free_allocated_buffers(cl_free_buf);

    return 0;
}
/**
 * @brief Receives and decrypts an encrypted message from a socket using AES-GCM.
 * 
 * This function reads an encrypted message from the specified socket, along with associated
 * AAD, tag, and IV. It then decrypts the message using the provided AES key and checks if
 * the decrypted plaintext is equal to a predefined dummy byte. If successful, the function
 * returns 0; otherwise, it returns -1 in case of errors.
 *
 * @param socket    Socket from which the encrypted message and associated data are received.
 * @param aes_key   Pointer to an unsigned char array containing the AES key for decryption.
 *
 * @return          Returns 0 if the message is successfully received and decrypted, or -1 in case of errors.
 */
int receive_message3(int socket, unsigned char *aes_key)
{
    unsigned char *plaintext, *ciphertext, *aad, *tag, *iv;

    allocate_and_store_buffer(sv_free_buf, socket, 1, &ciphertext);
    if (recv_all(socket, (void *)ciphertext, 1) != 1)
    {
        log_error("Error receiving ciphertext");
        return -1;
    }

    allocate_and_store_buffer(sv_free_buf, socket, NONCE_LEN, &aad);
    if (recv_all(socket, (void *)aad, NONCE_LEN) != NONCE_LEN)
    {
        log_error("Error receiving AAD");
        return -1;
    }

    allocate_and_store_buffer(sv_free_buf, socket, TAG_LEN, &tag);
    if (recv_all(socket, (void *)tag, TAG_LEN) != TAG_LEN)
    {
        log_error("Error receiving tag");
        return -1;
    }

    allocate_and_store_buffer(sv_free_buf, socket, IV_LEN, &iv);
    if (recv_all(socket, (void *)iv, IV_LEN) != IV_LEN)
    {
        log_error("Error receiving IV");
        return -1;
    }

    // Decrypt the message

    int plaintext_len = aesgcm_decrypt(ciphertext, 1, aad, NONCE_LEN, tag, aes_key, iv, IV_LEN, plaintext);
    if (plaintext_len < 0)
    {
        log_error("Error decrypting message");
        return -1;
    }

    // CHECK if the plaintext is equal to the dummy byte

    if (plaintext[0] != 1)
    {
        log_error("Error: plaintext is not equal to the dummy byte");
        return -1;
    }

    // TODO: check if the nonce is the same of the one sent before (saved in the session struct)

    // Free the buffers

    return 0;
}

// TODO: Session class
// username
// nonce
// aes_key
// socket
// 