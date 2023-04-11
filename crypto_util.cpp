#include "utils.h"

// --------------------------------------------------------------------------
// CERTIFICATES
// --------------------------------------------------------------------------

/**
 * Loads a certificate from file.
 *
 * @param filename the name of the file containing the certificate
 * @param certificate pointer to the certificate object to be loaded
 * @return 0 if successful, -1 otherwise
 */
int load_certificate(std::string filename, X509 **certificate)
{
    // Convert filename to a character array, so that it can be used with fopen -> Alternative solution: use fstream
    FILE *fp = fopen(filename.c_str(), "r");
    if (!fp)
    {
        std::cerr << "An error occurred while opening the file" << std::endl;
        return -1;
    }
    *certificate = PEM_read_X509(fp, NULL, NULL, NULL);
    if (!certificate)
    {
        std::cerr << "An error occurred while reading the certificate" << std::endl;
        return -1;
    }
    fclose(fp);
    return 0;
}

/**
 * Loads a Certificate Revocation List (CRL) from file.
 *
 * @param filename the name of the file containing the CRL
 * @param crl pointer to the CRL object to be loaded
 * @return 0 if successful, -1 otherwise
 */
int load_crl(std::string filename, X509_CRL **crl)
{
    FILE *fp = fopen(filename.c_str(), "r");
    if (!fp)
    {
        std::cerr << "An error occurred while opening the file" << std::endl;
        return -1;
    }
    *crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL);
    if (!crl)
    {
        std::cerr << "An error occurred while reading the CRL" << std::endl;
        return -1;
    }
    fclose(fp);
    return 0;
}

/**
 * Create an X509_STORE with the given CA certificate and CRL.
 *
 * @param store the address of a pointer to an X509_STORE to be created.
 * @param CA_certificate a pointer to an X509 certificate representing the Certification Authority.
 * @param crl a pointer to an X509_CRL representing the Certificate Revocation List.
 * @return 0 if the store was created successfully, -1 otherwise.
 */
int create_store(X509_STORE **store, X509 *CA_certificate, X509_CRL *crl)
{
    // Allocate an empty store, returning NULL if an error occurred
    *store = X509_STORE_new();
    if (store == NULL)
    {
        std::cerr << "An error occurred during the creation of the store" << std::endl;
        return -1;
    }

    // Add the CA certificate to the store
    if (X509_STORE_add_cert(*store, CA_certificate) != 1)
    {
        std::cerr << "An error occurred during the addition of certificate" << std::endl;
        return -1;
    }

    // Add the CRL to the store
    if (X509_STORE_add_crl(*store, crl) != 1)
    {
        std::cerr << "An error occurred during the addition of CRL" << std::endl;
        return -1;
    }

    // Configure the store to perform CRL checking for every valid certificate before returning the result
    if (X509_STORE_set_flags(*store, X509_V_FLAG_CRL_CHECK) != 1)
    {
        std::cerr << "An error occurred while configuring the store flags" << std::endl;
        return -1;
    }

    return 0;
}

/**
 * Verifies if a certificate is valid and trusted by a given certificate store.
 *
 * @param store A pointer to the X509_STORE object representing the certificate store.
 * @param certificate A pointer to the X509 object representing the certificate to verify.
 * @return Returns 0 if the certificate is verified successfully and is trusted, or -1 if an error occurs.
 */
int verify_certificate(X509_STORE *store, X509 *certificate)
{
    // Allocate a new context for certificate verification, returns the allocated context or NULL if an error occurs
    X509_STORE_CTX *certificate_ctx = X509_STORE_CTX_new();
    if (certificate_ctx == NULL)
    {
        std::cerr << "An error occurred during the creation of the store context" << std::endl;
        X509_STORE_CTX_free(certificate_ctx);
        return -1;
    }

    // Initialize the context for certificate verification.
    if (X509_STORE_CTX_init(certificate_ctx, store, certificate, NULL) != 1)
    {
    std:
        cerr << "An error occurred during initialization of the store context" << std::endl;
        X509_STORE_CTX_free(certificate_ctx);
        return -1;
    }

    // Verify the certificate.
    int verification_result = X509_verify_cert(certificate_ctx);
    if (verification_result < 0)
    {
        std::cerr << "An error occurred during the verification of the certificate" << std::endl;
        X509_STORE_CTX_free(certificate_ctx);
        return -1;
    }
    else if (verification_result == 0)
    {
        X509_STORE_CTX_free(certificate_ctx);
        std::cerr << "The certificate cannot be verified" << std::endl;
        return -1;
    }

    X509_STORE_CTX_free(certificate_ctx);
    return 0;
}

/**
 * @brief Loads a public key from the specified PEM file.
 *
 * This function attempts to open and read a public key from the specified PEM file.
 * If the file cannot be opened or the public key cannot be read, an error message
 * is displayed, and the function returns nullptr.
 *
 * @param public_key_file Pointer to a null-terminated string containing the path to the PEM file with the public key.
 *
 * @return                Pointer to an EVP_PKEY structure containing the public key, or nullptr in case of errors.
 */
EVP_PKEY *load_public_key(const char *public_key_file)
{
    FILE *pub_key_file = fopen(public_key_file, "r");
    if (!pub_key_file)
    {
        std::cerr << "Error opening public key file: " << public_key_file << std::endl;
        return nullptr;
    }

    EVP_PKEY *public_key = PEM_read_PUBKEY(pub_key_file, nullptr, nullptr, nullptr);
    fclose(pub_key_file);

    if (!public_key)
    {
        std::cerr << "Error reading public key from file: " << public_key_file << std::endl;
    }

    return public_key;
}

// --------------------------------------------------------------------------
// DIGITAL SIGNATURE
// --------------------------------------------------------------------------
/**
 * @brief Creates a digital signature for the given data using the provided private key.
 *
 * This function creates a digital signature for the given data using the SHA-256
 * digest algorithm and the provided private key. The signature is generated using
 * the EVP_Sign* family of functions from the OpenSSL library.
 *
 * @param private_key Pointer to an EVP_PKEY structure containing the private key used for signing.
 * @param data        Pointer to the unsigned char array containing the data to be signed.
 * @param data_len    Integer representing the length of the data in bytes.
 * @param signature   Pointer to the unsigned char array where the generated signature will be stored.
 *
 * @return            Integer representing the length of the generated signature in bytes, or -1 in case of errors.
 */
int create_digital_signature(EVP_PKEY *private_key, const unsigned char *data, int data_len, unsigned char *signature)
{
    const EVP_MD *digest = EVP_sha256();
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int signature_len = 0;
    int ret;

    if (!ctx)
    {
        log_error("Failed to create digital signature context");
        return -1;
    }

    ret = EVP_SignInit(ctx, digest);
    if (ret != 1)
    {
        log_error("Failed to initialize digital signature context");
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    ret = EVP_SignUpdate(ctx, data, data_len);
    if (ret != 1)
    {
        log_error("Failed to update digital signature context");
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    ret = EVP_SignFinal(ctx, signature, &signature_len, private_key);
    if (ret != 1)
    {
        log_error("Failed to finalize digital signature");
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return signature_len;
}

/**
 * @brief Verifies a digital signature using a public key.
 *
 * This function verifies a digital signature using a given public key, signature, and data.
 * The function computes the SHA-256 hash of the data and checks if the signature matches the hash.
 *
 * @param public_key      Pointer to the EVP_PKEY structure containing the public key.
 * @param signature       Pointer to an unsigned char array containing the signature.
 * @param signature_len   Length of the signature array.
 * @param data            Pointer to an unsigned char array containing the data to verify.
 * @param data_len        Length of the data array.
 *
 * @return                Returns 1 if the signature is successfully verified, -1 in case of errors.
 */
int verify_digital_signature(EVP_PKEY *public_key, const unsigned char *signature, int signature_len, const unsigned char *data, int data_len)
{
    const EVP_MD *digest = EVP_sha256();
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ret;

    if (!ctx)
    {
        log_error("Failed to create digital signature context");
        return -1;
    }

    ret = EVP_VerifyInit(ctx, digest);
    if (ret != 1)
    {
        log_error("Failed to initialize digital signature context");
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    ret = EVP_VerifyUpdate(ctx, data, data_len);
    if (ret != 1)
    {
        log_error("Failed to update digital signature context");
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    ret = EVP_VerifyFinal(ctx, signature, signature_len, public_key);
    if (ret != 1)
    {
        std::cerr << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    std::cout << "Signature verified successfully" << std::endl;
    return ret;
}

// --------------------------------------------------------------------------
// AES-256 GCM
// --------------------------------------------------------------------------

const EVP_CIPHER *cipher = EVP_aes_256_gcm();

/**
 * Encrypts the plaintext using the AES-GCM encryption algorithm and returns the ciphertext and tag.
 *
 * @param plaintext The plaintext to be encrypted.
 * @param plaintext_len The length of the plaintext.
 * @param aad The additional authentication data (AAD) to be included in the encryption.
 * @param aad_len The length of the AAD.
 * @param key The encryption key.
 * @param iv The initialization vector (IV).
 * @param iv_len The length of the IV.
 * @param ciphertext The buffer where the ciphertext will be written.
 * @param tag The buffer where the authentication tag will be written.
 * @return The length of the ciphertext on success, or -1 on error.
 */
int aesgcm_encrypt(unsigned char *plaintext,
                   int plaintext_len,
                   unsigned char *aad, int aad_len,
                   unsigned char *key,
                   unsigned char *iv, int iv_len,
                   unsigned char *ciphertext,
                   unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len = 0;
    int ciphertext_len = 0;

    // Create and initialise the context
    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL)
    {
        std::cerr << "An error occurred during the creation of the context" << std::endl;
        return -1;
    }

    // Initialise the encryption operation.
    if (1 != EVP_EncryptInit(ctx, cipher, key, iv))
    {
        std::cerr << "An error occurred during the initialization of the encryption" << std::endl;
        return -1;
    }

    // Provide any AAD data. This can be called zero or more times as required
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
    {
        std::cerr << "An error occurred during the provision of AAD data" << std::endl;
        return -1;
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        std::cerr << "An error occurred during the update of the encryption" << std::endl;
        return -1;
    }

    ciphertext_len = len;

    // Finalize Encryption
    if (1 != EVP_EncryptFinal(ctx, ciphertext + len, &len))
    {
        std::cerr << "An error occurred during the finalization of the encryption" << std::endl;
        return -1;
    }

    ciphertext_len += len;

    // Get the tag
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
    {
        std::cerr << "An error occurred while getting the tag" << std::endl;
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
/**
 * @brief Decrypts an AES-GCM ciphertext and verifies its authenticity.
 *
 * This function decrypts an AES-GCM encrypted ciphertext using the provided key, IV, and
 * authentication tag. It also processes additional authenticated data (AAD) if provided.
 * The function uses the EVP_Decrypt* family of functions from the OpenSSL library for decryption.
 *
 * @param ciphertext    Pointer to the unsigned char array containing the ciphertext to be decrypted.
 * @param ciphertext_len Integer representing the length of the ciphertext in bytes.
 * @param aad           Pointer to the unsigned char array containing the additional authenticated data (AAD).
 * @param aad_len       Integer representing the length of the AAD in bytes.
 * @param tag           Pointer to the unsigned char array containing the authentication tag.
 * @param key           Pointer to the unsigned char array containing the decryption key.
 * @param iv            Pointer to the unsigned char array containing the initialization vector (IV).
 * @param iv_len        Integer representing the length of the IV in bytes.
 * @param plaintext     Pointer to the unsigned char array where the decrypted plaintext will be stored.
 *
 * @return              Integer representing the length of the decrypted plaintext in bytes, or -1 in case of errors or authentication failure.
 */
int aesgcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                   unsigned char *aad, int aad_len,
                   unsigned char *tag,
                   unsigned char *key,
                   unsigned char *iv, int iv_len,
                   unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL)
    {
        std::cerr << "An error occurred during the creation of the context" << std::endl;
        return -1;
    }

    if (!EVP_DecryptInit(ctx, cipher, key, iv))
    {
        std::cerr << "An error occurred during the initialization of the decryption" << std::endl;
        return -1;
    }

    // Provide any AAD data.
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
    {
        std::cerr << "An error occurred during the provision of AAD data" << std::endl;
        return -1;
    }

    // Provide the message to be decrypted, and obtain the plaintext output.
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        std::cerr << "An error occurred during the update of the decryption" << std::endl;
        return -1;
    }

    plaintext_len = len;

    /* Set expected tag value. */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag))
    {
        std::cerr << "An error occurred while getting the tag" << std::endl;
        return -1;
    }
    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0)
    {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    }
    else
    {
        /* Verify failed */
        return -1;
    }
}

// --------------------------------------------------------------------------
// DIGITAL ENVELOPE
// --------------------------------------------------------------------------
/**
 * @brief Encrypts a plaintext using envelope encryption with a public key.
 *
 * This function performs envelope encryption on the given plaintext using the provided public key.
 * It generates a random symmetric key and initialization vector (IV) for encryption and encrypts the
 * symmetric key using the public key. The function uses the EVP_Seal* family of functions from the
 * OpenSSL library for encryption.
 *
 * @param public_key    Pointer to the EVP_PKEY structure containing the public key for envelope encryption.
 * @param plaintext     Pointer to the unsigned char array containing the plaintext to be encrypted.
 * @param pt_len        Integer representing the length of the plaintext in bytes.
 * @param sym_key_enc   Pointer to the unsigned char array where the encrypted symmetric key will be stored.
 * @param sym_key_len   Integer representing the length of the encrypted symmetric key in bytes.
 * @param iv            Pointer to the unsigned char array where the generated initialization vector (IV) will be stored.
 * @param ciphertext    Pointer to the unsigned char array where the encrypted ciphertext will be stored.
 *
 * @return              Integer representing the length of the encrypted ciphertext in bytes, or -1 in case of errors.
 */
int envelope_encrypt(EVP_PKEY *public_key,
                     unsigned char *plaintext,
                     int pt_len,
                     unsigned char *sym_key_enc,
                     int sym_key_len,
                     unsigned char *iv,
                     unsigned char *ciphertext)
{
    int ret = 0;
    int len = 0;
    int ciphertext_len = 0;

    // Create and initialise the context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (!ctx)
    {
        std::cerr << "An error occurred during the creation of the context" << std::endl;
        return -1;
    }

    // Generate the IV and the symmetric key and encrypt the symmetric key
    ret = EVP_SealInit(ctx, EVP_aes_256_cbc(), &sym_key_enc, &sym_key_len, iv, &public_key, 1);
    if (ret != 1)
    {
        std::cerr << "An error occurred during the seal initialization" << std::endl;
        return -1;
    }

    // Encrypt the plaintext
    ret = EVP_SealUpdate(ctx, ciphertext, &len, (unsigned char *)plaintext, pt_len);
    if (ret != 1)
    {
        std::cerr << "An error occurred during the seal update" << std::endl;
        return -1;
    }

    ciphertext_len = len;

    // Finalize the encryption and add the padding
    ret = EVP_SealFinal(ctx, ciphertext + ciphertext_len, &len);
    if (ret != 1)
    {
        log_error("An error occurred during the seal finalization");
        return -1;
    }

    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
/**
 * @brief Decrypts a ciphertext using envelope encryption and the given private key.
 *
 * This function performs envelope decryption of the ciphertext using the provided private key,
 * encrypted symmetric key, and initialization vector (IV). The decrypted plaintext is then returned.
 *
 * @param private_key   Pointer to the EVP_PKEY structure containing the private key.
 * @param ciphertext    Pointer to an unsigned char array containing the ciphertext to decrypt.
 * @param ct_len        Length of the ciphertext array.
 * @param sym_key_enc   Pointer to an unsigned char array containing the encrypted symmetric key.
 * @param sym_key_len   Length of the encrypted symmetric key array.
 * @param iv            Pointer to an unsigned char array containing the initialization vector.
 * @param plaintext     Pointer to an unsigned char array that will hold the decrypted plaintext.
 *
 * @return              Returns the length of the decrypted plaintext if successful, or -1 in case of errors.
 */
int envelope_decrypt(EVP_PKEY *private_key,
                     unsigned char *ciphertext,
                     int ct_len,
                     unsigned char *sym_key_enc,
                     int sym_key_len,
                     unsigned char *iv,
                     unsigned char *plaintext)
{

    int ret = 0;
    int outlen = 0;
    int plaintext_len = 0;

    // Create and initialise the context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        log_error("An error occurred during the creation of the context");
        return -1;
    }

    // Decrypt the symmetric key that will be used to decrypt the ciphertext
    ret = EVP_OpenInit(ctx, EVP_aes_256_cbc(), sym_key_enc, sym_key_len, iv, private_key);
    if (ret != 1)
    {
        log_error("An error occurred during the open initialization");
        return -1;
    }

    // Decrypt the ciphertext
    ret = EVP_OpenUpdate(ctx, plaintext, &outlen, ciphertext, ct_len);
    if (ret != 1)
    {
        log_error("An error occurred during the open update");
        return -1;
    }
    plaintext_len += outlen;

    ret = EVP_OpenFinal(ctx, plaintext + plaintext_len, &outlen);
    if (ret != 1)
    {
        log_error("An error occurred during the open final");
        return -1;
    }

    plaintext_len += outlen;
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
