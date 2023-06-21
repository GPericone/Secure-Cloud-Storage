#include "utils.h"

// --------------------------------------------------------------------------
// CERTIFICATES
// --------------------------------------------------------------------------

/**
 * @brief Loads a certificate from the specified PEM file.
 *
 * @param filename the name of the file containing the certificate
 * @param certificate pointer to the certificate object to be loaded
 * @return int 0 if successful, -1 otherwise
 */
int load_certificate(std::string filename, X509 **certificate)
{
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
 * @brief Loads a CRL from the specified PEM file.
 *
 * @param filename the name of the file containing the CRL
 * @param crl pointer to the CRL object to be loaded
 * @return int 0 if successful, -1 otherwise
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
 * @brief Create a store object and add the CA certificate and CRL to it.
 *
 * @param store pointer to the store object to be created
 * @param CA_certificate pointer to the CA certificate
 * @param crl pointer to the CRL
 * @return int 0 if successful, -1 otherwise
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
 * @brief Verify the validity of a certificate using the provided store.
 *
 * @param store pointer to the store object
 * @param certificate pointer to the certificate to be verified
 * @return int 0 if successful, -1 otherwise
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
        std::cerr << "An error occurred during initialization of the store context" << std::endl;
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

// --------------------------------------------------------------------------
// ASYMMETRIC KEYS
// --------------------------------------------------------------------------

/**
 * @brief Load a private key from the specified private key file.
 *
 * @param private_key_file the name of the file containing the private key
 * @return EVP_PKEY* pointer to the private key object
 */
EVP_PKEY *load_private_key(const char *private_key_file)
{
    // Open the file
    FILE *priv_key_file = fopen(private_key_file, "r");
    if (!priv_key_file)
    {
        std::cerr << "Error opening private key file: " << private_key_file << std::endl;
        return nullptr;
    }

    // Read the private key from the file
    EVP_PKEY *private_key = PEM_read_PrivateKey(priv_key_file, nullptr, nullptr, (void *)"password");

    if (!private_key)
    {
        std::cerr << "Error reading private key from file: " << private_key_file << std::endl;
        fclose(priv_key_file);
        return nullptr;
    }

    // Close the file
    fclose(priv_key_file);

    return private_key;
}

/**
 * @brief Generate an ephemeral key pair.
 *
 * @param k_priv the private key to be generated
 * @param k_pub the public key to be generated
 * @return true on success, false otherwise
 */
bool generateEphKeys(EVP_PKEY **k_priv, EVP_PKEY **k_pub)
{
    // Inialize the variables
    RSA *rsa = nullptr;
    BIGNUM *big_num = nullptr;
    BIO *bio = nullptr;
    BIO *bio_pub = nullptr;

    // Generate RSA key
    big_num = BN_new(); // Create a new BIGNUM instance to hold the RSA public exponent.
    if (big_num == nullptr)
    {
        return false; // Return false if BIGNUM creation fails.
    }

    // Set the exponent
    if (BN_set_word(big_num, RSA_F4) != 1) // Set the value of BIGNUM to RSA_F4 (0x10001, or 65537).
    {
        BN_free(big_num); // Free the BIGNUM if setting the value fails.
        return false;     // Return false if setting the value fails.
    }
    rsa = RSA_new(); // Create a new RSA structure.
    if (rsa == nullptr)
    {
        BN_free(big_num); // Free the BIGNUM if RSA creation fails.
        return false;     // Return false if RSA creation fails.
    }

    // Generate an RSA key pair with a length of 2048 bits.
    if (RSA_generate_key_ex(rsa, 2048, big_num, nullptr) != 1)
    {
        BN_free(big_num); // Free the BIGNUM if RSA key pair generation fails.
        RSA_free(rsa);    // Free the RSA structure if RSA key pair generation fails.
        return false;     // Return false if RSA key pair generation fails.
    }

    BN_free(big_num); // Free the BIGNUM now as it's no longer needed.

    // Extract the private key
    bio = BIO_new(BIO_s_mem()); // Create a new BIO for input/output operations.
    if (bio == nullptr)
    {
        RSA_free(rsa); // Free the RSA structure if BIO creation fails.
        return false;  // Return false if BIO creation fails.
    }

    // Write the RSA private key to the BIO.
    if (PEM_write_bio_RSAPrivateKey(bio, rsa, nullptr, nullptr, 0, nullptr, nullptr) != 1)
    {
        BIO_free_all(bio); // Free the BIO if writing the private key fails.
        RSA_free(rsa);     // Free the RSA structure if writing the private key fails.
        return false;      // Return false if writing the private key fails.
    }

    // Read the private key from the BIO into the k_priv pointer.
    if (PEM_read_bio_PrivateKey(bio, k_priv, nullptr, nullptr) != *k_priv)
    {
        BIO_free_all(bio); // Free the BIO if reading the private key fails.
        RSA_free(rsa);     // Free the RSA structure if reading the private key fails.
        return false;      // Return false if reading the private key fails.
    }

    BIO_free_all(bio); // Free the BIO now as it's no longer needed.

    // Extract the public key
    bio_pub = BIO_new(BIO_s_mem()); // Create a new BIO for input/output operations.
    if (bio_pub == nullptr)
    {
        RSA_free(rsa); // Free the RSA structure if BIO creation fails.
        return false;  // Return false if BIO creation fails.
    }

    // Write the public key from the private key in k_priv to the BIO.
    if (PEM_write_bio_PUBKEY(bio_pub, *k_priv) != 1)
    {
        BIO_free_all(bio_pub); // Free the BIO if writing the public key fails.
        RSA_free(rsa);         // Free the RSA structure if writing the public key fails.
        return false;          // Return false if writing the public key fails.
    }

    // Read the public key from the BIO into the k_pub pointer.
    if (PEM_read_bio_PUBKEY(bio_pub, k_pub, nullptr, nullptr) != *k_pub)
    {
        BIO_free_all(bio_pub); // Free the BIO if reading the public key fails.
        RSA_free(rsa);         // Free the RSA structure if reading the public key fails.
        return false;          // Return false if reading the public key fails.
    }

    BIO_free_all(bio_pub); // Free the BIO now as it's no longer needed.

    // If all steps complete successfully, return true.
    return true;
}

/**
 * @brief Serializes a public key to a byte array.
 *
 * This function serializes a public key to a byte array.
 * The byte array is allocated inside the function, and a pointer to it is returned.
 *
 * @param public_key      Pointer to an EVP_PKEY structure containing the public key.
 * @param serialized_key  Pointer to a pointer to an unsigned char array that will contain the serialized key.
 *
 * @return                The size of the serialized key, or -1 in case of errors.
 */
int serialize_public_key(EVP_PKEY *public_key, unsigned char **serialized_key)
{
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
    {
        std::cerr << "Error during BIO creation" << std::endl;
        return -1;
    }

    if (!PEM_write_bio_PUBKEY(bio, public_key))
    {
        std::cerr << "Error during PEM_write_bio_PUBKEY" << std::endl;
        BIO_free_all(bio);
        return -1;
    }

    int key_len = BIO_pending(bio);
    *serialized_key = new unsigned char[key_len];

    if (BIO_read(bio, *serialized_key, key_len) != key_len)
    {
        std::cerr << "Error during BIO_read" << std::endl;
        BIO_free_all(bio);
        delete[] *serialized_key;
        return -1;
    }

    BIO_free_all(bio);
    return key_len;
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

// The cipher to be used for encryption and decryption
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

bool rsaDecrypt(const unsigned char *ciphertext, size_t ciphertextLength, EVP_PKEY *privateKey, unsigned char *&plaintext, size_t &plaintextLength)
{
    RSA *rsaKey = EVP_PKEY_get1_RSA(privateKey);
    if (!rsaKey)
    {
        std::cerr << "Error getting RSA key from EVP_PKEY." << std::endl;
        return false;
    }

    int rsaKeySize = RSA_size(rsaKey);
    plaintext = new unsigned char[rsaKeySize];

    int result = RSA_private_decrypt(ciphertextLength, ciphertext, plaintext, rsaKey, RSA_PKCS1_PADDING);
    if (result == -1)
    {
        std::cerr << "Error decrypting with RSA." << std::endl;
        ERR_print_errors_fp(stderr);
        RSA_free(rsaKey);
        delete[] plaintext;
        return false;
    }

    plaintextLength = result;

    RSA_free(rsaKey);

    return true;
}