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
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

// --------------------------------------------------------------------------
// ASYMMETRIC KEYS
// --------------------------------------------------------------------------

/**
 * @brief Load a public key from the specified public key file.
 *
 * @param public_key_file the name of the file containing the public key
 * @return EVP_PKEY* pointer to the public key object
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

/**
 * @brief Deserializes a public key from a byte array.
 *
 * This function deserializes a public key from a byte array.
 * The byte array is allocated inside the function, and a pointer to it is returned.
 *
 * @param serialized_key  Pointer to an unsigned char array containing the serialized key.
 * @param key_len         The length of the serialized key.
 *
 * @return                Pointer to an EVP_PKEY structure containing the public key, or nullptr in case of errors.
 */
EVP_PKEY *deserialize_public_key(unsigned char *serialized_key, int key_len)
{

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
    {
        std::cerr << "Error during BIO creation" << std::endl;
        return nullptr;
    }

    if (BIO_write(bio, serialized_key, key_len) != key_len)
    {
        std::cerr << "Error during BIO_write" << std::endl;
        BIO_free_all(bio);
        return nullptr;
    }

    EVP_PKEY *public_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    if (!public_key)
    {
        std::cerr << "Error during PEM_read_bio_PUBKEY" << std::endl;
        BIO_free_all(bio);
        return nullptr;
    }

    BIO_free_all(bio);
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

bool rsaEncrypt(const unsigned char *plaintext, size_t plaintextLength, EVP_PKEY *publicKey, unsigned char *&ciphertext, size_t &ciphertextLength)
{
    RSA *rsaKey = EVP_PKEY_get1_RSA(publicKey);
    if (!rsaKey)
    {
        std::cerr << "Error extracting RSA key from EVP_PKEY." << std::endl;
        return false;
    }

    int rsaKeySize = RSA_size(rsaKey);
    ciphertext = new unsigned char[rsaKeySize];

    int result = RSA_public_encrypt(plaintextLength, plaintext, ciphertext, rsaKey, RSA_PKCS1_PADDING);
    if (result == -1)
    {
        std::cerr << "Error encrypting with RSA." << std::endl;
        ERR_print_errors_fp(stderr);
        RSA_free(rsaKey);
        delete[] ciphertext;
        return false;
    }

    ciphertextLength = result;

    RSA_free(rsaKey);

    return true;
}

EVP_PKEY *duplicate_key(EVP_PKEY *pkey)
{
    EVP_PKEY *pDupKey = EVP_PKEY_new();
    RSA *pRSA = EVP_PKEY_get1_RSA(pkey);
    RSA *pRSADupKey;
    printf("START - duplicate_key, EVP_PKEY_get1_RSA, pRSA=%d, pkey=%d", pRSA!=NULL, pkey!=NULL);
    pRSADupKey = RSAPublicKey_dup(pRSA);

    RSA_free(pRSA);
    EVP_PKEY_set1_RSA(pDupKey, pRSADupKey);
    printf("START - duplicate_key, EVP_PKEY_set1_RSA, pDupKey=%d, pRSADupKey=%d", pDupKey!=NULL, pRSADupKey!=NULL);
    RSA_free(pRSADupKey);
    return pDupKey;
}