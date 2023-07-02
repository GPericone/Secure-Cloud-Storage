#include "utils.h"

// --------------------------------------------------------------------------
// CERTIFICATES
// --------------------------------------------------------------------------

/**
 * @brief Load a certificate from a file
 * 
 * @param filename the name of the file containing the certificate
 * @param certificate the certificate where to store the loaded certificate
 * @return true if the certificate was loaded successfully, false otherwise
 */
bool load_certificate(std::string filename, X509 **certificate)
{
    FILE *fp = fopen(filename.c_str(), "r");
    if (!fp)
    {
        log_error("An error occurred while opening the file", true);
        return false;
    }
    *certificate = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    if (!certificate)
    {
        log_error("An error occurred while reading the certificate", true);
        fclose(fp);
        return false;
    }
    fclose(fp);
    return true;
}

/**
 * @brief Load a CRL from a file
 * 
 * @param filename the name of the file containing the CRL
 * @param crl the CRL where to store the loaded CRL
 * @return true if the CRL was loaded successfully, false otherwise
 */
bool load_crl(std::string filename, X509_CRL **crl)
{
    FILE *fp = fopen(filename.c_str(), "r");
    if (!fp)
    {
        log_error("An error occurred while opening the file", true);
        return false;
    }
    *crl = PEM_read_X509_CRL(fp, nullptr, nullptr, nullptr);
    if (!crl)
    {
        log_error("An error occurred while reading the CRL", true);
        fclose(fp);
        return false;
    }
    fclose(fp);
    return true;
}

/**
 * @brief Create a store object and add the CA certificate and the CRL to it
 * 
 * @param store the X509_STORE where to store the loaded store
 * @param CA_certificate the CA certificate to add to the store
 * @param crl the CRL to add to the store  
 * @return true if the store was created successfully, false otherwise
 */
bool create_store(X509_STORE **store, X509 *CA_certificate, X509_CRL *crl)
{
    // Allocate an empty store, returning NULL if an error occurred
    *store = X509_STORE_new();
    if (store == nullptr)
    {
        log_error("An error occurred during the creation of the store", true);
        return false;
    }

    // Add the CA certificate to the store
    if (X509_STORE_add_cert(*store, CA_certificate) != 1)
    {
        log_error("An error occurred during the addition of certificate", true);
        return false;
    }

    // Add the CRL to the store
    if (X509_STORE_add_crl(*store, crl) != 1)
    {
        log_error("An error occurred during the addition of CRL", true);
        return false;
    }

    // Configure the store to perform CRL checking for every valid certificate before returning the result
    if (X509_STORE_set_flags(*store, X509_V_FLAG_CRL_CHECK) != 1)
    {
        log_error("An error occurred while configuring the store flags", true);
        return false;
    }

    return true;
}

/**
 * @brief Verify a certificate using the store
 * 
 * @param store the store to use for the verification
 * @param certificate the certificate to verify
 * @return true if the certificate was verified successfully, false otherwise
 */
bool verify_certificate(X509_STORE *store, X509 *certificate)
{
    // Allocate a new context for certificate verification, returns the allocated context or NULL if an error occurs
    X509_STORE_CTX *certificate_ctx = X509_STORE_CTX_new();
    if (certificate_ctx == nullptr)
    {
        log_error("An error occurred during the creation of the store context", true);
        X509_STORE_CTX_free(certificate_ctx);
        return false;
    }

    // Initialize the context for certificate verification.
    if (X509_STORE_CTX_init(certificate_ctx, store, certificate, nullptr) != 1)
    {
        log_error("An error occurred during initialization of the store context", true);
        X509_STORE_CTX_free(certificate_ctx);
        return false;
    }

    // Verify the certificate.
    int verification_result = X509_verify_cert(certificate_ctx);
    if (verification_result < 0)
    {
        log_error("An error occurred during the verification of the certificate", true);
        X509_STORE_CTX_free(certificate_ctx);
        return false;
    }
    else if (verification_result == 0)
    {
        X509_STORE_CTX_free(certificate_ctx);
        log_error("The certificate cannot be verified", true);
        return false;
    }

    X509_STORE_CTX_free(certificate_ctx);
    return true;
}

// --------------------------------------------------------------------------
// ASYMMETRIC KEYS
// --------------------------------------------------------------------------

/**
 * @brief Load a private key from a file
 * 
 * @param private_key_file the name of the file containing the private key
 * @return EVP_PKEY* the private key loaded from the file
 */
EVP_PKEY *load_private_key(const char *private_key_file)
{
    // Open the file
    FILE *priv_key_file = fopen(private_key_file, "r");
    if (!priv_key_file)
    {
        log_error("Error opening private key file", true);
        return nullptr;
    }

    // Read the private key from the file
    EVP_PKEY *private_key = PEM_read_PrivateKey(priv_key_file, nullptr, nullptr, nullptr);

    if (!private_key)
    {
        fclose(priv_key_file);
        return nullptr;
    }

    // Close the file
    fclose(priv_key_file);

    return private_key;
}

/**
 * @brief Generate a new RSA key pair
 * 
 * @param k_priv the EVP_PKEY where to store the private key
 * @param k_pub the EVP_PKEY where to store the public key
 * @return true if the key pair was generated successfully, false otherwise
 */
bool generateEphKeys(EVP_PKEY **k_priv, EVP_PKEY **k_pub)
{
    // Inialize the variables
    RSA *rsa = nullptr;
    BIGNUM *big_num = nullptr;
    BIO *bio = nullptr;
    BIO *bio_pub = nullptr;

    // Generate RSA key
    // Create a new BIGNUM instance to hold the RSA public exponent.
    big_num = BN_new();
    if (big_num == nullptr)
    {
        // Return false if BIGNUM creation fails.
        return false; 
    }

    // Set the exponent
    // Set the value of BIGNUM to RSA_F4 (0x10001, or 65537).
    if (BN_set_word(big_num, RSA_F4) != 1)
    {
        // Free the BIGNUM if setting the value fails.
        BN_free(big_num);
        // Return false if setting the value fails.
        return false;
    }
    // Create a new RSA structure.
    rsa = RSA_new();
    if (rsa == nullptr)
    {
        // Free the BIGNUM if RSA creation fails.
        BN_free(big_num);
        // Return false if RSA creation fails.
        return false;    
    }

    // Generate an RSA key pair with a length of 2048 bits.
    if (RSA_generate_key_ex(rsa, 2048, big_num, nullptr) != 1)
    {
        // Free the BIGNUM if RSA key pair generation fails.
        BN_free(big_num);
        // Free the RSA structure if RSA key pair generation fails.
        RSA_free(rsa);   
        // Return false if RSA key pair generation fails.
        return false;    
    }

    // Free the BIGNUM now as it's no longer needed.
    BN_free(big_num);

    // Extract the private key
    // Create a new BIO for input/output operations.
    bio = BIO_new(BIO_s_mem());
    if (bio == nullptr)
    {
        // Free the RSA structure if BIO creation fails.
        RSA_free(rsa);
        // Return false if BIO creation fails.
        return false;  
    }

    // Write the RSA private key to the BIO.
    if (PEM_write_bio_RSAPrivateKey(bio, rsa, nullptr, nullptr, 0, nullptr, nullptr) != 1)
    {
        // Free the BIO if writing the private key fails.
        BIO_free_all(bio);
        // Free the RSA structure if writing the private key fails.
        RSA_free(rsa);
        // Return false if writing the private key fails.     
        return false;      
    }

    // Read the private key from the BIO into the k_priv pointer.
    if (PEM_read_bio_PrivateKey(bio, k_priv, nullptr, nullptr) != *k_priv)
    {
        // Free the BIO if reading the private key fails.
        BIO_free_all(bio); 
        // Free the RSA structure if reading the private key fails.
        RSA_free(rsa);    
        // Return false if reading the private key fails. 
        return false;      
    }

    // Free the BIO now as it's no longer needed.
    BIO_free_all(bio);

    // Extract the public key
    // Create a new BIO for input/output operations.
    bio_pub = BIO_new(BIO_s_mem()); 
    if (bio_pub == nullptr)
    {
        // Free the RSA structure if BIO creation fails.
        RSA_free(rsa);
        // Return false if BIO creation fails.
        return false; 
    }

    // Write the public key from the private key in k_priv to the BIO.
    if (PEM_write_bio_PUBKEY(bio_pub, *k_priv) != 1)
    {
        // Free the BIO if writing the public key fails.
        BIO_free_all(bio_pub);
        // Free the RSA structure if writing the public key fails.
        RSA_free(rsa);     
        // Return false if writing the public key fails.    
        return false;          
    }

    // Read the public key from the BIO into the k_pub pointer.
    if (PEM_read_bio_PUBKEY(bio_pub, k_pub, nullptr, nullptr) != *k_pub)
    {
        // Free the BIO if reading the public key fails.
        BIO_free_all(bio_pub); 
        // Free the RSA structure if reading the public key fails.
        RSA_free(rsa);
        // Return false if reading the public key fails.         
        return false;         
    }

    // Free the BIO now as it's no longer needed.
    BIO_free_all(bio_pub);

    // If all steps complete successfully, return true.
    return true;
}

/**
 * @brief Serialize a public key into a buffer of unsigned char
 * 
 * @param public_key the public key to serialize
 * @param serialized_key the buffer where to store the serialized key
 * @return int the length of the serialized key if the serialization was successful, -1 otherwise
 */
int serialize_public_key(EVP_PKEY *public_key, unsigned char **serialized_key)
{
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
    {
        log_error("Error during BIO creation", true);
        return -1;
    }

    // Write the public key to the BIO
    if (!PEM_write_bio_PUBKEY(bio, public_key))
    {
        log_error("Error during PEM_write_bio_PUBKEY", true);
        BIO_free_all(bio);
        return -1;
    }

    // Read the public key from the BIO into the serialized_key buffer
    int key_len = BIO_pending(bio);
    *serialized_key = new unsigned char[key_len];
    if (BIO_read(bio, *serialized_key, key_len) != key_len)
    {
        log_error("Error during BIO_read", true);
        BIO_free_all(bio);
        delete[] *serialized_key;
        return -1;
    }

    BIO_free_all(bio);
    return key_len;
}

/**
 * @brief Decrypt a ciphertext using RSA
 * 
 * @param ciphertext the ciphertext to decrypt
 * @param ciphertextLength the length of the ciphertext
 * @param privateKey the private key to use for decryption
 * @param plaintext the buffer where to store the plaintext
 * @param plaintextLength the length of the plaintext
 * @return true if the decryption was successful, false otherwise
 */
bool rsaDecrypt(const unsigned char *ciphertext, size_t ciphertextLength, EVP_PKEY *privateKey, unsigned char *&plaintext, int &plaintextLength)
{
    RSA *rsaKey = EVP_PKEY_get1_RSA(privateKey);
    if (!rsaKey)
    {
        log_error("Error getting RSA key from EVP_PKEY.", true);
        return false;
    }

    plaintext = new unsigned char[RSA_size(rsaKey)];

    plaintextLength = RSA_private_decrypt(size_t_to_int(ciphertextLength), ciphertext, plaintext, rsaKey, RSA_PKCS1_OAEP_PADDING);
    if (plaintextLength == -1)
    {
        log_error("Error decrypting with RSA.", true);
        ERR_print_errors_fp(stderr);
        RSA_free(rsaKey);
        return false;
    }

    RSA_free(rsaKey);

    return true;
}

/**
 * @brief The function for duplicate a RSA key
 * 
 * @param pkey the key to duplicate
 * @param is_private true if the key is private, false otherwise
 * @return EVP_PKEY* the duplicated key
 */
EVP_PKEY *duplicate_key(EVP_PKEY *pkey, bool is_private)
{
    EVP_PKEY *pDupKey = EVP_PKEY_new();
    RSA *pRSA = EVP_PKEY_get1_RSA(pkey);
    RSA *pRSADupKey;

    pRSADupKey = (is_private==true) ? RSAPrivateKey_dup(pRSA) : RSAPublicKey_dup(pRSA);

    RSA_free(pRSA);
    EVP_PKEY_set1_RSA(pDupKey, pRSADupKey);
    RSA_free(pRSADupKey);
    return pDupKey;
}

// --------------------------------------------------------------------------
// DIGITAL SIGNATURE
// --------------------------------------------------------------------------

/**
 * @brief Create a digital signature for a given data
 * 
 * @param private_key the private key to use to sign the data
 * @param data the data to sign
 * @param data_len the length of the data to sign
 * @param signature the buffer where to store the signature
 * @return int the length of the signature if the signature was successful, -1 otherwise
 */
int create_digital_signature(EVP_PKEY *private_key, const unsigned char *data, size_t data_len, unsigned char *signature)
{
    const EVP_MD *digest = EVP_sha256();
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int signature_len = 0;
    int ret;

    if (!ctx)
    {
        log_error("Failed to create digital signature context", true);
        return -1;
    }

    ret = EVP_SignInit(ctx, digest);
    if (ret != 1)
    {
        log_error("Failed to initialize digital signature context", true);
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    ret = EVP_SignUpdate(ctx, data, data_len);
    if (ret != 1)
    {
        log_error("Failed to update digital signature context", true);
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    ret = EVP_SignFinal(ctx, signature, &signature_len, private_key);
    if (ret != 1)
    {
        log_error("Failed to finalize digital signature", true);
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return signature_len;
}

/**
 * @brief Verify a digital signature for a given data
 * 
 * @param public_key the public key to use to verify the signature
 * @param signature the signature to verify
 * @param signature_len the length of the signature
 * @param data the data to verify
 * @param data_len the length of the data to verify
 * @return the result of the verification
 */
int verify_digital_signature(EVP_PKEY *public_key, const unsigned char *signature, unsigned int signature_len, const unsigned char *data, size_t data_len)
{
    const EVP_MD *digest = EVP_sha256();
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ret;

    if (!ctx)
    {
        log_error("Failed to create digital signature context", true);
        return -1;
    }

    ret = EVP_VerifyInit(ctx, digest);
    if (ret != 1)
    {
        log_error("Failed to initialize digital signature context", true);
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    ret = EVP_VerifyUpdate(ctx, data, data_len);
    if (ret != 1)
    {
        log_error("Failed to update digital signature context", true);
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    ret = EVP_VerifyFinal(ctx, signature, signature_len, public_key);
    if (ret != 1)
    {
        log_error(ERR_error_string(ERR_get_error(), nullptr), true);
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return ret;
}

// --------------------------------------------------------------------------
// AES-256 GCM
// --------------------------------------------------------------------------

// The cipher to be used for encryption and decryption
const EVP_CIPHER *cipher = EVP_aes_256_gcm();

/**
 * @brief Encrypt a plaintext using AES-256 GCM
 * 
 * @param plaintext the plaintext to encrypt
 * @param plaintext_len the length of the plaintext
 * @param aad the additional authenticated data
 * @param aad_len the length of the additional authenticated data
 * @param key the key to use for encryption
 * @param iv the initialization vector to use for encryption
 * @param ciphertext the buffer where to store the ciphertext
 * @param tag the buffer where to store the tag
 * @return int the length of the ciphertext if the encryption was successful, -1 otherwise
 */
int aesgcm_encrypt(const unsigned char *plaintext,
                   int plaintext_len,
                   const unsigned char *aad, int aad_len,
                   const unsigned char *key,
                   const unsigned char *iv,
                   unsigned char *ciphertext,
                   unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len = 0;
    int ciphertext_len = 0;

    // Create and initialise the context
    ctx = EVP_CIPHER_CTX_new();

    if (ctx == nullptr)
    {
        log_error("An error occurred during the creation of the context", true);
        return -1;
    }

    // Initialise the encryption operation.
    if (1 != EVP_EncryptInit(ctx, cipher, key, iv))
    {
        log_error("An error occurred during the initialization of the encryption", true);
    }

    // Provide any AAD data. This can be called zero or more times as required
    if (1 != EVP_EncryptUpdate(ctx, nullptr, &len, aad, aad_len))
    {
        log_error("An error occurred during the provision of AAD data", true);
        return -1;
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        log_error("An error occurred during the update of the encryption", true);
        return -1;
    }

    ciphertext_len = len;

    // Finalize Encryption
    if (1 != EVP_EncryptFinal(ctx, ciphertext + len, &len))
    {
        log_error("An error occurred during the finalization of the encryption", true);
        return -1;
    }

    ciphertext_len += len;

    // Get the tag
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
    {
        log_error("An error occurred while getting the tag", true);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

/**
 * @brief Decrypt a ciphertext using AES-256 GCM
 * 
 * @param ciphertext the ciphertext to decrypt
 * @param ciphertext_len the length of the ciphertext
 * @param aad the additional authenticated data
 * @param aad_len the length of the additional authenticated data
 * @param tag the tag to use for decryption
 * @param key the key to use for decryption
 * @param iv the initialization vector to use for decryption
 * @param plaintext the buffer where to store the plaintext
 * @return int the length of the plaintext if the decryption was successful, -1 otherwise
 */
int aesgcm_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                   const unsigned char *aad, int aad_len,
                   unsigned char *tag,
                   const unsigned char *key,
                   const unsigned char *iv,
                   unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();

    if (ctx == nullptr)
    {
        log_error("An error occurred during the creation of the context", true);
        return -1;
    }

    if (!EVP_DecryptInit(ctx, cipher, key, iv))
    {
        log_error("An error occurred during the initialization of the decryption", true);
        return -1;
    }

    // Provide any AAD data.
    if (!EVP_DecryptUpdate(ctx, nullptr, &len, aad, aad_len))
    {
        log_error("An error occurred during the provision of AAD data", true);
        return -1;
    }

    // Provide the message to be decrypted, and obtain the plaintext output.
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        log_error("An error occurred during the update of the decryption", true);
    }

    plaintext_len = len;

    /* Set expected tag value. */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag))
    {
        log_error("An error occurred while getting the tag", true);
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
