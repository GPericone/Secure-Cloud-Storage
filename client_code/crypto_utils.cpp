#include "utils.h"

// --------------------------------------------------------------------------
// CERTIFICATES
// --------------------------------------------------------------------------

bool load_certificate(std::string filename, X509 **certificate)
{
    FILE *fp = fopen(filename.c_str(), "r");
    if (!fp)
    {
        std::cerr << "An error occurred while opening the file" << std::endl;
        return false;
    }
    *certificate = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    if (!certificate)
    {
        std::cerr << "An error occurred while reading the certificate" << std::endl;
        fclose(fp);
        return false;
    }
    fclose(fp);
    return true;
}

bool load_crl(std::string filename, X509_CRL **crl)
{
    FILE *fp = fopen(filename.c_str(), "r");
    if (!fp)
    {
        std::cerr << "An error occurred while opening the file" << std::endl;
        return false;
    }
    *crl = PEM_read_X509_CRL(fp, nullptr, nullptr, nullptr);
    if (!crl)
    {
        std::cerr << "An error occurred while reading the CRL" << std::endl;
        fclose(fp);
        return false;
    }
    fclose(fp);
    return true;
}

bool create_store(X509_STORE **store, X509 *CA_certificate, X509_CRL *crl)
{
    // Allocate an empty store, returning NULL if an error occurred
    *store = X509_STORE_new();
    if (store == nullptr)
    {
        std::cerr << "An error occurred during the creation of the store" << std::endl;
        return false;
    }

    // Add the CA certificate to the store
    if (X509_STORE_add_cert(*store, CA_certificate) != 1)
    {
        std::cerr << "An error occurred during the addition of certificate" << std::endl;
        return false;
    }

    // Add the CRL to the store
    if (X509_STORE_add_crl(*store, crl) != 1)
    {
        std::cerr << "An error occurred during the addition of CRL" << std::endl;
        return false;
    }

    // Configure the store to perform CRL checking for every valid certificate before returning the result
    if (X509_STORE_set_flags(*store, X509_V_FLAG_CRL_CHECK) != 1)
    {
        std::cerr << "An error occurred while configuring the store flags" << std::endl;
        return false;
    }

    return true;
}

bool verify_certificate(X509_STORE *store, X509 *certificate)
{
    // Allocate a new context for certificate verification, returns the allocated context or NULL if an error occurs
    X509_STORE_CTX *certificate_ctx = X509_STORE_CTX_new();
    if (certificate_ctx == nullptr)
    {
        std::cerr << "An error occurred during the creation of the store context" << std::endl;
        X509_STORE_CTX_free(certificate_ctx);
        return false;
    }

    // Initialize the context for certificate verification.
    if (X509_STORE_CTX_init(certificate_ctx, store, certificate, nullptr) != 1)
    {
        std::cerr << "An error occurred during initialization of the store context" << std::endl;
        X509_STORE_CTX_free(certificate_ctx);
        return false;
    }

    // Verify the certificate.
    int verification_result = X509_verify_cert(certificate_ctx);
    if (verification_result < 0)
    {
        std::cerr << "An error occurred during the verification of the certificate" << std::endl;
        X509_STORE_CTX_free(certificate_ctx);
        return false;
    }
    else if (verification_result == 0)
    {
        X509_STORE_CTX_free(certificate_ctx);
        std::cerr << "The certificate cannot be verified" << std::endl;
        return false;
    }

    X509_STORE_CTX_free(certificate_ctx);
    return true;
}

// --------------------------------------------------------------------------
// ASYMMETRIC KEYS
// --------------------------------------------------------------------------

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
    EVP_PKEY *private_key = PEM_read_PrivateKey(priv_key_file, nullptr, nullptr, nullptr);

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

int create_digital_signature(EVP_PKEY *private_key, const unsigned char *data, size_t data_len, unsigned char *signature)
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

int verify_digital_signature(EVP_PKEY *public_key, const unsigned char *signature, unsigned int signature_len, const unsigned char *data, size_t data_len)
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
        std::cerr << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
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
    if (1 != EVP_EncryptUpdate(ctx, nullptr, &len, aad, aad_len))
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
        std::cerr << "An error occurred during the creation of the context" << std::endl;
        return -1;
    }

    if (!EVP_DecryptInit(ctx, cipher, key, iv))
    {
        std::cerr << "An error occurred during the initialization of the decryption" << std::endl;
        return -1;
    }

    // Provide any AAD data.
    if (!EVP_DecryptUpdate(ctx, nullptr, &len, aad, aad_len))
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

bool rsaDecrypt(const unsigned char *ciphertext, size_t ciphertextLength, EVP_PKEY *privateKey, unsigned char *&plaintext, int &plaintextLength)
{
    RSA *rsaKey = EVP_PKEY_get1_RSA(privateKey);
    if (!rsaKey)
    {
        std::cerr << "Error getting RSA key from EVP_PKEY." << std::endl;
        return false;
    }

    plaintext = new unsigned char[RSA_size(rsaKey)];

    plaintextLength = RSA_private_decrypt(size_t_to_int(ciphertextLength), ciphertext, plaintext, rsaKey, RSA_PKCS1_OAEP_PADDING);
    if (plaintextLength == -1)
    {
        std::cerr << "Error decrypting with RSA." << std::endl;
        ERR_print_errors_fp(stderr);
        RSA_free(rsaKey);
        return false;
    }

    RSA_free(rsaKey);

    return true;
}

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