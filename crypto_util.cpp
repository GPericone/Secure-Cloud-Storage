#include "utils.h"

// --------------------------------------------------------------------------
// CERTIFICATES
// --------------------------------------------------------------------------

void log_error(const std::string &msg) {
    std::cerr << "Error: " << msg << std::endl;
}

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
// AES-128 GCM
// --------------------------------------------------------------------------

const EVP_CIPHER *cipher = EVP_aes_128_gcm();

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
        log_error("seal final contesto fallito");
        return -1;
    }

    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

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
        log_error("creazione contesto fallita");
        return -1;
    }

    // Decrypt the symmetric key that will be used to decrypt the ciphertext
    ret = EVP_OpenInit(ctx, EVP_aes_256_cbc(), sym_key_enc, sym_key_len, iv, private_key);
    if (ret != 1)
    {
        log_error("open init contesto fallito");
        return -1;
    }

    // Decrypt the ciphertext
    ret = EVP_OpenUpdate(ctx, plaintext, &outlen, ciphertext, ct_len);
    if (ret != 1)
    {
        log_error("open update contesto fallito");
        return -1;
    }
    plaintext_len += outlen;

    ret = EVP_OpenFinal(ctx, plaintext + plaintext_len, &outlen);
    if (ret != 1)
    {
        log_error("open final contesto fallito");
        return -1;
    }

    plaintext_len += outlen;
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
