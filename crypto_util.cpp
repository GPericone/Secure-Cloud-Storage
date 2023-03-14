#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>



/*

Funzioni di OPENSSL da utilizzare:

- Gestione del certificato
- Digital Envelope
- AES-128 GCM

*/

// --------------------------------------------------------------------------
// CERTIFICATI
// --------------------------------------------------------------------------

int load_certificate(std::string filename, X509 **certificate){
    // converto la stringa filename in un array di caratteri, per poter usare fopen -> Altra soluzione uso fstream
	FILE* fp = fopen(filename.c_str(), "r");
	if(!fp)
    {
        std::cerr << "An error occurred while opening the file" << std::endl;
		return -1;
	}
	*certificate = PEM_read_X509(fp, NULL, NULL, NULL);
	if(!certificate)
    {
        std::cerr << "An error occurred while reading the certificate" << std::endl;
		return -1;
	}
	fclose(fp);
	return 0;
}

int load_crl(std::string filename, X509_CRL** crl){
	FILE* fp = fopen(filename.c_str(), "r");
	if(!fp)
    {
        std::cerr << "An error occurred while opening the file" << std::endl;
		return -1;
	}
	*crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL);
	if(!crl)
    {
        std::cerr << "An error occurred while reading the CRL" << std::endl;
		return -1;
	}
	fclose(fp);
	return 0;
}

int create_store(X509_STORE **store, X509 *CA_certificate, X509_CRL *crl)
{

    // Alloco uno store vuoto, la funzione ritorna lo store o NULL se è avvenuto un errore
    *store = X509_STORE_new();
    if(store == NULL)
    {
        std::cerr << "An error occurred during the creation of the store" << std::endl;
        return -1;
    }

    // Aggiungo il certificato della Certification Authority nello store
    if(X509_STORE_add_cert(*store, CA_certificate) != 1)
    {
		std::cerr << "An error occurred during the addition of certificate" << std::endl;
		return -1;
	}

    // Aggiungo il CRL nello store
    if(X509_STORE_add_crl(*store, crl) != 1)
    {
		std::cerr << "An error occurred during the addition of CRL" << std::endl;
		return -1;
	}

    /*
    Configura lo store così che effettui il controllo sul CRL per ogni certificato valido prima che restituisca il risultato
    */
    if(X509_STORE_set_flags(*store, X509_V_FLAG_CRL_CHECK) != 1){
		std::cerr << "An error occurred while configuring the store flags" << std::endl;
		return -1;
	}

    return 0;

}

int verify_certificate (X509_STORE *store, X509 *certificate){
    // Alloco un nuovo contesto per la verifica dei certificato, ritornerà il contesto allocato o NULL se ci sarà un errore
    X509_STORE_CTX* certificate_ctx = X509_STORE_CTX_new();
    if(certificate_ctx == NULL)
    {
        std::cerr << "An error occurred during the creation of the store context" << std::endl;
        X509_STORE* X509_STORE_free(certificate_ctx);
        return -1;
    }

    /*
    Inizializzo il contesto per la verifica del certificato
    int X509_STORE_CTX_init(X509_STORE_CTX* ctx, X509_STORE* s, X509* cert, NULL);
    La funzione ritorna 1 se l'inizializzazione è avvenuta correttamente
    */
    if(X509_STORE_CTX_init(certificate_ctx, store, certificate, NULL) != 1)
    {
        std:cerr << "An error occured during initialization of the store context" << std:endl;
        X509_STORE* X509_STORE_free(certificate_ctx);
        return -1;
    }

    /*
    Verificato il certificato
    int X509_STORE_CTX_init(X509_STORE_CTX* ctx, X509_STORE* s, X509* cert, NULL);
    La funzione ritorna 1 se la verifica è avvenuta correttamente, 0 se non è verificato o < 0 in caso di errore
    */
    int verification_result;
    verification_result = X509_verify_cert(certificate_ctx);
    if(verification_result < 0)
    {
        std::cerr << "An error occurred during the verification of the certificate" << std::endl;
        X509_STORE* X509_STORE_free(certificate_ctx);
        return -1;
    }
    else if (verification_result = 0)
    {
        X509_STORE* X509_STORE_free(certificate_ctx);
        std::cerr << "The certificate cannot be verified" << std::endl;
        return -1;
    }

    X509_STORE* X509_STORE_free(certificate_ctx);
    return 0;
}

// --------------------------------------------------------------------------
// AES-128 GCM
// --------------------------------------------------------------------------

const EVP_CIPHER *cipher = EVP_aes_128_gcm();

int aesgcm_encrypt(unsigned char *plaintext, int plaintext_len,
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

    if(ctx == NULL)
    {
        std::cerr << "An error occurred during the creation of the context" << std::endl;
        return -1;
    }

    // Initialise the encryption operation.
    if(1 != EVP_EncryptInit(ctx, cipher, key, iv))
    {
        std::cerr << "An error occurred during the initialization of the encryption" << std::endl;
        return -1;
    }

    //Provide any AAD data. This can be called zero or more times as required
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
    {
        std::cerr << "An error occurred during the provision of AAD data" << std::endl;
        return -1;
    }

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        std::cerr << "An error occurred during the update of the encryption" << std::endl;
        return -1;
    }

    ciphertext_len = len;

	//Finalize Encryption
    if(1 != EVP_EncryptFinal(ctx, ciphertext + len, &len))
    {
        std::cerr << "An error occurred during the finalization of the encryption" << std::endl;
        return -1;
    }

    ciphertext_len += len;

    // Get the tag
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
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

    if(ctx == NULL)
    {
        std::cerr << "An error occurred during the creation of the context" << std::endl;
        return -1;
    }

    if(!EVP_DecryptInit(ctx, cipher, key, iv))
    {
        std::cerr << "An error occurred during the initialization of the decryption" << std::endl;
        return -1;
    }

	//Provide any AAD data.
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
    {
        std::cerr << "An error occurred during the provision of AAD data" << std::endl;
        return -1;
    }

	//Provide the message to be decrypted, and obtain the plaintext output.
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        std::cerr << "An error occurred during the update of the decryption" << std::endl;
        return -1;
    }
    
    plaintext_len = len;

    /* Set expected tag value. */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag))
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

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}

// --------------------------------------------------------------------------
// DIGITAL ENVELOPE
// --------------------------------------------------------------------------

int envelope_encrypt(EVP_PKEY* public_key, 
                    unsigned char* plaintext, 
                    int pt_len, 
                    unsigned char* sym_key_enc, 
                    int sym_key_len, 
                    unsigned char* iv, 
                    unsigned char* ciphertext)
{
	int ret = 0;
	int len = 0;
	int ciphertext_len = 0;

	// Create and initialise the context 
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if(!ctx){
        std::cerr << "An error occurred during the creation of the context" << std::endl;
		return -1;
	}

	// Generate the IV and the symmetric key and encrypt the symmetric key 
	ret = EVP_SealInit(ctx, EVP_aes_256_cbc(), &sym_key_enc, &sym_key_len, iv, &public_key, 1);
	if(ret != 1){
        std::cerr << "An error occurred during the seal initialization" << std::endl;
	    return -1;
	}

	// Encrypt the plaintext 
	ret = EVP_SealUpdate(ctx, ciphertext, &len, (unsigned char*)plaintext, pt_len);
	if(ret != 1){
        std::cerr << "An error occurred during the seal update" << std::endl;
	    return -1;
	}
        
	ciphertext_len = len;

	// Finalize the encryption and add the padding
	ret = EVP_SealFinal(ctx, ciphertext + ciphertext_len, &len);
	if(ret != 1){
		error_handler("seal final contesto fallito");
	    	return -1;
	}

	ciphertext_len += len;

	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

