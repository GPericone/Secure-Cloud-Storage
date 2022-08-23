#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>


/*

Funzioni di OPENSSL da utilizzare:

- Gestione del certificato
- Protocollo di scambio delle chiavi DH -> Serve? Possiamo fare attraverso lo scambio di certificati
- Digital Envelope
- Protocollo di autenticazione -> HMAC

*/

// --------------------------------------------------------------------------
// CERTIFICATI
// --------------------------------------------------------------------------

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








}