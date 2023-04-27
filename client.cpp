#include "client.h"

int main(int argc, char **argv)
{

    if (argc != 1)
    {
        ipServer = argv[1];
        serverPort = atoi(argv[2]);
    } else {
        serverPort = 4242;
    }

    // Create socket
    sd = socket(AF_INET, SOCK_STREAM, 0);

    memset(&srvAddr, 0, sizeof(srvAddr));
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_port = htons(serverPort);
    inet_pton(AF_INET, ipServer, &srvAddr.sin_addr);
    ret = connect(sd, (struct sockaddr *)&srvAddr, sizeof(srvAddr));

    if (sd < 0 || ret < 0)
    {
        printf("LOG_ERR: Errore di connesione, sd=%d, ret=%d \n", sd, ret);
        exit(-1);
    }

    auto session = std::make_unique<Session>();
    session->socket = sd;

    if (!send_message1(session.get()))
    {
        printf("LOG_ERR: Errore nell'invio del messaggio 1 \n");
        exit(-1);
    }

    // TODO: Leggo la private key del client (ottenuta concatenando il percorso fisso con lo username)
    EVP_PKEY *private_key = load_private_key(("client_file/keys/" + session->username + "_private_key.pem").c_str());
    if (private_key == nullptr)
    {
        printf("LOG_ERROR: Errore in fase di caricamento della chiave privata dell'utente\n");
        exit(1);
    }
    
    if (receive_message2(session.get(), private_key) == false)
    {
        printf("LOG_ERROR: Errore in fase di ricezione del messaggio 2\n");
        exit(1);
    }

    if (send_message3(session.get()) == false)
    {
        printf("LOG_ERROR: Errore in fase di invio del messaggio 3\n");
        exit(1);
    }
    
    // Handshake completato

    // while(1)
    // {
    // }
    
    close(sd);
}