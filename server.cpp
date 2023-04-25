#include "server.h"
#include "utils.h"

int main(int argc, char **argv)
{

    // TODO: Crea la mappa di sessioni
    std::map<unsigned char, Session> sessioni;
    // TODO: Crea la nonce_list
    auto nonce_list = NonceList();
    if (argc == 1)
    {
        port = 4243;
    }
    else
        port = atoi(argv[1]);

    sd = socket(AF_INET, SOCK_STREAM, 0);
    printf("LOG_INFO: Socket creato correttamente\n");
    if (sd < 0)
    {
        exit(1);
    }

    memset(&myAddr, 0, sizeof(myAddr));
    myAddr.sin_family = AF_INET;
    myAddr.sin_port = htons(port);
    myAddr.sin_addr.s_addr = INADDR_ANY;

    ret = bind(sd, (struct sockaddr *)&myAddr, sizeof(myAddr));
    if (ret < 0)
        exit(-1);

    ret = listen(sd, 10);
    if (ret < 0)
        exit(-1);

    while (true)
    {
        len = sizeof(clAddr);
        newSd = accept(sd, (struct sockaddr *)&clAddr, &len);
        if (newSd < 0)
            exit(1);

        pid = fork();
        if (pid == 0)
        {
            if (int closeSd = close(sd); closeSd < 0)
            {
                printf("LOG_ERROR: Errore in fase di chiusura del socket\n");
                exit(1);
            }
            else
            {
                printf("LOG_INFO: Socket chiuso correttamente\n");
            }

            auto session = std::make_unique<Session>();
            session->socket = newSd;

            receive_message1(session.get(), nonce_list);
            // TODO: Implementare la funzione che legge la chiave privata del server (/server_file/key/server_private_key.pem)
            // TODO: Leggere la chiave pubblica del client (il file deve essere aperto concatenando il percorso fisso con lo username ricevuto dal client)
            // TODO: Chiama send_message2
            EVP_PKEY *client_public_key = load_public_key(("server_file/public_keys/" + session->username + "_public_key.pem").c_str());
            if (client_public_key == nullptr)
            {
                printf("LOG_ERROR: Errore in fase di caricamento della chiave pubblica del client\n");
                exit(1);
            }

            EVP_PKEY *server_private_key = load_private_key("server_file/keys/server_private_key.pem");
            if (server_private_key == nullptr)
            {
                printf("LOG_ERROR: Errore in fase di caricamento della chiave privata del server\n");
                exit(1);
            }

            send_message2(session.get(), client_public_key, server_private_key);
            // TODO: Chiama receive_message3
            // Handshake completato
        }
        else
        {
            close(newSd);
        }
    }
}