#include "server.h"

int main(int argc, char**argv)
{

    // TODO: Crea la mappa di sessioni
    // TODO: Crea la nonce_list
    if(argc == 1)
    {
        port = 4242;
    }
    else
        port = atoi(argv[1]);
    

    sd = socket(AF_INET, SOCK_STREAM, 0);

    if(sd < 0)
    {
        exit(1);
    }

    memset(&myAddr, 0, sizeof(myAddr));
    myAddr.sin_family = AF_INET;
    myAddr.sin_port = htons(port);
    myAddr.sin_addr.s_addr = INADDR_ANY;

    ret = bind(sd, (struct sockaddr *)&myAddr, sizeof(myAddr));
    if(ret < 0)
        exit(-1);
    
    ret = listen(sd, 10);
    if(ret < 0)
        exit(-1);

    while(1)
    {
        len = sizeof(clAddr);
        newSd = accept(sd, (struct sockaddr *)&clAddr, &len);
        if( newSd < 0)
            exit(1);

        pid = fork();
        if(pid == 0)
        {
            int closeSd = close(sd);
            if(closeSd < 0)
            {
                printf("LOG_ERROR: Errore in fase di chiusura del socket\n");
                exit(1);
            }
            else
                printf("LOG_INFO: Socket chiuso correttamente");
            // TODO: Crea la sessione
            // TODO: Salvo il socket nella sessione
            // TODO: Chiama receive_message1
            // TODO: Implementare la funzione che legge la chiave privata del server (/server_file/key/server_private_key.pem)
            // TODO: Leggere la chiave pubblica del client (il file deve essere aperto concatenando il percorso fisso con lo username ricevuto dal client)
            // TODO: Chiama send_message2
            // TODO: Chiama receive_message3
            // Handshake completato
            
        }



    }

}   