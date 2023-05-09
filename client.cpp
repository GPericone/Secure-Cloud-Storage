#include "client.h"

int main(int argc, char **argv)
{

 if (argc != 1)
    {
        ip_server = argv[1];
        server_port = atoi(argv[2]);
    } else {
        server_port = 4242;
    }

    // Create socket
    sd = socket(AF_INET, SOCK_STREAM, 0);

    memset(&srvAddr, 0, sizeof(srvAddr));
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_port = htons(server_port);
    inet_pton(AF_INET, ip_server, &srvAddr.sin_addr);
    ret = connect(sd, (struct sockaddr *)&srvAddr, sizeof(srvAddr));

    if (sd < 0 || ret < 0)
    {
        log_error("Error in connection" + std::to_string(sd) + " " + std::to_string(ret));
        exit(-1);
    }

    // Handshake with the server
    auto session = std::make_unique<Session>();
    session->socket = sd;

    if (!send_message1(session.get()))
    {
        log_error("Error in sending message 1");
        exit(1);
    }

    if (!receive_message2(session.get()))
    {
        log_error("Error in receiving message 2");
        exit(1);
    }

    if (!send_message3(session.get()))
    {
        log_error("Error in sending message 3");
        exit(1);
    }

    std::cout << "Handshake completed successfully" << std::endl;

    // Delete the ephemeral keys
    EVP_PKEY_free(session->eph_key_pub);
    EVP_PKEY_free(session->eph_key_priv);

    while (true)
    {
        // // Leggo il messaggio da tastiera
        // std::string input;
        // std::getline(std::cin, input);

        // // Invio il messaggio al server
        // if (!send_message(session.get(), input))
        // {
        //     std::cerr << "Errore nell'invio del messaggio al server" << std::endl;
        //     break;
        // }

        // // Ricevo la risposta del server
        // std::string response;
        // if (!receive_message(session.get(), response))
        // {
        //     std::cerr << "Errore nella ricezione della risposta dal server" << std::endl;
        //     break;
        // }

        // // Stampo la risposta del server a schermo
        // std::cout << "Risposta del server: " << response << std::endl;
    }

    // Close the connection with the server
    close(sd);
    return 0;
}