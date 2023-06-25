#include "utils.h"

int main(int argc, char **argv)
{
    struct sockaddr_in srv_addr;
    const char *ip_server = "127.0.0.1";
    const unsigned short int server_port = 4242;
    int sd;

    if (argc != 1)
    {
        ip_server = argv[1];
    }

    // Create socket
    sd = socket(AF_INET, SOCK_STREAM, 0);

    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, ip_server, &srv_addr.sin_addr);
    
    if (sd < 0 || connect(sd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0)
    {
        log_error("Error in connection, socket=%d" + std::to_string(sd));
        exit(1);
    }

    // Effettuo l'handshake con il server
    std::unique_ptr<Session> session(new Session());
    session->socket = sd;

    if (!receive_message1(session.get()))
    {
        log_error("Error receiving message 0");
        exit(1);
    }

    if (!send_message2(session.get()))
    {
        log_error("Error sending message 1");
        exit(1);
    }

    if (!receive_message3(session.get()))
    {
        log_error("Error receiving message 2");
        exit(1);
    }

    if (!send_message4(session.get()))
    {
        log_error("Error sending message 3");
        exit(1);
    }

    std::cout << "Handshake completed successfully" << std::endl;

    // Delete the ephemeral keys
    EVP_PKEY_free(session->eph_key_pub);
    EVP_PKEY_free(session->eph_key_priv);

    std::map<std::string, std::unique_ptr<CommandClient>> client_command_map;
    
    client_command_map["upload"].reset(new UploadClient());
    client_command_map["download"].reset(new DownloadClient());
    client_command_map["delete"].reset(new DeleteClient());
    client_command_map["list"].reset(new ListClient());
    client_command_map["rename"].reset(new RenameClient());
    client_command_map["logout"].reset(new LogoutClient());

    // Invio e ricezione messaggi con il server
    std::cout << instruction << std::endl;

    while (true)
    {
        // Leggo il messaggio da tastiera
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        std::string command;
        std::cout << "> ";
        // Elimina eventuali errori di sincronizzazione
        std::cin.sync();
        // Legge l'intera riga di input
        std::getline(std::cin, command);
        std::cout << std::endl;

        std::cout << "Il comando inserito è: " << command << std::endl;

        // Cerca il comando nella mappa
        auto iter = client_command_map.find(command.substr(0, command.find(' ')));
        if (iter != client_command_map.end())
        {
            if (!send_message(session.get(), command))
            {
                log_error("Error in sending message");
                break;
            }
            if (iter->second->execute(session.get(), command) == false)
            {
                break;
            }
        }
        else
        {
            std::cout << "Comando non riconosciuto" << std::endl;
        }
        std::cout << "Operazione conclusa con successo, premi INVIO per continuare..." << std::endl;
    }

    // Chiudo la connessione con il server
    client_command_map.clear();
    session.reset();
    close(sd);
    return 0;
}