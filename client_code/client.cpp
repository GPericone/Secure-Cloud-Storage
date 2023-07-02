#include "utils.h"

int main(int argc, char **argv)
{
    struct sockaddr_in srv_addr;
    const char *ip_server = "127.0.0.1";
    const unsigned short int server_port = 4242;
    int sd;

    // Check that there is at least one argument
    if (argc >= 2)
    {
        // Check if the argument is a valid IP address
        struct in_addr addr;
        if (inet_pton(AF_INET, argv[1], &addr) == 1)
        {
            ip_server = argv[1];
        }
        else
        {
            log_error("Invalid IP address: " + std::string(argv[1]), false);
            exit(1);
        }
    }

    // Check if there is a second argument
    if (argc >= 3)
    {
        // Check if the argument is -d (debug mode)
        if (strcmp(argv[2], "-d") == 0)
        {
            DEBUG_MODE = true;
        }
        else
        {
            log_error("Invalid argument: " + std::string(argv[2]), false);
            exit(1);
        }
    }

    // Create socket
    sd = socket(AF_INET, SOCK_STREAM, 0);

    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, ip_server, &srv_addr.sin_addr);
    
    if (sd < 0 || connect(sd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0)
    {
        log_error("Error in connection, socket=%d" + std::to_string(sd), true);
        log_error("Error in connection", false);
        exit(1);
    }

    // The client does the handshake with the server
    std::unique_ptr<Session> session(new Session());
    session->socket = sd;

    if (!receive_message1(session.get()))
    {
        log_error("Error receiving message 1", true);
        log_error("Error during authentication", false);
        exit(1);
    }

    if (!send_message2(session.get()))
    {
        log_error("Error sending message 2", true);
        log_error("Error during authentication", false);
        exit(1);
    }

    if (!receive_message3(session.get()))
    {
        log_error("Error receiving message 3", true);
        log_error("Error during authentication", false);
        exit(1);
    }

    if (!send_message4(session.get()))
    {
        log_error("Error sending message 4", true);
        log_error("Error during authentication", false);
        exit(1);
    }

    std::cout << "Authentication completed successfully" << std::endl;

    // Delete the ephemeral keys
    EVP_PKEY_free(session->eph_key_pub);
    EVP_PKEY_free(session->eph_key_priv);

    // Map of commands
    std::map<std::string, std::unique_ptr<CommandClient>> client_command_map;
    client_command_map["upload"].reset(new UploadClient());
    client_command_map["download"].reset(new DownloadClient());
    client_command_map["delete"].reset(new DeleteClient());
    client_command_map["list"].reset(new ListClient());
    client_command_map["rename"].reset(new RenameClient());
    client_command_map["logout"].reset(new LogoutClient());

    // Print the instructions
    std::cout << instruction << std::endl;

    while (true)
    {
        // Read the input from the user
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        std::string command;
        std::cout << "> ";
        // Delete eventual sync problems
        std::cin.sync();
        // Read the command from the user and store it in the string command
        std::getline(std::cin, command);
        std::cout << std::endl;

        std::cout << "The command entered is: " << command << std::endl;

        // Search the command in the map
        auto iter = client_command_map.find(command.substr(0, command.find(' ')));
        if (iter != client_command_map.end())
        {
            if (!iter->second->validate_command(session.get(), command))
            {
                log_error("Invalid command", false);
                std::cout << "Operation completed successfully, press ENTER to continue..." << std::endl;
                continue;
            }
            if (!send_message(session.get(), command))
            {
                log_error("Error in sending message", false);
                break;
            }
            if (iter->second->execute(session.get(), command) == false)
            {
                break;
            }
        }
        else
        {
            log_error("Command not recognized", false);
        }
        std::cout << "Operation completed successfully, press ENTER to continue..." << std::endl;
    }

    // Close the connection with the server
    client_command_map.clear();
    session.reset();
    close(sd);
    return 0;
}