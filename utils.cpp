#include "utils.h"

void log_error(const std::string &msg)
{
    std::cerr << "Error: " << msg << std::endl;
}

/**
 * @brief The function serializes an integer and stores it in the provided buffer as unsigned char buffer.
 *
 * @param input the integer to be serialized
 * @param output the buffer where the serialized integer should be stored
 */
void serialize_int(int input, unsigned char *output)
{
    unsigned char *p = reinterpret_cast<unsigned char *>(&input);
    std::copy(p, p + sizeof(int), output);
}

/**
 * @brief The function serializes a long integer and stores it in the provided buffer as unsigned char buffer.
 *
 * @param input the long integer to be serialized
 * @param output the buffer where the serialized long integer should be stored
 */
void serialize_longint(long int input, unsigned char *output)
{
    unsigned char *p = reinterpret_cast<unsigned char *>(&input);
    std::copy(p, p + sizeof(long int), output);
}

/**
 * @brief Receive a specified number of bytes from a socket.
 *
 * This function receives data from the specified socket and stores it in the provided buffer.
 * It will continue to receive data until the specified number of bytes have been received or an
 * error occurs. In case of an error or if the connection is closed before receiving all the
 * requested bytes, the function returns the number of bytes received so far or -1 if an error occurred.
 *
 * @param socket The socket file descriptor from which data should be received.
 * @param buffer A pointer to the buffer where the received data should be stored.
 * @param len The number of bytes to receive.
 * @return The number of bytes actually received or -1 if an error occurred.
 */
int recv_all(int socket, void *buffer, ssize_t len)
{
    ssize_t bytes_left = len;                       // The number of bytes remaining to be received
    ssize_t bytes_read;                             // The number of bytes read in the current iteration
    char *buffer_ptr = static_cast<char *>(buffer); // A pointer to the current position in the buffer

    // Continue to receive data until all requested bytes have been read or an error occurs
    while (bytes_left > 0)
    {
        bytes_read = recv(socket, static_cast<void *>(buffer_ptr), bytes_left, 0);

        if (bytes_read < 0)
        {
            log_error("Failed to receive data from the socket");
            return -1;
        }

        if (bytes_read == 0)
        {
            break;
        }

        bytes_left -= bytes_read;
        buffer_ptr += bytes_read;

        return len - bytes_left;
    }
    return -1;
}

/**
 * @brief check if the username is registered
 *
 * @param username the username to check
 * @return true if the username is registered, false otherwise
 */
bool isRegistered(std::string_view username)
{
    std::string line;
    std::string word;

    // Open the file
    std::fstream file(F_NAME, std::ios::in);
    if (!file.is_open())
    {
        log_error("Could not open the file\n");
        return false;
    }

    // Read the file line by line
    while (getline(file, line))
    {
        std::stringstream str(line);
        while (getline(str, word, ' '))
        {
            // Compare the username with the word
            if (word.compare(username) == 0)
            {
                return true;
            }
        }
    }

    return false;
}

/**
 * @brief convert a size_t value to an int value in a safe way
 *
 * @param value the size_t value to convert
 *
 * @return int the converted value
 */
int safe_size_t_to_int(size_t value)
{
    if (value > static_cast<size_t>(std::numeric_limits<int>::max()))
    {
        throw std::runtime_error("Conversion error: size_t value is too large for int");
    }

    return static_cast<int>(value);
}

/**
 * @brief a variadic function that deletes a list of buffers
 *
 * @tparam T the type of the buffers
 * @param buffer the first buffer to delete
 */
template <typename T>
void deleteBuffers(T *buffer)
{
    delete[] buffer;
}

/**
 * @brief a variadic function that deletes a list of buffers
 *
 * @tparam T the type of the buffers
 * @tparam Ts the types of the buffers
 * @param buffer the first buffer to delete
 * @param buffers the other buffers to delete
 */
template <typename T, typename... Ts>
void deleteBuffers(T *buffer, Ts *...buffers)
{
    delete[] buffer;
    deleteBuffers(buffers...);
}

bool send_file(Session *session, std::string const &file_path)
{
    std::ifstream input_file(file_path, std::ios::binary);
    if (!input_file)
    {
        std::cerr << "Errore durante l'apertura del file " << file_path << std::endl;
        return false;
    }

    input_file.seekg(0, std::ios::beg);

    // Leggi il file a blocchi di 1 MB alla volta e invia ogni blocco
    std::string buffer;
    auto file_size = (double)std::filesystem::file_size(file_path);
    int num_sends = static_cast<int>((file_size + CHUNK_SIZE - 1) / CHUNK_SIZE);
    for (int i = 0; i < num_sends; ++i)
    {
        // pulisco il buffer;
        int esito = 1;
        auto bytes_to_read = CHUNK_SIZE;
        if (i == num_sends - 1)
        {
            bytes_to_read = static_cast<int>(file_size - i * CHUNK_SIZE);
            esito = 0;
        }
        buffer.resize(bytes_to_read);
        input_file.read(buffer.data(), bytes_to_read);
        if (!send_message(session, buffer, true, esito)) // inviare il flag finale solo per l'ultimo chunk
        {
            std::cerr << "Errore durante l'invio del file " << file_path << std::endl;
            buffer.clear();
            return false;
        }
        buffer.clear();
    }

    input_file.close();

    int esito;
    std::string response;
    if (!receive_message(session, &response, true, &esito))
    {
        std::cerr << "Errore durante la ricezione dell'esito del download del file " << file_path << std::endl;
        return false;
    }
    if (esito == 0)
    {
        std::cerr << "Errore durante il download del file " << file_path << std::endl;
        return false;
    }
    else
    {
        std::cout << "Download del file " << file_path << " completato" << std::endl;
        return true;
    }
}

std::string get_file_size_no_ext(std::string const &path)
{
    if (std::filesystem::is_directory(path))
    {
        return "";
    }
    int i{};
    auto mantissa = (double)std::filesystem::file_size(path);
    for (; mantissa >= 1024.; mantissa /= 1024., ++i)
    {
        // stiamo solo cercando la mantissa, nessuna operazione richiesta;
    }
    std::stringstream stream;
    stream << std::fixed << std::setprecision(2) << mantissa;
    return stream.str();
}

std::string get_file_size(std::string const &path)
{
    if (std::filesystem::is_directory(path))
    {
        return "";
    }
    int i{};
    auto mantissa = (double)std::filesystem::file_size(path);
    for (; mantissa >= 1024.; mantissa /= 1024., ++i)
    {
        // stiamo solo cercando la mantissa, nessuna operazione richiesta;
    }
    std::stringstream stream;
    stream << std::fixed << std::setprecision(2) << mantissa;
    return stream.str() + " " + "BKMGTPE"[i] + std::string((i == 0) ? "yte" : "B");
}

bool send_message(Session *session, const std::string payload)
{
    return send_message(session, payload, false, 0);
}

bool send_message(Session *session, const std::string payload, bool send_esito, int esito)
{
    // Serialize the username length
    unsigned char *command_len_byte = new unsigned char[sizeof(int)];
    serialize_int(safe_size_t_to_int(payload.size()), command_len_byte);

    // Serialize the counter
    unsigned char counter_byte[sizeof(int)];
    serialize_int(session->counter + 1, counter_byte);

    // Calculate message size and allocate the buffer
    int message_size = sizeof(int) + sizeof(int) + payload.size();
    if (send_esito)
    {
        message_size += sizeof(int);
    }
    unsigned char *message = new unsigned char[message_size];

    // Construct the message: length_payload | counter | command
    memcpy(message, command_len_byte, sizeof(int));
    memcpy(message + sizeof(int), counter_byte, sizeof(int));
    // if send_esito send esito
    if (send_esito)
    {
        unsigned char esito_byte[sizeof(int)];
        serialize_int(esito, esito_byte);
        memcpy(message + sizeof(int) * 2, esito_byte, sizeof(int));
        memcpy(message + sizeof(int) * 3, payload.c_str(), payload.size());
    }
    else
    {
        memcpy(message + sizeof(int) * 2, payload.c_str(), payload.size());
    }

    // Send the message
    if (send(session->socket, message, message_size, 0) < 0)
    {
        log_error("Error sending message");
        delete_buffers(command_len_byte, message);
        return false;
    }

    // Update the session counter
    session->counter++;

    // Clean up and return
    delete_buffers(command_len_byte, message);
    return true;
}

bool check_availability_to_upload(std::string const &path, std::string *response)
{
    if (std::filesystem::is_directory(path))
    {
        *response = "Il file è una directory";
        return false;
    }
    else if (!std::filesystem::exists(path))
    {
        *response = "Il file non esiste";
        return false;
    }
    else
    {
        // Check file size
        std::ifstream input_file(path, std::ios::binary);
        input_file.seekg(0, std::ios::end);
        std::streampos file_size = input_file.tellg();
        input_file.seekg(0, std::ios::beg);
        if (file_size > UINT32_MAX)
        {
            *response = "Errore: il file " + path + " supera i 4 GB di dimensione.";
            input_file.close();
            return false;
        }
        // response prende la dimensione del file
        input_file.close();
        *response = get_file_size_no_ext(path);
        return true;
    }
}

bool UploadClient::execute(Session *session, std::string command)
{
    std::istringstream iss(command);
    std::vector<std::string> tokens;
    std::string token;
    while (std::getline(iss, token, ' '))
    {
        tokens.push_back(token);
    }

    if (tokens.size() != 2)
    {
        printf("Il comando richiede 1 parametro, nome del file da caricare, riprova\n");
        send_message(session, "Il comando richiede 1 parametro, nome del file da caricare, riprova\n");
        return true;
    }

    std::string file_to_upload = tokens[1];

    printf("file_to_upload: %s\n", file_to_upload.c_str());

    std::string response_existance;
    bool check_file = check_availability_to_upload(file_to_upload, &response_existance);
    send_message(session, response_existance, true, check_file);

    if (check_file)
    {
        std::string response;
        int success;
        receive_message(session, &response, true, &success);

        if (success == 1)
        {
            // TODO: divido il file in chunk di 1 MB e li invio
            send_file(session, file_to_upload.c_str());
        }
        else
        {
            printf("File non caricato %s\n", response.c_str());
        }
    }

    return true;
}

bool DownloadClient::execute(Session *session, std::string command)
{
    std::istringstream iss(command);
    std::vector<std::string> tokens;
    std::string token;
    while (std::getline(iss, token, ' '))
    {
        tokens.push_back(token);
    }

    if (tokens.size() != 2)
    {
        printf("Il comando richiede 1 parametro, nome del file da scaricare, riprova\n");
        send_message(session, "Il comando richiede 1 parametro, nome del file da scaricare, riprova\n");
        return true;
    }

    std::string response_existance;
    int exists;
    receive_message(session, &response_existance, true, &exists);

    std::cout << response_existance;

    std::string file_to_download = tokens[1];

    if (exists == 1)
    {
        // ricevo da tastiera s o n
        std::string esito;
        std::cin >> esito;

        std::string response;
        send_message(session, esito);

        std::ofstream output_file("download/" + file_to_download, std::ios::binary);
        if (!output_file)
        {
            std::cerr << "Errore durante la creazione del file " << file_to_download << std::endl;
            return false;
        }

        bool is_last = false;
        while (!is_last)
        {
            std::string buffer;
            int esito_receive;
            if (!receive_message(session, &buffer, true, &esito_receive))
            {
                std::cerr << "Errore durante la ricezione del file " << file_to_download << std::endl;
                break;
            }
            is_last = esito_receive == 0;
            output_file << buffer;
        }

        // Leggi il file a blocchi di 1 MB alla volta e scrivi ogni blocco

        output_file.close();
    }
    else
    {
        std::cout << "\n";
        return true;
    }

    send_message(session, "File scaricato correttamente\n", true, 1);
    return true;
}

bool DeleteClient::execute(Session *session, std::string command)
{
    std::string response_existance;
    int exists;
    receive_message(session, &response_existance, true, &exists);

    std::cout << response_existance;

    if (exists == 1)
    {
        // ricevo da tastiera s o n
        std::string esito;
        std::cin >> esito;

        std::string response;
        send_message(session, esito);

        std::string response_delete;
        receive_message(session, &response_delete);

        printf("%s\n", response_delete.c_str());
        return true;
    }
    else
    {
        std::cout << "\n";
        return true;
    }
}

bool ListClient::execute(Session *session, std::string command)
{
    std::string response;
    if (!receive_message(session, &response))
    {
        log_error("Failed to receive message");
        return false;
    }
    printf("%s\n", response.c_str());
    return true;
}

bool RenameClient::execute(Session *session, std::string command)
{

    std::string response;
    if (!receive_message(session, &response))
    {
        log_error("Failed to receive message");
        return false;
    }
    printf("%s\n", response.c_str());
    return true;
}

bool LogoutClient::execute(Session *session, std::string command)
{
    return false;
}

bool receive_message(Session *server_session, std::string *payload)
{
    return receive_message(server_session, payload, false, nullptr);
}

bool receive_message(Session *server_session, std::string *payload, bool receive_esito, int *esito)
{
    // Read the payload length from the socket
    int message_len;
    unsigned char *message_len_byte = new unsigned char[sizeof(int)];
    if ((recv_all(server_session->socket, (void *)message_len_byte, sizeof(int))) != sizeof(int))
    {
        log_error("Failed to read payload length");
        delete_buffers(message_len_byte);
        return false;
    }
    memcpy(&message_len, message_len_byte, sizeof(int));

    // Read the counter from the socket
    int counter;
    unsigned char *counter_byte = new unsigned char[sizeof(int)];
    if ((recv_all(server_session->socket, (void *)counter_byte, sizeof(int))) != sizeof(int))
    {
        log_error("Failed to read counter");
        delete_buffers(message_len_byte, counter_byte);
        return false;
    }
    memcpy(&counter, counter_byte, sizeof(int));

    // TODO : aggiungere due counter, sistemare controllo
    if (counter != server_session->counter + 1)
    {
        log_error("Counter mismatch");
        delete_buffers(message_len_byte, counter_byte);
        return false;
    }

    server_session->counter++;

    if (receive_esito)
    {
        unsigned char *esito_byte = new unsigned char[sizeof(int)];
        if ((recv_all(server_session->socket, (void *)esito_byte, sizeof(int))) != sizeof(int))
        {
            log_error("Failed to read esito");
            delete_buffers(message_len_byte, counter_byte, esito_byte);
            return false;
        }
        memcpy(esito, esito_byte, sizeof(int));
    }

    // Read the command from the socket
    unsigned char *message = new unsigned char[message_len];
    if (recv_all(server_session->socket, (void *)message, message_len) != message_len)
    {
        log_error("Failed to receive the payload");
        delete_buffers(message_len_byte, counter_byte);
        return false;
    }

    *payload = std::string(reinterpret_cast<char *>(message), message_len);

    delete_buffers(message_len_byte, counter_byte);
    return true;
}

bool UploadServer::execute(Session *session, std::string command)
{
    std::istringstream iss(command);
    std::vector<std::string> tokens;
    std::string token;
    while (std::getline(iss, token, ' '))
    {
        tokens.push_back(token);
    }

    if (tokens.size() != 2)
    {
        printf("Il comando richiede 1 parametro, nome del file da scaricare, riprova\n");
        send_message(session, "Il comando richiede 1 parametro, nome del file da scaricare, riprova\n");
        return true;
    }

    std::string file_size;
    int esito = 0;
    receive_message(session, &file_size, true, &esito);

    if (esito == 0)
    {
        return true;
    }

    // check che il file non sia più grande di 4GB
    std::string esito_string = "";
    int valido = 1;
    if (std::stoi(file_size) > UINT32_MAX)
    {
        esito_string = "Dimensione file maggiore di 4GB, riprova\n";
        valido = 0;
    }

    std::string file_to_upload = tokens[1];

    if (valido == 1)
    {
        std::ofstream output_file("upload/" + file_to_upload, std::ios::binary);
        if (!output_file)
        {
            std::cerr << "Errore durante la creazione del file " << file_to_upload << std::endl;
            esito_string = "Errore durante la creazione del file " + file_to_upload + "\n";
            valido = 0;
        }

        send_message(session, esito_string, true, valido);
        if (valido == 0)
        {
            std::cout << "\n";
            return true;
        }
        bool is_last = false;
        while (!is_last)
        {
            std::string buffer;
            int esito_receive;
            if (!receive_message(session, &buffer, true, &esito_receive))
            {
                std::cerr << "Errore durante la ricezione del file " << file_to_upload << std::endl;
                break;
            }
            is_last = esito_receive == 0;
            output_file << buffer;
        }

        // Leggi il file a blocchi di 1 MB alla volta e scrivi ogni blocco

        output_file.close();
    }
    else
    {
        send_message(session, esito_string, true, valido);
        std::cout << "\n";
        return true;
    }

    send_message(session, "File scaricato correttamente\n", true, 1);
    return true;
}

bool check_availability_to_download(std::string const &path, std::string *response)
{
    if (std::filesystem::is_directory(path))
    {
        *response = "Il file è una directory, impossibile scaricarla";
        return false;
    }
    else if (!std::filesystem::exists(path))
    {
        *response = "Il file non esiste";
        return false;
    }
    else
    {
        // Check file size
        std::ifstream input_file(path, std::ios::binary);
        input_file.seekg(0, std::ios::end);
        std::streampos file_size = input_file.tellg();
        input_file.seekg(0, std::ios::beg);
        if (file_size > UINT32_MAX)
        {
            *response = "Errore: il file " + path + " supera i 4 GB di dimensione.";
            return false;
        }
        *response = "Il file esiste," + path + " ha una dimensione di " + get_file_size(path) + " sei sicuro di voler effettuare il download? (s/n)";
        return true;
    }
}

bool DownloadServer::execute(Session *session, std::string command)
{
    std::istringstream iss(command);
    std::vector<std::string> tokens;
    std::string token;
    while (std::getline(iss, token, ' '))
    {
        tokens.push_back(token);
    }

    if (tokens.size() != 2)
    {
        printf("Il comando richiede 1 parametro, nome del file da scaricare, riprova\n");
        send_message(session, "Il comando richiede 1 parametro, nome del file da scaricare, riprova\n");
        return true;
    }

    std::string file_to_download = tokens[1];

    printf("file_to_download: %s\n", file_to_download.c_str());

    std::string response_existance;
    bool exists = check_availability_to_download(file_to_download, &response_existance);
    send_message(session, response_existance, true, exists);

    if (exists)
    {
        std::string response;
        receive_message(session, &response);

        // se response è uguale a s elimino altrimenti no
        if (response == "s")
        {
            // TODO: divido il file in chunk di 1 MB e li invio
            send_file(session, file_to_download.c_str());
        }
        else
        {
            printf("File non scaricato\n");
            send_message(session, "File non scaricato\n");
        }
    }

    return true;
}

bool check_file_existance(std::string const &path, std::string *response)
{
    if (std::filesystem::is_directory(path))
    {
        *response = "Il file è una directory, impossibile eliminarla";
        return false;
    }
    else if (!std::filesystem::exists(path))
    {
        *response = "Il file non esiste";
        return false;
    }
    else
    {
        *response = "Il file esiste, sei sicuro di voler eliminare " + path + "? (s/n)";
        return true;
    }
}

std::string delete_file(std::string const &path)
{
    if (std::filesystem::exists(path))
    {
        std::filesystem::remove(path);
        return "File " + path + " eliminato con successo\n ";
    }
    return "File non trovato";
}

bool DeleteServer::execute(Session *session, std::string command)
{
    std::istringstream iss(command);
    std::vector<std::string> tokens;
    std::string token;
    while (std::getline(iss, token, ' '))
    {
        tokens.push_back(token);
    }

    if (tokens.size() != 2)
    {
        printf("Il comando richiede 1 parametro, nome del file da eliminare, riprova\n");
        send_message(session, "Il comando richiede 1 parametro, nome del file da eliminare, riprova\n");
        return true;
    }

    std::string file_to_delete = tokens[1];

    printf("file_to_delete: %s\n", file_to_delete.c_str());

    std::string response_existance;
    bool exists = check_file_existance(file_to_delete, &response_existance);
    send_message(session, response_existance, true, exists);

    if (exists)
    {
        std::string response;
        receive_message(session, &response);

        // se response è uguale a s elimino altrimenti no
        if (response == "s")
        {
            send_message(session, delete_file(file_to_delete));
        }
        else
        {
            printf("File non eliminato\n");
            send_message(session, "File non eliminato\n");
        }
    }

    return true;
}

bool ListServer::execute(Session *session, std::string command)
{
    std::string path = ".";
    DIR *folder = opendir(path.c_str());
    if (path.empty() || !folder)
    {
        log_error("Failed to open directory");
        return false;
    }
    struct dirent const *dp;
    std::string temp;
    std::string size;
    auto ret = std::string("File disponibili sul server:\n");

    // FILE *proc = popen("/bin/ls -al", "r");
    // char buf[1024];
    // while (!feof(proc) && fgets(buf, sizeof(buf), proc))
    // {
    //     printf("* %s", buf);
    // }

    while ((dp = readdir(folder)) != nullptr)
    {
        char const *filename = dp->d_name;
        if (filename[0] == '.')
        {
            continue;
        }
        ret += " * " + get_file_size(path + "/" + filename) + "\t\t" + std::string(filename) + "\n";
    }
    closedir(folder);
    send_message(session, ret);
    return true;
}

std::string rename_file(std::string const &old_file_name, std::string const &new_file_name)
{
    // check esistenza file con nome oldFilePath
    if (old_file_name.empty() || new_file_name.empty())
    {
        return "Nome file non valido";
    }

    if (!std::ifstream(old_file_name))
    {
        return "File con nome " + old_file_name + " non esistente";
    }

    // check esistenza file con nome newFilePath
    if (std::ifstream(new_file_name))
    {
        return "File con nome " + new_file_name + " già esistente";
    }

    if (rename(old_file_name.c_str(), new_file_name.c_str()) == 0)
    {
        return "File " + old_file_name + " rinominato in " + new_file_name;
    }
    return "Errore nella rinomina del file";
}

bool RenameServer::execute(Session *session, std::string command)
{
    std::istringstream iss(command);
    std::vector<std::string> tokens;
    std::string token;
    while (std::getline(iss, token, ' '))
    {
        tokens.push_back(token);
    }

    if (tokens.size() != 3)
    {
        printf("Il comando richiede esattamente 2 parametri, nome del file da rinominare e nuovo nome del file, riprova\n");
        send_message(session, "Il comando richiede esattamente 2 parametri, nome del file da rinominare e nuovo nome del file, riprova\n");
        return true;
    }

    std::string old_name = tokens[1];
    std::string new_name = tokens[2];

    printf("old_name: %s\n", old_name.c_str());
    printf("new_name: %s\n", new_name.c_str());

    send_message(session, rename_file(old_name, new_name));

    return true;
}

bool LogoutServer::execute(Session *session, std::string command)
{
    return false;
}