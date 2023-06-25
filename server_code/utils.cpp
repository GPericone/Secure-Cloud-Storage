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

void serialize_longint(long int value, unsigned char *buffer, size_t buffer_size)
{
    if (buffer_size >= sizeof(long int))
    {
        std::memcpy(buffer, &value, sizeof(long int));
    }
    else
    {
        std::cout << "Dimensione del buffer insufficiente!" << std::endl;
    }
}

bool deserializeNumber(const unsigned char *buffer, long int *result)
{
    if (buffer == nullptr || result == nullptr)
    {
        return false; // Controllo di validità dei puntatori
    }

    *result = 0;

    for (long unsigned int i = 0; i < sizeof(long int); i++)
    {
        if (buffer[i] == '\0')
        {
            break; // Interrompi la deserializzazione se viene trovato un carattere di fine stringa
        }
        *result |= static_cast<long int>(buffer[i]) << (8 * i);
    }

    return true;
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
    }
    return len - bytes_left;
}

/**
 * @brief check if the username is registered
 *
 * @param username the username to check
 * @return true if the username is registered, false otherwise
 */
bool isRegistered(std::string username)
{
    std::string line;
    std::string word;

    // Open the file
    std::fstream file(USERNAMES_FILE, std::ios::in);
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

double get_double_file_size(std::string const &path)
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        return 0.0;
    }

    std::streampos fileSize = file.tellg();
    file.close();

    printf("File size: %f\n", static_cast<double>(fileSize));

    return static_cast<double>(fileSize);
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
    // int file_size = get_file_size_no_ext(file_path);
    auto file_size = get_double_file_size(file_path);
    int num_sends = static_cast<int>((file_size + CHUNK_SIZE - 1) / CHUNK_SIZE);
    for (int i = 0; i < num_sends; ++i)
    {
        int esito = 1;
        auto bytes_to_read = CHUNK_SIZE;
        if (i == num_sends - 1)
        {
            bytes_to_read = static_cast<int>(file_size - i * CHUNK_SIZE);
            esito = 0;
        }
        buffer.resize(bytes_to_read);
        input_file.read(&buffer[0], bytes_to_read);
        std::copy(buffer.begin(), buffer.end(), const_cast<char *>(buffer.data()));

        if (!send_message(session, std::string(buffer.begin(), buffer.end()), true, esito)) // inviare il flag finale solo per l'ultimo chunk
        {
            std::cerr << "Errore durante l'invio del file " << file_path << std::endl;
            input_file.close();
            return false;
        }
        // pulisco il buffer;
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

std::string get_file_size_no_ext(const std::string &path)
{
    auto mantissa = get_double_file_size(path);
    int i = 0;
    for (; mantissa >= 1024.0; mantissa /= 1024.0, ++i)
    {
        // Stiamo solo cercando la mantissa, nessuna operazione richiesta
    }

    std::stringstream stream;
    stream << std::fixed << std::setprecision(2) << mantissa;
    return stream.str();
}

std::string get_file_size(std::string const &path)
{
    auto mantissa = get_double_file_size(path);
    int i = 0;
    for (; mantissa >= 1024.0; mantissa /= 1024.0, ++i)
    {
        // Stiamo solo cercando la mantissa, nessuna operazione richiesta
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
    int aad_len = sizeof(int) + ((send_esito) ? sizeof(int) : 0);
    unsigned char *plaintext = new unsigned char[payload.size()];
    unsigned char *aad = new unsigned char[aad_len];
    unsigned char *iv = new unsigned char[IV_LEN];
    unsigned char *tag = new unsigned char[TAG_LEN];
    unsigned char *ciphertext = new unsigned char[payload.size()];

    // Serialize the command length
    unsigned char *command_len_byte = new unsigned char[sizeof(long int)];
    serialize_longint(payload.size(), command_len_byte, sizeof(long int));

    // Serialize the counter
    unsigned char *counter_byte = new unsigned char[sizeof(int)];
    serialize_int(session->server_counter, counter_byte);

    memcpy(aad, counter_byte, sizeof(int));
    if (send_esito)
    {
        unsigned char *esito_byte = new unsigned char[sizeof(int)];
        serialize_int(esito, esito_byte);
        memcpy(aad + sizeof(int), esito_byte, sizeof(int));
        delete_buffers(esito_byte);
    }
    memcpy(plaintext, payload.c_str(), payload.size());

    // Generate a random IV
    if (!RAND_bytes(iv, safe_size_t_to_int(IV_LEN)))
    {
        log_error("Error generating IV");
        delete_buffers(plaintext, aad, iv, tag, command_len_byte, counter_byte);
        return false;
    }

    // Encrypt the message using AES-GCM
    int ciphertext_len = aesgcm_encrypt(plaintext, safe_size_t_to_int(payload.size()), aad, aad_len, session->aes_key, iv, safe_size_t_to_int(IV_LEN), ciphertext, tag);
    if (ciphertext_len < 0)
    {
        log_error("Error encrypting message");
        delete_buffers(plaintext, aad, iv, tag, ciphertext, command_len_byte, counter_byte);
        return false;
    }

    int message_size = sizeof(long int) + aad_len + ciphertext_len + TAG_LEN + IV_LEN;

    unsigned char *message = new unsigned char[message_size];
    // message: payload_len | counter | esito* | payload | tag | iv
    memcpy(message, command_len_byte, sizeof(int));
    memcpy(message + sizeof(long int), aad, aad_len);
    memcpy(message + sizeof(long int) + aad_len, ciphertext, ciphertext_len);
    memcpy(message + sizeof(long int) + aad_len + ciphertext_len, tag, TAG_LEN);
    memcpy(message + sizeof(long int) + aad_len + ciphertext_len + TAG_LEN, iv, IV_LEN);

    // Send the message
    if (send(session->socket, message, message_size, 0) < 0)
    {
        log_error("Error sending message");
        delete_buffers(plaintext, aad, iv, tag, ciphertext, command_len_byte, counter_byte, message);
        return false;
    }

    if (session->server_counter + 1 >= UINT_MAX)
    {
        printf("Il contatore del server ha raggiunto il massimo valore consentito\n");
        return false;
    }

    // Update the session counter
    session->server_counter++;

    // Clean up and return
    delete_buffers(plaintext, aad, iv, tag, ciphertext, command_len_byte, counter_byte, message);
    return true;
}

bool receive_message(Session *session, std::string *payload)
{
    return receive_message(session, payload, false, nullptr);
}

bool receive_message(Session *session, std::string *payload, bool receive_esito, int *esito)
{
    // Read the payload length from the socket
    long int message_len;
    unsigned char *message_len_byte = new unsigned char[sizeof(long int)];
    if ((recv_all(session->socket, (void *)message_len_byte, sizeof(long int))) != sizeof(long int))
    {
        log_error("Failed to read payload length");
        delete_buffers(message_len_byte);
        return false;
    }
    deserializeNumber(message_len_byte, &message_len);
    printf("Message length: %ld\n", message_len);

    // Allocate buffers for the ciphertext and plaintext
    unsigned char *ciphertext = new unsigned char[message_len];
    unsigned char *plaintext = new unsigned char[message_len];

    // Read the counter from the socket
    unsigned int counter;
    unsigned char *counter_byte = new unsigned char[sizeof(int)];
    if ((recv_all(session->socket, (void *)counter_byte, sizeof(int))) != sizeof(int))
    {
        log_error("Failed to read counter");
        delete_buffers(message_len_byte, counter_byte, ciphertext, plaintext);
        return false;
    }
    memcpy(&counter, counter_byte, sizeof(int));

    if (counter != session->client_counter)
    {
        log_error("Counter mismatch");
        delete_buffers(message_len_byte, counter_byte, ciphertext, plaintext);
        return false;
    }

    session->client_counter++;

    unsigned char *esito_byte = new unsigned char[sizeof(int)];
    if (receive_esito)
    {
        if ((recv_all(session->socket, (void *)esito_byte, sizeof(int))) != sizeof(int))
        {
            log_error("Failed to read esito");
            delete_buffers(message_len_byte, counter_byte, ciphertext, plaintext, esito_byte);
            return false;
        }
        memcpy(esito, esito_byte, sizeof(int));
    }

    int aad_len = sizeof(int) + ((receive_esito) ? sizeof(int) : 0);
    unsigned char *aad = new unsigned char[aad_len];
    memcpy(aad, counter_byte, sizeof(int));
    if (receive_esito)
    {
        memcpy(aad + sizeof(int), esito_byte, sizeof(int));
        delete_buffers(esito_byte);
    }
    // Allocate buffers for the tag
    unsigned char *tag = new unsigned char[TAG_LEN];

    // Receive the ciphertext
    if (recv_all(session->socket, (void *)ciphertext, message_len) != message_len)
    {
        log_error("Error receiving ciphertext");
        delete_buffers(message_len_byte, counter_byte, ciphertext, plaintext, aad, tag);
        return false;
    }

    // Receive the tag
    if (recv_all(session->socket, (void *)tag, TAG_LEN) != TAG_LEN)
    {
        log_error("Error receiving tag");
        delete_buffers(message_len_byte, counter_byte, ciphertext, plaintext, aad, tag);
        return false;
    }

    // Allocate buffers for the IV
    unsigned char *iv = new unsigned char[IV_LEN];

    // Receive the IV
    if (recv_all(session->socket, (void *)iv, IV_LEN) != (int)IV_LEN)
    {
        log_error("Error receiving IV");
        delete_buffers(message_len_byte, counter_byte, ciphertext, plaintext, aad, tag, iv);
        return false;
    }

    // Decrypt the message
    int plaintext_len = aesgcm_decrypt(ciphertext, message_len, aad, aad_len, tag, session->aes_key, iv, safe_size_t_to_int(IV_LEN), plaintext);
    if (plaintext_len < 0)
    {
        log_error("Error decrypting message");
        delete_buffers(message_len_byte, counter_byte, ciphertext, plaintext, aad, tag, iv);
        return false;
    }

    *payload = std::string(reinterpret_cast<char *>(plaintext), message_len);
    delete_buffers(message_len_byte, counter_byte, ciphertext, plaintext, aad, tag, iv);
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
        if (!send_message(session, "Il comando richiede 1 parametro, nome del file da scaricare, riprova\n"))
        {
            log_error("Failed to send message");
            return false;
        }
        return true;
    }

    std::string file_size;
    int esito = 0;
    if (!receive_message(session, &file_size, true, &esito))
    {
        log_error("Failed to receive message");
        return false;
    }

    if (esito == 0)
    {
        return true;
    }

    // check che il file non sia più grande di 4GB
    std::string esito_string = "";
    int valido = 1;
    if (std::stoul(file_size) > UINT32_MAX)
    {
        esito_string = "Dimensione file maggiore di 4GB, riprova\n";
        valido = 0;
    }

    std::string file_to_upload = tokens[1];

    if (valido == 1)
    {
        std::ofstream output_file("server_file/users/" + session->username + "/" + file_to_upload, std::ios::binary);
        if (!output_file)
        {
            std::cerr << "Errore durante la creazione del file " << file_to_upload << std::endl;
            esito_string = "Errore durante la creazione del file " + file_to_upload + "\n";
            valido = 0;
        }

        if (!send_message(session, esito_string, true, valido))
        {
            log_error("Failed to send message");
            return false;
        }
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
        if (!send_message(session, esito_string, true, valido))
        {
            log_error("Failed to send message");
            return false;
        }
        std::cout << "\n";
        return true;
    }

    if (!send_message(session, "File scaricato correttamente\n", true, 1))
    {
        log_error("Failed to send message");
        return false;
    }
    return true;
}

bool check_availability_to_download(std::string const &path, std::string *response)
{

    // Check file size
    std::ifstream input_file(path, std::ios::binary);
    if (!input_file.is_open())
    {
        *response = "Errore: impossibile aprire il file " + path + ".";
        return false;
    }
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
        if (!send_message(session, "Il comando richiede 1 parametro, nome del file da scaricare, riprova\n"))
        {
            log_error("Failed to send message");
            return false;
        }
        return true;
    }

    std::string file_to_download = "server_file/users/" + session->username + "/" + tokens[1];

    printf("file_to_download: %s\n", file_to_download.c_str());

    std::string response_existance = "Il nome del file non rispetta i requisiti previsti, riprova\n";
    bool exists = std::regex_match(tokens[1], pattern) && check_availability_to_download(file_to_download, &response_existance);
    if (!send_message(session, response_existance, true, exists))
    {
        log_error("Failed to send message");
        return false;
    }

    if (exists)
    {
        std::string response;
        if (!receive_message(session, &response))
        {
            log_error("Failed to receive message");
            return false;
        }

        // se response è uguale a s elimino altrimenti no
        if (response == "s")
        {
            // TODO: divido il file in chunk di 1 MB e li invio
            if (!send_file(session, file_to_download.c_str()))
            {
                log_error("Failed to send file");
                return false;
            }
        }
        else
        {
            printf("File non scaricato\n");
            if (!send_message(session, "File non scaricato\n"))
            {
                log_error("Failed to send message");
                return false;
            }
        }
    }

    return true;
}

bool check_file_existance(std::string const &path, std::string *response)
{
    std::ifstream input_file(path, std::ios::binary);
    if (!input_file.is_open())
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
    if (std::remove(path.c_str()) == 0)
    {
        return "File " + path + " eliminato con successo\n";
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
        if (!send_message(session, "Il comando richiede 1 parametro, nome del file da eliminare, riprova\n"))
        {
            log_error("Failed to send message");
            return false;
        }
        return true;
    }

    std::string file_to_delete = "server_file/users/" + session->username + "/" + tokens[1];

    printf("file_to_delete: %s\n", file_to_delete.c_str());
    //TODO: verifica nome file 
    std::string response_existance;
    bool exists = check_file_existance(file_to_delete, &response_existance);
    if (!send_message(session, response_existance, true, exists))
    {
        log_error("Failed to send message");
        return false;
    }

    if (exists)
    {
        std::string response;
        if (!receive_message(session, &response))
        {
            log_error("Failed to receive message");
            return false;
        }

        // se response è uguale a s elimino altrimenti no
        if (response == "s")
        {
            if (!send_message(session, delete_file(file_to_delete)))
            {
                log_error("Failed to send message");
                return false;
            }
        }
        else
        {
            printf("File non eliminato\n");
            if (!send_message(session, "File non eliminato\n"))
            {
                log_error("Failed to send message");
                return false;
            }
        }
    }

    return true;
}

bool ListServer::execute(Session *session, std::string command)
{
    std::string path = "server_file/users/" + session->username;
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
    if (!send_message(session, ret))
    {
        log_error("Failed to send message");
        return false;
    }
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
        if (!send_message(session, "Il comando richiede esattamente 2 parametri, nome del file da rinominare e nuovo nome del file, riprova\n"))
        {
            log_error("Failed to send message");
            return false;
        }
        return true;
    }

    std::string old_name = "server_file/users/" + session->username + "/" + tokens[1];
    std::string new_name = "server_file/users/" + session->username + "/" + tokens[2];

    printf("old_name: %s\n", old_name.c_str());
    printf("new_name: %s\n", new_name.c_str());

    if (!send_message(session, rename_file(old_name, new_name)))
    {
        log_error("Failed to send message");
        return false;
    }

    return true;
}

bool LogoutServer::execute(Session *session, std::string command)
{
    return false;
}