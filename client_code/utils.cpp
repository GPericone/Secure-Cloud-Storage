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

    for (int i = 0; i < sizeof(long int); i++)
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
    // int file_size = get_file_size_no_ext(file_path);
    auto file_size = (double)std::filesystem::file_size(file_path);
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
        input_file.read(buffer.data(), bytes_to_read);
        if (!send_message(session, buffer, true, esito)) // inviare il flag finale solo per l'ultimo chunk
        {
            std::cerr << "Errore durante l'invio del file " << file_path << std::endl;
            buffer.clear();
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
    serialize_int(session->client_counter, counter_byte);

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

    // Update the session counter
    session->client_counter++;

    // Clean up and return
    delete_buffers(plaintext, aad, iv, tag, ciphertext, command_len_byte, counter_byte, message);
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
        if (!send_message(session, "Il comando richiede 1 parametro, nome del file da caricare, riprova\n"))
        {
            log_error("Error sending message");
            return false;
        }
        return true;
    }

    std::string file_to_upload = "client_file/users/" + session->username + "/" + tokens[1];

    printf("file_to_upload: %s\n", file_to_upload.c_str());

    std::string response_existance;
    bool check_file = check_availability_to_upload(file_to_upload, &response_existance);
    if (!send_message(session, response_existance, true, check_file))
    {
        log_error("Error sending message");
        return false;
    }

    if (check_file)
    {
        std::string response;
        int success;
        if (!receive_message(session, &response, true, &success))
        {
            log_error("Error receiving message");
            return false;
        }

        if (success == 1)
        {
            // TODO: divido il file in chunk di 1 MB e li invio
            if (!send_file(session, file_to_upload.c_str())) {
                log_error("Error sending file");
                return false;
            }
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
        if (!send_message(session, "Il comando richiede 1 parametro, nome del file da scaricare, riprova\n"))
        {
            log_error("Error sending message");
            return false;
        }
        return true;
    }

    std::string response_existance;
    int exists;
    if (!receive_message(session, &response_existance, true, &exists))
    {
        log_error("Error receiving message");
        return false;
    }

    std::cout << response_existance;

    std::string file_to_download = "client_file/users/" + session->username + "/" + tokens[1];

    if (exists == 1)
    {
        // ricevo da tastiera s o n
        std::string esito;
        std::cin >> esito;

        std::string response;
        if (!send_message(session, esito))
        {
            log_error("Error sending message");
            return false;
        }

        std::ofstream output_file(file_to_download, std::ios::binary);
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

    if (!send_message(session, "File scaricato correttamente\n", true, 1))
    {
        log_error("Error sending message");
        return false;
    }
    return true;
}

bool DeleteClient::execute(Session *session, std::string command)
{
    std::string response_existance;
    int exists;
    if (!receive_message(session, &response_existance, true, &exists))
    {
        log_error("Error receiving message");
        return false;
    }

    std::cout << response_existance;

    if (exists == 1)
    {
        // ricevo da tastiera s o n
        std::string esito;
        std::cin >> esito;

        std::string response;
        if (!send_message(session, esito))
        {
            log_error("Error sending message");
            return false;
        }

        std::string response_delete;
        if (!receive_message(session, &response_delete))
        {
            log_error("Error receiving message");
            return false;
        }

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
    int counter;
    unsigned char *counter_byte = new unsigned char[sizeof(int)];
    if ((recv_all(session->socket, (void *)counter_byte, sizeof(int))) != sizeof(int))
    {
        log_error("Failed to read counter");
        delete_buffers(message_len_byte, counter_byte, ciphertext, plaintext);
        return false;
    }
    memcpy(&counter, counter_byte, sizeof(int));

    // TODO : aggiungere due counter, sistemare controllo
    if (counter != session->server_counter)
    {
        log_error("Counter mismatch");
        delete_buffers(message_len_byte, counter_byte, ciphertext, plaintext);
        return false;
    }

    session->server_counter++;

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