#include "utils.h"

// We use this global variable to enable/disable debug messages
bool DEBUG_MODE = false;

/**
 * @brief This function is used to print debug and error messages
 *
 * @param msg the message to print
 * @param debug if true, the message is printed only if the global variable DEBUG_MODE is true
 */
void log_error(const std::string &msg, bool debug)
{
    // If the global variable DEBUG_MODE is true and the debug parameter is true, or if debug is false, print the error message
    if ((DEBUG_MODE && debug) || !debug)
    {
        std::cerr << "Error: " << msg << std::endl;
    }
}

/**
 * @brief This function serialize an int value into a buffer of unsigned char
 *
 * @param input the int value to serialize
 * @param output the buffer where the serialized value will be stored
 */
void serialize_int(int input, unsigned char *output)
{
    unsigned char *p = reinterpret_cast<unsigned char *>(&input);
    std::copy(p, p + sizeof(int), output);
}

/**
 * @brief This function serialize a long int value into a buffer of unsigned char
 *
 * @param value the long int value to serialize
 * @param buffer the buffer where the serialized value will be stored
 * @param buffer_size the size of the buffer
 */
void serialize_longint(long int value, unsigned char *buffer, size_t buffer_size)
{
    if (buffer_size >= sizeof(long int))
    {
        std::memcpy(buffer, &value, sizeof(long int));
    }
    else
    {
        log_error("Buffer size is too small!", true);
        exit(1);
    }
}

/**
 * @brief This function deserialize a buffer of unsigned char into an long int value
 *
 * @param buffer the buffer to deserialize
 * @param result the long int value where the deserialized value will be stored
 * @return true if the deserialization is successful, false otherwise
 */
bool deserialize_longint(const unsigned char *buffer, long int *result)
{
    if (buffer == nullptr || result == nullptr)
    {
        return false;
    }
    *result = 0;
    for (long unsigned int i = 0; i < sizeof(long int); i++)
    {
        if (buffer[i] == '\0')
        {
            break;
        }
        *result |= static_cast<long int>(buffer[i]) << (8 * i);
    }
    return true;
}

/**
 * @brief This function convert a int value to a size_t value in a safe way
 * 
 * @param value the int value to convert
 * @return size_t the converted value
 */
size_t int_to_size_t(int value)
{
    if (value < 0)
    {
        log_error("Error: negative value during conversion to size_t!", true);
        exit(1);
    }

    return static_cast<size_t>(value);
}

/**
 * @brief This function convert a size_t value to a int value in a safe way
 * 
 * @param value the size_t value to convert
 * @return int the converted value
 */
int size_t_to_int(size_t value)
{
    if (value > static_cast<size_t>(std::numeric_limits<int>::max()))
    {
        log_error("Error: size_t value is too large for int", true);
        exit(1);
    }

    return static_cast<int>(value);
}

/**
 * @brief This function convert a size_t value to a int value in a safe way
 * 
 * @param value the size_t value to convert
 * @return int the converted value
 */
int size_t_to_int(size_t value)
{
    if (value > static_cast<size_t>(std::numeric_limits<int>::max()))
    {
        log_error("Error: size_t value is too large for int", true);
        exit(1);
    }

    return static_cast<int>(value);
}

/**
 * @brief This function convert a long int value to a int value in a safe way
 * 
 * @param value the long int value to convert
 * @return int the converted value
 */
int longint_to_int(long int value) {
    if (value < std::numeric_limits<int>::min() || value > std::numeric_limits<int>::max()) {
        log_error("Error: long int value is too large for int", true);
        exit(1);
    }
    
    return static_cast<int>(value);
}

/**
 * @brief This function receive a message from a socket and store in a buffer.
 * Differently from recv function, this continue to receive data until all requested bytes have been read or an error occurs.
 * 
 * @param socket the socket to read from
 * @param buffer the buffer where the message will be stored
 * @param len the length of the message to receive
 * @return true if the message is received successfully, false otherwise
 */
bool recv_all(int socket, void *buffer, ssize_t len)
{
    // The number of bytes remaining to be received
    ssize_t bytes_left = len;     
    // The number of bytes read in the current iteration                  
    ssize_t bytes_read;
    // A pointer to the current position in the buffer                            
    char *buffer_ptr = static_cast<char *>(buffer);

    // Continue to receive data until all requested bytes have been read or an error occurs
    while (bytes_left > 0)
    {
        bytes_read = recv(socket, static_cast<void *>(buffer_ptr), bytes_left, 0);

        if (bytes_read < 0)
        {
            log_error("Failed to receive data from the socket", true);
            return false;
        }

        if (bytes_read == 0)
        {
            break;
        }

        bytes_left -= bytes_read;
        buffer_ptr += bytes_read;
    }
    return ((len - bytes_left) == len);
}

/**
 * @brief This function delete a buffer of any type
 * 
 * @tparam T the type of the buffer
 * @param buffer the buffer to delete
 */
template <typename T>
void deleteBuffers(T *buffer)
{
    delete[] buffer;
}

/**
 * @brief This function delete a buffer of any type with variadic template
 * 
 * @tparam T the type of the buffer
 * @tparam Ts the types of the other buffers
 * @param buffer the buffer to delete
 * @param buffers the other buffers to delete
 */
template <typename T, typename... Ts>
void deleteBuffers(T *buffer, Ts *...buffers)
{
    delete[] buffer;
    deleteBuffers(buffers...);
}

/**
 * @brief Get the size of a file as double value
 * 
 * @param path the path of the file
 * @return double the size of the file
 */
double get_double_file_size(std::string const &path)
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        return 0.0;
    }

    std::streampos fileSize = file.tellg();
    file.close();

    return static_cast<double>(fileSize);
}

/**
 * @brief This function send a file to a socket
 * 
 * @param session the session to use
 * @param file_path the path of the file to send
 * @return true if the file is sent successfully, false otherwise
 */
bool send_file(Session *session, std::string const &file_path)
{
    // Open the file to send in binary mode
    std::ifstream input_file(file_path, std::ios::binary);
    if (!input_file)
    {
        log_error("Failed to open the file to send", true);
        return false;
    }

    // Set the pointer to the beginning of the file
    input_file.seekg(0, std::ios::beg);

    // Read the file in chunks of 1 MB and send each chunk
    std::string buffer;
    auto file_size = get_double_file_size(file_path);
    // Compute the number of chunks to send
    int num_sends = static_cast<int>((file_size + CHUNK_SIZE - 1) / CHUNK_SIZE);
    for (int i = 0; i < num_sends; ++i)
    {
        // We use a flag to indicate if the current chunk is the last one
        int esito = 1;
        auto bytes_to_read = CHUNK_SIZE;
        // If the current chunk is the last one, we need to read only the remaining bytes
        if (i == num_sends - 1)
        {
            bytes_to_read = static_cast<int>(file_size - i * CHUNK_SIZE);
            esito = 0;
        }
        // Resize the buffer to the number of bytes to read
        buffer.resize(bytes_to_read);
        // Read the chunk from the file
        input_file.read(&buffer[0], bytes_to_read);

        // Send the chunk
        if (!send_message(session, std::string(buffer.begin(), buffer.end()), true, esito))
        {
            std::cerr << "Error during the sending of the file " << file_path << std::endl;
            input_file.close();
            return false;
        }
        // Clear the buffer
        buffer.clear();
    }

    // Close the file
    input_file.close();

    unsigned int esito;
    std::string response;
    // Receive the response from the server
    if (!receive_message(session, &response, true, &esito))
    {
        std::cerr << "Error during the reception of the result of the download of the file " << file_path << std::endl;
        return false;
    }
    if (esito == 0)
    {
        std::cerr << "Error during the download of the file " << file_path << std::endl;
        return false;
    }
    else
    {
        std::cout << "Download of the file " << file_path << " completed" << std::endl;
        return true;
    }
}

std::string get_file_size_no_ext(const std::string &path)
{
    auto mantissa = get_double_file_size(path);
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

/**
 * @brief This function send a message
 * 
 * @param session the session to use
 * @param payload the payload of the message
 * @return true if the message is sent successfully, false otherwise
 */
bool send_message(Session *session, const std::string payload)
{
    return send_message(session, payload, false, 0);
}

/**
 * @brief This function send a message
 * 
 * @param session the session to use
 * @param payload the payload of the message
 * @param send_esito 
 * @param esito 
 * @return true if the message is sent successfully, false otherwise
 */ 
bool send_message(Session *session, const std::string payload, bool send_esito, unsigned int esito)
{
    // The size of AAD depends if we need to send the esito or not
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

    // Create the AAD
    memcpy(aad, counter_byte, sizeof(int));
    if (send_esito)
    {
        unsigned char *esito_byte = new unsigned char[sizeof(int)];
        serialize_int(esito, esito_byte);
        memcpy(aad + sizeof(int), esito_byte, sizeof(int));
        delete_buffers(esito_byte);
    }
    // Copy the payload in the plaintext buffer
    memcpy(plaintext, payload.c_str(), payload.size());

    // Generate a random IV
    if (!RAND_bytes(iv, IV_LEN))
    {
        log_error("Error generating IV", true);
        delete_buffers(plaintext, aad, iv, tag, ciphertext, command_len_byte, counter_byte);
        return false;
    }

    // Encrypt the message using AES-GCM
    int ciphertext_len = aesgcm_encrypt(plaintext, size_t_to_int(payload.size()), aad, aad_len, session->aes_key, iv, ciphertext, tag);
    if (ciphertext_len < 0)
    {
        log_error("Error encrypting message", true);
        delete_buffers(plaintext, aad, iv, tag, ciphertext, command_len_byte, counter_byte);
        return false;
    }

    // Compute the size of the message
    unsigned int message_size = sizeof(long int) + aad_len + ciphertext_len + TAG_LEN + IV_LEN;

    unsigned char *message = new unsigned char[message_size];
    // MESSAGE: payload_len | counter | esito* | payload | tag | iv
    memcpy(message, command_len_byte, sizeof(int));
    memcpy(message + sizeof(long int), aad, aad_len);
    memcpy(message + sizeof(long int) + aad_len, ciphertext, ciphertext_len);
    memcpy(message + sizeof(long int) + aad_len + ciphertext_len, tag, TAG_LEN);
    memcpy(message + sizeof(long int) + aad_len + ciphertext_len + TAG_LEN, iv, IV_LEN);

    // Send the message
    if (send(session->socket, message, message_size, 0) < 0)
    {
        log_error("Error sending message", true);
        delete_buffers(plaintext, aad, iv, tag, ciphertext, command_len_byte, counter_byte, message);
        return false;
    }

    // Update the session counter
    session->client_counter++;

    // Clean up and return
    delete_buffers(plaintext, aad, iv, tag, ciphertext, command_len_byte, counter_byte, message);
    return true;
}

/**
 * @brief This function receive a message
 * 
 * @param session the session to use
 * @param payload the payload of the message
 * @return true if the message is received successfully, false otherwise
 */
bool receive_message(Session *session, std::string *payload)
{
    return receive_message(session, payload, false, nullptr);
}

/**
 * @brief This function receive a message
 * 
 * @param session the session to use
 * @param payload the payload of the message
 * @param receive_esito 
 * @param esito 
 * @return true if the message is received successfully, false otherwise
 */
bool receive_message(Session *session, std::string *payload, bool receive_esito, unsigned int *esito)
{
    // Read the payload length from the socket
    long int message_len;
    unsigned char *message_len_byte = new unsigned char[sizeof(long int)];
    if (!recv_all(session->socket, (void *)message_len_byte, sizeof(long int)))
    {
        log_error("Failed to read payload length", true);
        delete_buffers(message_len_byte);
        return false;
    }
    deserialize_longint(message_len_byte, &message_len);

    // Allocate buffers for the ciphertext and plaintext
    unsigned char *ciphertext = new unsigned char[message_len];
    unsigned char *plaintext = new unsigned char[message_len];

    // Read the counter from the socket
    unsigned int counter;
    unsigned char *counter_byte = new unsigned char[sizeof(int)];
    if (!recv_all(session->socket, (void *)counter_byte, sizeof(int)))
    {
        log_error("Failed to read counter", true);
        delete_buffers(message_len_byte, counter_byte, ciphertext, plaintext);
        return false;
    }
    memcpy(&counter, counter_byte, sizeof(int));

    // Check the counter
    if (counter != session->server_counter)
    {
        log_error("Counter mismatch", true);
        delete_buffers(message_len_byte, counter_byte, ciphertext, plaintext);
        return false;
    }

    session->server_counter++;

    unsigned char *esito_byte = new unsigned char[sizeof(int)];
    if (receive_esito)
    {
        if (!recv_all(session->socket, (void *)esito_byte, sizeof(int)))
        {
            log_error("Failed to read esito", true);
            delete_buffers(message_len_byte, counter_byte, ciphertext, plaintext, esito_byte);
            return false;
        }
        memcpy(esito, esito_byte, sizeof(int));
    }

    unsigned int aad_len = sizeof(int) + ((receive_esito) ? sizeof(int) : 0);
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
    if (!recv_all(session->socket, (void *)ciphertext, message_len))
    {
        log_error("Error receiving ciphertext", true);
        delete_buffers(message_len_byte, counter_byte, ciphertext, plaintext, aad, tag);
        return false;
    }

    // Receive the tag
    if (!recv_all(session->socket, (void *)tag, TAG_LEN))
    {
        log_error("Error receiving tag", true);
        delete_buffers(message_len_byte, counter_byte, ciphertext, plaintext, aad, tag);
        return false;
    }

    // Allocate buffers for the IV
    unsigned char *iv = new unsigned char[IV_LEN];

    // Receive the IV
    if (!recv_all(session->socket, (void *)iv, IV_LEN))
    {
        log_error("Error receiving IV", true);
        delete_buffers(message_len_byte, counter_byte, ciphertext, plaintext, aad, tag, iv);
        return false;
    }

    // Decrypt the message
    int plaintext_len = aesgcm_decrypt(ciphertext, longint_to_int(message_len), aad, aad_len, tag, session->aes_key, iv, plaintext);
    if (plaintext_len < 0)
    {
        log_error("Error decrypting message", true);
        delete_buffers(message_len_byte, counter_byte, ciphertext, plaintext, aad, tag, iv);
        return false;
    }

    *payload = std::string(reinterpret_cast<char *>(plaintext), message_len);
    delete_buffers(message_len_byte, counter_byte, ciphertext, plaintext, aad, tag, iv);
    return true;
}

bool check_availability_to_upload(std::string const &path, std::string *response)
{

    // Check file size
    std::ifstream input_file(path, std::ios::binary);
    // check file existance
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
        input_file.close();
        return false;
    }
    // response prende la dimensione del file
    input_file.close();
    *response = get_file_size_no_ext(path);
    return true;
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
        return true;
    }

    std::string file_to_upload = "client_file/users/" + session->username + "/" + tokens[1];

    std::string response_existance;
    bool check_file = check_availability_to_upload(file_to_upload, &response_existance);
    if (!send_message(session, response_existance, true, check_file))
    {
        log_error("Error sending message", false);
        return false;
    }

    if (check_file)
    {
        std::string response;
        unsigned int success;
        if (!receive_message(session, &response, true, &success))
        {
            log_error("Error receiving message", false);
            return false;
        }

        if (success == 1)
        {
            if (!send_file(session, file_to_upload.c_str()))
            {
                log_error("Error sending file", false);
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
        return true;
    }

    std::string response_existance;
    unsigned int exists;
    if (!receive_message(session, &response_existance, true, &exists))
    {
        log_error("Error receiving message", false);
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
            log_error("Error sending message", false);
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
            unsigned int esito_receive;
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
        log_error("Error sending message", false);
        return false;
    }
    return true;
}

bool DeleteClient::execute(Session *session, std::string command)
{
    std::string response_existance;
    unsigned int exists;
    if (!receive_message(session, &response_existance, true, &exists))
    {
        log_error("Error receiving message", false);
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
            log_error("Error sending message", false);
            return false;
        }

        std::string response_delete;
        if (!receive_message(session, &response_delete))
        {
            log_error("Error receiving message", false);
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
        log_error("Failed to receive message", false);
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
        log_error("Failed to receive message", false);
        return false;
    }
    printf("%s\n", response.c_str());
    return true;
}

bool LogoutClient::execute(Session *session, std::string command)
{
    return false;
}