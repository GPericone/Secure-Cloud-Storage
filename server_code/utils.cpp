#include "utils.h"

/**
 * @brief Print an error message on the standard error output
 * 
 * @param msg The message to print
 */
void log_error(const std::string &msg)
{
    std::cerr << "Error: " << msg << std::endl;
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
        log_error("Buffer size is too small to store the value");
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
        throw std::runtime_error("Conversion error: int value is negative");
    }

    return static_cast<size_t>(value);
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
            log_error("Failed to receive data from the socket");
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
        log_error("Could not open the file");
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
 * @brief This function convert a size_t value to a int value in a safe way
 *
 * @param value the size_t value to convert
 * @return int the converted value
 */
int size_t_to_int(size_t value)
{
    if (value > static_cast<size_t>(std::numeric_limits<int>::max()))
    {
        log_error("Conversion error: size_t value is too big");
        return -1;
    }

    return static_cast<int>(value);
}

template <typename T>
void deleteBuffers(T *buffer)
{
    delete[] buffer;
}

template <typename T, typename... Ts>
void deleteBuffers(T *buffer, Ts *...buffers)
{
    delete[] buffer;
    deleteBuffers(buffers...);
}

/**
 * @brief Get the size of the file as a double
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

bool send_file(Session *session, std::string const &file_path)
{
    std::ifstream input_file(file_path, std::ios::binary);
    if (!input_file)
    {
        log_error("Error opening file " + file_path);
        return false;
    }

    input_file.seekg(0, std::ios::beg);

    // Read the file in chunks of 1 MB at a time and send each chunk
    std::string buffer;

    auto file_size = get_double_file_size(file_path);
    int num_sends = static_cast<int>((file_size + CHUNK_SIZE - 1) / CHUNK_SIZE);
    for (int i = 0; i < num_sends; ++i)
    {
        int not_last_message = 1;
        auto bytes_to_read = CHUNK_SIZE;
        if (i == num_sends - 1)
        {
            bytes_to_read = static_cast<int>(file_size - i * CHUNK_SIZE);
            not_last_message = 0;
        }
        buffer.resize(bytes_to_read);
        input_file.read(&buffer[0], bytes_to_read);

        if (!send_message(session, std::string(buffer.begin(), buffer.end()), true, not_last_message))
        {
            log_error("Error during the sending of the file " + file_path);
            input_file.close();
            return false;
        }
        buffer.clear();
    }

    input_file.close();

    unsigned int not_last_message;
    std::string response;
    if (!receive_message(session, &response, true, &not_last_message))
    {
        log_error("Error during the reception of the not_last_message of the file " + file_path);
        return false;
    }
    if (not_last_message == 0)
    {
        log_error("Error during the download of the file " + file_path);
        return false;
    }
    else
    {
        std::cout << "File downloaded: " << file_path << std::endl;
        return true;
    }
}

/**
 * @brief Get the file size in bytes
 * 
 * @param path the path of the file
 * @return std::string the size of the file
 */
std::string get_file_size_no_ext(const std::string &path)
{
    auto mantissa = get_double_file_size(path);
    std::stringstream stream;
    stream << std::fixed << std::setprecision(2) << mantissa;
    return stream.str();
}

/**
 * @brief Get the file size in human readable format
 * 
 * @param path the path of the file
 * @return std::string the size of the file
 */
std::string get_file_size(std::string const &path)
{
    auto mantissa = get_double_file_size(path);
    int i = 0;
    for (; mantissa >= 1024.0; mantissa /= 1024.0, ++i)
    {
        // We are just looking for the mantissa, no operation required
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
 * @param send_not_last_message if true, the not_last_message flag is sent
 * @param not_last_message notify if the message is not the last one to send
 * @return true if the message is sent successfully, false otherwise
 */
bool send_message(Session *session, const std::string payload, bool send_not_last_message, unsigned int not_last_message)
{
    int aad_len = sizeof(int) + ((send_not_last_message) ? sizeof(int) : 0);
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
    if (send_not_last_message)
    {
        unsigned char *not_last_message_byte = new unsigned char[sizeof(int)];
        serialize_int(not_last_message, not_last_message_byte);
        memcpy(aad + sizeof(int), not_last_message_byte, sizeof(int));
        delete_buffers(not_last_message_byte);
    }
    memcpy(plaintext, payload.c_str(), payload.size());

    // Generate a random IV
    if (!RAND_bytes(iv, IV_LEN))
    {
        log_error("Error generating IV");
        delete_buffers(plaintext, aad, iv, tag, ciphertext, command_len_byte, counter_byte);
        return false;
    }

    // Encrypt the message using AES-GCM
    int ciphertext_len = aesgcm_encrypt(plaintext, size_t_to_int(payload.size()), aad, aad_len, session->aes_key, iv, ciphertext, tag);
    if (ciphertext_len < 0)
    {
        log_error("Error encrypting message");
        delete_buffers(plaintext, aad, iv, tag, ciphertext, command_len_byte, counter_byte);
        return false;
    }

    int message_size = sizeof(long int) + aad_len + ciphertext_len + TAG_LEN + IV_LEN;

    unsigned char *message = new unsigned char[message_size];
    // message: payload_len | counter | not_last_message* | payload | tag | iv
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
        std::cout << "The server counter has reached the maximum allowed value" << std::endl;
        return false;
    }

    // Update the session counter
    session->server_counter++;

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
 * @param receive_not_last_message if true, the not_last_message flag is received
 * @param not_last_message notify if the message is not the last one to receive
 * @return true if the message is received successfully, false otherwise
 */
bool receive_message(Session *session, std::string *payload, bool receive_not_last_message, unsigned int *not_last_message)
{
    // Read the payload length from the socket
    long int message_len;
    unsigned char *message_len_byte = new unsigned char[sizeof(long int)];
    if (!recv_all(session->socket, (void *)message_len_byte, sizeof(long int)))
    {
        log_error("Failed to read payload length");
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

    unsigned char *not_last_message_byte = new unsigned char[sizeof(int)];
    if (receive_not_last_message)
    {
        if (!recv_all(session->socket, (void *)not_last_message_byte, sizeof(int)))
        {
            log_error("Failed to read not_last_message");
            delete_buffers(message_len_byte, counter_byte, ciphertext, plaintext, not_last_message_byte);
            return false;
        }
        memcpy(not_last_message, not_last_message_byte, sizeof(int));
    }

    unsigned int aad_len = sizeof(int) + ((receive_not_last_message) ? sizeof(int) : 0);
    unsigned char *aad = new unsigned char[aad_len];
    memcpy(aad, counter_byte, sizeof(int));
    if (receive_not_last_message)
    {
        memcpy(aad + sizeof(int), not_last_message_byte, sizeof(int));
        delete_buffers(not_last_message_byte);
    }
    // Allocate buffers for the tag
    unsigned char *tag = new unsigned char[TAG_LEN];

    // Receive the ciphertext
    if (!recv_all(session->socket, (void *)ciphertext, message_len))
    {
        log_error("Error receiving ciphertext");
        delete_buffers(message_len_byte, counter_byte, ciphertext, plaintext, aad, tag);
        return false;
    }

    // Receive the tag
    if (!recv_all(session->socket, (void *)tag, TAG_LEN))
    {
        log_error("Error receiving tag");
        delete_buffers(message_len_byte, counter_byte, ciphertext, plaintext, aad, tag);
        return false;
    }

    // Allocate buffers for the IV
    unsigned char *iv = new unsigned char[IV_LEN];

    // Receive the IV
    if (!recv_all(session->socket, (void *)iv, IV_LEN))
    {
        log_error("Error receiving IV");
        delete_buffers(message_len_byte, counter_byte, ciphertext, plaintext, aad, tag, iv);
        return false;
    }

    // Decrypt the message
    int plaintext_len = aesgcm_decrypt(ciphertext, message_len, aad, aad_len, tag, session->aes_key, iv, plaintext);
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

/**
 * @brief This function receives an upload request from the client, receives the file and saves it
 * 
 * @param session the server session
 * @param command the command to execute
 * @return true if the command is executed successfully, false otherwise
 */
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
        std::cerr << " The command received requires 1 parameter, file name to upload, try again" << std::endl;
        if (!send_message(session, "The command received requires 1 parameter, file name to upload, try again\n"))
        {
            log_error("Failed to send message");
            return false;
        }
        return true;
    }

    std::string file_size;
    unsigned int not_last_message = 0;
    if (!receive_message(session, &file_size, true, &not_last_message))
    {
        log_error("Failed to receive message");
        return false;
    }

    if (not_last_message == 0)
    {
        return true;
    }

    // Check if the file size is less than 4GB
    std::string not_last_message_string = "";
    int valid = 1;
    if (std::stoul(file_size) > UINT32_MAX)
    {
        not_last_message_string = "File dimension greater than 4GB, try again\n";
        valid = 0;
    }

    std::string file_to_upload = tokens[1];

    if (valid == 1)
    {
        std::ofstream output_file("server_file/users/" + session->username + "/" + file_to_upload, std::ios::binary);
        if (!std::regex_match(file_to_upload, pattern))
        {
            log_error("Filename not valid " + file_to_upload);
            not_last_message_string = "Filename not valid ";
            valid = 0;
        }
        else if (!output_file)
        {
            log_error("Error during file creation " + file_to_upload);
            not_last_message_string += "Error during file creation ";
            valid = 0;
        }

        if (!send_message(session, not_last_message_string, true, valid))
        {
            log_error("Failed to send message");
            return false;
        }
        if (valid == 0)
        {
            std::cout << std::endl;
            return true;
        }
        bool is_last = false;
        while (!is_last)
        {
            std::string buffer;
            unsigned int not_last_message_receive;
            if (!receive_message(session, &buffer, true, &not_last_message_receive))
            {
                log_error("Error during file reception " + file_to_upload);
                break;
            }
            is_last = not_last_message_receive == 0;
            output_file << buffer;
        }

        // Read the file in blocks of 1 MB at a time and write each block

        output_file.close();
    }
    else
    {
        if (!send_message(session, not_last_message_string, true, valid))
        {
            log_error("Failed to send message");
            return false;
        }
        std::cout << std::endl;
        return true;
    }

    if (!send_message(session, "File downloaded successfully\n", true, 1))
    {
        log_error("Failed to send message");
        return false;
    }
    return true;
}

/**
 * @brief the function checks if the file is available to download
 * 
 * @param path the path of the file
 * @param response indicates if the file is available to download and that the file size is less than 4 GB
 * @return true if the file is available to download, false otherwise
 */
bool check_availability_to_download(std::string const &path, std::string *response)
{

    // Check file size
    std::ifstream input_file(path, std::ios::binary);
    if (input_file.fail())
    {
        *response = "Error: file does not exists.";
        return false;
    }
    if (!input_file.is_open())
    {
        *response = "Error: impossible to open file";
        return false;
    }
    input_file.seekg(0, std::ios::end);
    std::streampos file_size = input_file.tellg();
    input_file.seekg(0, std::ios::beg);
    if (file_size > UINT32_MAX)
    {
        *response = "Error: file is bigger than 4 GB.";
        return false;
    }
    *response = "The file exists, it has a size of " + get_file_size(path) + " are you sure you want to download it? (y/n)";
    return true;
}

/**
 * @brief This function receives a download request from the client and sends the file to the client
 * 
 * @param session the server session
 * @param command the command to execute
 * @return true if the command is executed successfully, false otherwise
 */
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
        log_error("The command received requires 1 parameter, file name to download, try again");
        if (!send_message(session, "The command received requires 1 parameter, file name to download, try again\n"))
        {
            log_error("Failed to send message");
            return false;
        }
        return true;
    }

    std::string file_to_download = "server_file/users/" + session->username + "/" + tokens[1];

    std::cout << "file_to_download: " << file_to_download.c_str() << std::endl;

    std::string response_existance = "File name does not match requirements, try again\n";
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
        if (response == "y")
        {
            if (!send_file(session, file_to_download.c_str()))
            {
                log_error("Failed to send file");
                return false;
            }
        }
        else
        {
            std::cout << "File not downloaded" << std::endl;
            return true;
        }
    }
    return true;
}

/**
 * @brief This function checks if the file exists
 * 
 * @param path the path of the file
 * @param response the response to send to the client
 * @return true if the file exists, false otherwise
 */
bool check_file_existance(std::string const &path, std::string *response)
{
    std::ifstream input_file(path, std::ios::binary);
    if (!input_file.is_open())
    {
        *response = "File does not exists\n";
        return false;
    }
    else
    {
        *response = "File exists, are you sure you want to delete it? (/n)\n";
        return true;
    }
}

/**
 * @brief This function deletes a file
 * 
 * @param path the path of the file
 * @return std::string the response to send to the client
 */
std::string delete_file(std::string const &path)
{
    if (std::remove(path.c_str()) == 0)
    {
        return "File deleted correctly\n";
    }
    return "File not found\n";
}

/**
 * @brief This function receives a delete request from the client and deletes the file
 * 
 * @param session the server session
 * @param command the command to execute
 * @return true if the command is executed successfully, false otherwise
 */
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
        log_error("The command received requires 1 parameter, file name to delete, try again");
        if (!send_message(session, "The command received requires 1 parameter, file name to delete, try again\n"))
        {
            log_error("Failed to send message");
            return false;
        }
        return true;
    }

    std::string file_to_delete = "server_file/users/" + session->username + "/" + tokens[1];

    std::string response_existance = "File name does not match requirements, try again\n";
    bool exists = std::regex_match(tokens[1], pattern) && check_file_existance(file_to_delete, &response_existance);
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

        if (response == "")
        {
            if (!send_message(session, delete_file(file_to_delete)))
            {
                log_error("Failed to send message");
                return false;
            }
        }
        else
        {
            log_error("File not deleted");
            if (!send_message(session, "File not deleted\n"))
            {
                log_error("Failed to send message");
                return false;
            }
        }
    }

    return true;
}

/**
 * @brief This function sends the list of files available on the server
 * 
 * @param session the server session
 * @param command the command to execute
 * @return true if the command is executed successfully, false otherwise
 */
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
    auto ret = std::string("Files available on the server:\n");

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

/**
 * @brief This function renames a file
 * 
 * @param old_file_name the old file name
 * @param new_file_nam the new file name
 * @return std::string the response to send to the client
 */
std::string rename_file(std::string const &old_file_name, std::string const &new_file_name)
{
    // check esistenza file con nome oldFilePath
    if (old_file_name.empty() || new_file_name.empty())
    {
        return "Invalid file name";
    }

    if (!std::ifstream(old_file_name))
    {
        return "File to rename does not exist";
    }

    // check esistenza file con nome newFilePath
    if (std::ifstream(new_file_name))
    {
        return "New file name already exists";
    }

    if (rename(old_file_name.c_str(), new_file_name.c_str()) == 0)
    {
        return "File renamed correctly";
    }
    return "Error renaming file";
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
        log_error("The command requires exactly 2 parameters, file name to rename and new file name, try again");
        if (!send_message(session, "The command requires exactly 2 parameters, file name to rename and new file name, try again\n"))
        {
            log_error("Failed to send message");
            return false;
        }
        return true;
    }
    std::string response = "Errore nel rinominare il file";

    std::string old_name = "server_file/users/" + session->username + "/" + tokens[1];
    std::string new_name = "server_file/users/" + session->username + "/" + tokens[2];

    if (!std::regex_match(tokens[1], pattern) || !std::regex_match(tokens[1], pattern))
    {
        response = "Filename not valid";
    }
    else
    {
        response = rename_file(old_name, new_name);
    }

    if (!send_message(session, response))
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