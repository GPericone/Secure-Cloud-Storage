#include "utils.h"

void log_error(const std::string &msg)
{
    std::cerr << "Error: " << msg << std::endl;
}

void serialize_int(int input, unsigned char *output)
{
    unsigned char *p = reinterpret_cast<unsigned char *>(&input);
    std::copy(p, p + sizeof(int), output);
}

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

bool deserialize_longint(const unsigned char *buffer, long int *result)
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

size_t int_to_size_t(int value)
{
    if (value < 0)
    {
        throw std::runtime_error("Conversion error: int value is negative");
    }

    return static_cast<size_t>(value);
}

bool recv_all(int socket, void *buffer, ssize_t len)
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

int size_t_to_int(size_t value)
{
    if (value > static_cast<size_t>(std::numeric_limits<int>::max()))
    {
        throw std::runtime_error("Conversion error: size_t value is too large for int");
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
        log_error("Errore durante l'apertura del file " + file_path);
        return false;
    }

    input_file.seekg(0, std::ios::beg);

    // Leggi il file a blocchi di 1 MB alla volta e invia ogni blocco
    std::string buffer;

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

        if (!send_message(session, std::string(buffer.begin(), buffer.end()), true, esito)) // inviare il flag finale solo per l'ultimo chunk
        {
            log_error("Errore durante l'invio del file " + file_path);
            input_file.close();
            return false;
        }
        // pulisco il buffer;
        buffer.clear();
    }

    input_file.close();

    unsigned int esito;
    std::string response;
    if (!receive_message(session, &response, true, &esito))
    {
        log_error("Errore durante la ricezione dell'esito del download del file " + file_path);
        return false;
    }
    if (esito == 0)
    {
        log_error("Errore durante il download del file " + file_path);
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

bool send_message(Session *session, const std::string payload, bool send_esito, unsigned int esito)
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
        std::cout << "Il contatore del server ha raggiunto il massimo valore consentito" << std::endl;
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

bool receive_message(Session *session, std::string *payload, bool receive_esito, unsigned int *esito)
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

    unsigned char *esito_byte = new unsigned char[sizeof(int)];
    if (receive_esito)
    {
        if (!recv_all(session->socket, (void *)esito_byte, sizeof(int)))
        {
            log_error("Failed to read esito");
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
        std::cout << "Il comando richiede 1 parametro, nome del file da scaricare, riprova" << std::endl;
        if (!send_message(session, "Il comando richiede 1 parametro, nome del file da scaricare, riprova"))
        {
            log_error("Failed to send message");
            return false;
        }
        return true;
    }

    std::string file_size;
    unsigned int esito = 0;
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
        if (!std::regex_match(file_to_upload, pattern))
        {
            log_error("Nome file non valido " + file_to_upload);
            esito_string = "Nome file non valido " + file_to_upload + "\n";
            valido = 0;
        }
        else if (!output_file)
        {
            log_error("Errore durante la creazione del file " + file_to_upload);
            esito_string = "Errore durante la creazione del file " + file_to_upload + "";
            valido = 0;
        }

        if (!send_message(session, esito_string, true, valido))
        {
            log_error("Failed to send message");
            return false;
        }
        if (valido == 0)
        {
            std::cout << std::endl;
            return true;
        }
        bool is_last = false;
        while (!is_last)
        {
            std::string buffer;
            unsigned int esito_receive;
            if (!receive_message(session, &buffer, true, &esito_receive))
            {
                log_error("Errore durante la ricezione del file " + file_to_upload);
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
        std::cout << std::endl;
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
        *response = "Errore: il file " + path + " supera i 4 GB di dimensione.";
        return false;
    }
    *response = "Il file esiste, ha una dimensione di " + get_file_size(path) + " sei sicuro di voler effettuare il download? (s/n)";
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

        // se response è uguale a s elimino altrimenti no
        if (response == "s")
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
        *response = "File exists, are you sure you want to delete it? (s/n)\n";
        return true;
    }
}

std::string delete_file(std::string const &path)
{
    if (std::remove(path.c_str()) == 0)
    {
        return "File deleted correctly\n";
    }
    return "File not found\n";
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
            std::cout << "File non eliminato" << std::endl;
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
    //     std::cout << "* %s", buf);
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
        std::cout << "Il comando richiede esattamente 2 parametri, nome del file da rinominare e nuovo nome del file, riprova" << std::endl;
        if (!send_message(session, "Il comando richiede esattamente 2 parametri, nome del file da rinominare e nuovo nome del file, riprova\n"))
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
        response = "Nome file non valido";
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