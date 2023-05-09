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
template<typename T>
void deleteBuffers(T* buffer) {
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
template<typename T, typename... Ts>
void deleteBuffers(T* buffer, Ts*... buffers) {
    delete[] buffer;
    deleteBuffers(buffers...);
}
