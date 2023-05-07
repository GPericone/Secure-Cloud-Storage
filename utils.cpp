#include "utils.h"

void log_error(const std::string &msg)
{
    std::cerr << "Error: " << msg << std::endl;
}

/**
 * @brief Frees all allocated buffers in the given buffer array.
 *
 * This function iterates through the buffer array and frees all non-null buffers.
 * It also sets their entries in the array to nullptr. The function displays the
 * number of freed buffers upon completion.
 *
 * @param buffer_array Pointer to an array of unsigned char pointers, containing the buffers to be freed.
 */
void free_allocated_buffers(unsigned char *buffer_array[])
{
    int counter = 0;
    for (int i = 0; i < MAX_BUF_SIZE; i++)
    {
        if (buffer_array[i] != nullptr)
        {
            free(buffer_array[i]);
            buffer_array[i] = nullptr;
            counter++;
        }
    }
    std::cout << "Freed " << counter << " allocated buffers" << std::endl;
}

/**
 * @brief Allocates a new buffer of the specified size and stores it in the given buffer array.
 *
 * This function allocates a new buffer of the specified size, initializes it to zero, and stores
 * it in the given buffer array. The new buffer's pointer is returned via the new_buf_ptr parameter.
 * If the buffer array is full or memory allocation fails, the function frees all allocated buffers,
 * closes the specified socket, and terminates the program with an error message.
 *
 * @param buffer_array Pointer to an array of unsigned char pointers, where the new buffer will be stored.
 * @param socket       Socket to close if an error occurs during buffer allocation or storage.
 * @param new_size     Size of the new buffer to be allocated.
 * @param new_buf_ptr  Pointer to an unsigned char pointer, which will be set to the address of the new buffer.
 *
 * @return             Index of the new buffer in the buffer array, or -1 in case of errors.
 */
int allocate_and_store_buffer(unsigned char *buffer_array[], int socket, size_t new_size, unsigned char **new_buf_ptr)
{
    if (buffer_array == NULL)
    {
        std::cerr << "Error: Invalid buffer array" << std::endl
                  << "Exiting program" << std::endl;
        exit(EXIT_FAILURE);
    }

    unsigned char *new_buf = (unsigned char *)calloc(new_size + 1, sizeof(unsigned char));
    if (new_buf == NULL)
    {
        free_allocated_buffers(buffer_array);
        if (socket != 0)
        {
            close(socket);
        }
        std::cerr << "Error: Failed to allocate " << new_size << " bytes" << std::endl
                  << "Exiting program" << std::endl;
        exit(EXIT_FAILURE);
    }

    // Check if buffer_array has room for a new buffer
    int i;
    for (i = 0; i < MAX_BUF_SIZE; i++)
    {
        if (buffer_array[i] == NULL)
        {
            break;
        }
    }

    if (i == MAX_BUF_SIZE)
    {
        // buffer_array is full
        std::cerr << "Error: Buffer array is full" << std::endl
                  << "Exiting program" << std::endl;
        // free_allocated_buffers(cl_free_buf);
        // free_allocated_buffers(sv_free_buf);
        exit(EXIT_FAILURE);
    }

    buffer_array[i] = new_buf;
    *new_buf_ptr = new_buf;
    return i;
}

void serialize_int(int input, unsigned char *output)
{
    unsigned char *p = reinterpret_cast<unsigned char *>(&input);
    std::copy(p, p + sizeof(int), output);
}

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

bool isRegistered(std::string_view username)
{
    std::string line;
    std::string word;

    std::fstream file(F_NAME, std::ios::in);

    if (!file.is_open())
    {
        log_error("Could not open the file\n");
        return false;
    }

    while (getline(file, line))
    {
        std::stringstream str(line);

        while (getline(str, word, ' '))
        {
            if (word.compare(username) == 0)
            {
                return true;
            }
        }
    }

    return false;
}

int safe_size_t_to_int(size_t value)
{
    if (value > static_cast<size_t>(std::numeric_limits<int>::max()))
    {
        throw std::runtime_error("Conversion error: size_t value is too large for int");
    }

    return static_cast<int>(value);
}

template<typename T>
void deleteBuffers(T* buffer) {
    delete[] buffer;
}

template<typename T, typename... Ts>
void deleteBuffers(T* buffer, Ts*... buffers) {
    delete[] buffer;
    deleteBuffers(buffers...);
}
