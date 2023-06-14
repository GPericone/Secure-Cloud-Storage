#include "server.h"

// Queue of tasks
std::queue<int> task_queue;

// Condition variable for the task queue
std::condition_variable task_cv;

// Mutex for the synchronization of the task queue
std::mutex task_mutex;

// Number of threads in the threadpool
const int NUM_THREADS = 4;

/**
 * @brief handle_client manages the connection with the client.
 *
 * The function performs the handshake with the client and then manages the connection with the client.
 *
 * @param newSd the socket descriptor of the client
 * @param nonce_list the list of nonces
 */
void handle_client(int newSd, NonceList &nonce_list)
{
    std::unique_ptr<Session> session(new Session());
    session->socket = newSd;

    if (send_message0(session.get()) == false)
    {
        log_error("Error in receiving message 0");
        return;
    }

    if (receive_message1(session.get(), nonce_list) == false)
    {
        log_error("Error in receiving message 1");
        return;
    }

    // Load the server private key
    char abs_path[PATH_MAX];
    getcwd(abs_path, PATH_MAX);
    std::string path = std::string(abs_path) + "/server_file/keys/server_private_key.pem";
    EVP_PKEY *server_private_key = load_private_key(path.c_str());
    if (server_private_key == nullptr)
    {
        log_error("Error loading server private key");
        return;
    }

    if (send_message2(session.get(), server_private_key) == false)
    {
        log_error("Error in sending message 2");
        return;
    }

    if (receive_message3(session.get()) == false)
    {
        log_error("Error in receiving message 3");
        return;
    }

    std::cout << "Handshake completed for client " << session->username << std::endl;

    // Delete the ephemeral key
    EVP_PKEY_free(session->eph_key_pub);

    server_command_map["upload"].reset(new UploadServer());
    server_command_map["download"].reset(new DownloadServer());
    server_command_map["delete"].reset(new DeleteServer());
    server_command_map["list"].reset(new ListServer());
    server_command_map["rename"].reset(new RenameServer());
    server_command_map["logout"].reset(new LogoutServer());

    // Manage the connection with the client
    while (true)
    {
        std::string command; 
        // Read the message from the client
        if (receive_message(session.get(), &command) == false)
        {
            log_error("Error in receiving message");
            break;
        }

        printf("Comando ricevuto: %s\n", command.c_str());

        if (auto iter = server_command_map.find(command.substr(0, command.find(' '))); iter != server_command_map.end())
        {
            if (iter->second->execute(session.get(), command) == false)
            {
                break;
            }
        }
        else
        {
            printf("Comando non riconosciuto\n");
            break;
        }
    
    }
        session.reset();
        // Close the connection with the client
        close(newSd);
    }

/**
 * @brief thread_func is the function executed by each thread of the threadpool.
 *
 * The function waits for a task to be added to the task queue and then executes it.
 *
 * @param nonce_list the list of nonces
 */
void thread_func(NonceList &nonce_list)
{
    while (true)
    {
        // Acquire the lock on the task queue
        std::unique_lock<std::mutex> task_lock(task_mutex);

        // Wait until there is a task in the queue
        task_cv.wait(task_lock, []
                     { return !task_queue.empty(); });

        // Take the task from the queue
        int newSd = task_queue.front();
        task_queue.pop();

        // Release the lock on the task queue
        task_lock.unlock();

        // Manage the connection with the client
        handle_client(newSd, nonce_list);
    }
}

int main(int argc, char **argv)
{
    auto nonce_list = NonceList();

    if (argc == 1)
    {
        port = 4242;
    }
    else
        port = atoi(argv[1]);

    sd = socket(AF_INET, SOCK_STREAM, 0);
    std::cout << "Socket created correctly" << std::endl;
    if (sd < 0)
    {
        exit(1);
    }

    memset(&myAddr, 0, sizeof(myAddr));
    myAddr.sin_family = AF_INET;
    myAddr.sin_port = htons(port);
    myAddr.sin_addr.s_addr = INADDR_ANY;

    ret = bind(sd, (struct sockaddr *)&myAddr, sizeof(myAddr));
    if (ret < 0)
        exit(-1);

    ret = listen(sd, 10);
    if (ret < 0)
        exit(-1);

    std::vector<std::thread> threads;

    // Create the threadpool
    for (int i = 0; i < NUM_THREADS; i++)
    {
        threads.emplace_back(thread_func, std::ref(nonce_list));
    }

    while (true)
    {
        len = sizeof(clAddr);
        newSd = accept(sd, (struct sockaddr *)&clAddr, &len);
        if (newSd < 0)
        {
            exit(1);
        }

        // Add the task to the task queue
        std::lock_guard<std::mutex> task_lock(task_mutex);
        task_queue.push(newSd);

        // Wake up one thread of the threadpool
        task_cv.notify_one();
    }

    // Join the threads
    for (auto &thread : threads)
    {
        thread.join();
    }

    return 0;
}