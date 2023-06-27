#include "utils.h"

// Queue of tasks
std::queue<int> task_queue;

// Condition variable for the task queue
std::condition_variable task_cv;

// Mutex for the synchronization of the task queue
std::mutex task_mutex;

// Number of threads in the threadpool
const int NUM_THREADS = 4;

void handle_client(int newSd)
{
    std::unique_ptr<Session> session(new Session());
    session->socket = newSd;

    if (send_message1(session.get()) == false)
    {
        log_error("Error in receiving message 1");
        return;
    }

    if (receive_message2(session.get()) == false)
    {
        log_error("Error in receiving message 2");
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

    if (send_message3(session.get(), server_private_key) == false)
    {
        log_error("Error in sending message 3");
        return;
    }

    if (receive_message4(session.get()) == false)
    {
        log_error("Error in receiving message 4");
        return;
    }

    std::cout << "Handshake completed for client " << session->username << std::endl;

    // Delete the ephemeral key
    EVP_PKEY_free(session->eph_key_pub);
    std::map<std::string, std::unique_ptr<CommandServer>> server_command_map;
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

        std::cout << "Comando ricevuto: " << command << std::endl;

        auto iter = server_command_map.find(command.substr(0, command.find(' ')));
        if (iter != server_command_map.end())
        {
            if (iter->second->execute(session.get(), command) == false)
            {
                break;
            }
        }
        else
        {
            std::cout << "Comando non riconosciuto" << std::endl;
        }
    }
    session.reset();
    // Close the connection with the client
    close(newSd);
}

void thread_func()
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
        handle_client(newSd);
    }
}

int main(int argc, char **argv)
{
    struct sockaddr_in myAddr, clAddr;
    socklen_t len;
    int sd, newSd;
    unsigned short int port = 4242;

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

    if (bind(sd, (struct sockaddr *)&myAddr, sizeof(myAddr)) < 0)
        exit(-1);

    if (listen(sd, 10) < 0)
        exit(-1);

    std::vector<std::thread> threads;

    // Create the threadpool
    for (int i = 0; i < NUM_THREADS; i++)
    {
        threads.emplace_back(thread_func);
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