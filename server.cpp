#include "server.h"

// Coda dei task per il threadpool
std::queue<int> task_queue;

// Variabile di condizione per il threadpool
std::condition_variable task_cv;

// Mutex per la sincronizzazione della coda dei task
std::mutex task_mutex;

// Numero di thread nel threadpool
const int NUM_THREADS = 4;

void handle_client(int newSd, NonceList &nonce_list)
{
    std::unique_ptr<Session> session(new Session());
    session->socket = newSd;

    if (receive_message1(session.get(), nonce_list) == false)
    {
        std::cerr << "Errore in fase di ricezione del messaggio 1" << std::endl;
        return;
    }

    EVP_PKEY *server_private_key = load_private_key("server_file/keys/server_private_key.pem");
    if (server_private_key == nullptr)
    {
        std::cerr << "Errore in fase di caricamento della chiave privata del server" << std::endl;
        return;
    }

    if (send_message2(session.get(), server_private_key) == false)
    {
        std::cerr << "Errore in fase di invio del messaggio 2" << std::endl;
        return;
    }

    if (receive_message3(session.get()) == false)
    {
        std::cerr << "Errore in fase di ricezione del messaggio 3" << std::endl;
        return;
    }

    std::cout << "Handshake completato per il client " << session->username << std::endl;

    // Delete the ephemeral key
    EVP_PKEY_free(session->eph_key_pub);

    // Gestisco la connessione con il client
    while (true)
    {
        // // Ricevo il messaggio dal client
        // if (receive_message(session.get()) == false)
        // {
        //     std::cerr << "Errore in fase di ricezione del messaggio dal client " << session->username << std::endl;
        //     break;
        // }

        // // Invio la risposta al client
        // if (send_message(session.get()) == false)
        // {
        //     std::cerr << "Errore in fase di invio della risposta al client " << session->username << std::endl;
        //     break;
        // }
    }

    // Chiudo la connessione con il client
    close(newSd);
}

void thread_func(NonceList &nonce_list)
{
    while (true)
    {
        // Acquisisco il lock sulla coda dei task
        std::unique_lock<std::mutex> task_lock(task_mutex);

        // Attendo finché non ci sono task nella coda
        task_cv.wait(task_lock, []
                     { return !task_queue.empty(); });

        // Prendo il prossimo task dalla coda
        int newSd = task_queue.front();
        task_queue.pop();

        // Rilascio il lock sulla coda dei task
        task_lock.unlock();

        // Gestisco la connessione con il client
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
    std::cout << "Socket creato correttamente" << std::endl;
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

    // Creo il threadpool
    for (int i = 0; i < NUM_THREADS; i++)
    {
        threads.emplace_back(thread_func, std::ref(nonce_list));
    }

    while (true)
    {
        len = sizeof(clAddr);
        newSd = accept(sd, (struct sockaddr *)&clAddr, &len);
        if (newSd < 0) {
            exit(1);
        }

        // Aggiungo il task alla coda dei task
        std::lock_guard<std::mutex> task_lock(task_mutex);
        task_queue.push(newSd);

        // Sveglio uno dei thread del pool
        task_cv.notify_one();
    }

    // Join di tutti i thread
    for (auto &thread : threads)
    {
        thread.join();
    }

    return 0;
}