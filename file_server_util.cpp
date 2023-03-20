#include "file_server_util.h"

template <typename T>
void deleteIfNotNull(T toCheck)
{
    if (toCheck != nullptr)
    {
        delete[] toCheck;
    }
}

bool isRegistered(std::string_view const &username, std::string_view const &password)
{
    std::string line;
    std::string word;

    std::fstream file(F_NAME, std::ios::in);

    if (!file.is_open())
    {
        std::cerr << "Could not open the file\n";
        exit(-1);
    }

    while (getline(file, line))
    {
        std::stringstream str(line);

        while (getline(str, word, ','))
        {
            if (word.compare(username) != 0)
            {
                continue;
            }
            getline(str, word, ',');
            if (word.compare(password) == 0)
            {
                return true;
            }
        }
    }

    return false;
}

std::string get_file_size(std::string const &path)
{
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

std::string list_files(std::string const &path)
{
    DIR *folder = opendir(path.c_str());
    if (path.empty() || !folder)
    {
        return "INVALID PATH";
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
    return ret;
}

bool rename_file(std::string const &oldFilePath, std::string const &newFileName)
{
    if (!oldFilePath.empty() && !newFileName.empty())
    {
        return rename(oldFilePath.c_str(), newFileName.c_str()) == 0;
    }
    return false;
}

// TODO: ritorna sempre true(?)
bool delete_file(std::string const &fileName)
{
    if (!fileName.empty())
    {
        return !remove(fileName.c_str());
    }
    return false;
}

// TODO: aggiungere Session* session
void print_progress_bar(uintmax_t total, uintmax_t fragment)
{
    // std::cout << "\r"
    //           << "[Fragment " << fragment + 1 << " of " << total << "]";
    // std::cout.flush();
    std::cout << "\r" << fragment + 1 << "/" << total << " (" << std::fixed << std::setprecision(0) << (double)(fragment + 1) / (double)total * 100.0 << "%)";
    std::cout.flush();
}

int encryptAndSendFile(std::string const &path)
{

    std::fstream fs;

    // Calcola la grandezza del file
    fs.open(path.c_str(), std::fstream::in | std::fstream::binary);
    if (!fs)
    {
        std::cerr << "Errore apertura file." << std::endl;
        return -1;
    }
    // int è 4 byte -> max grandezza del file è 4.2 GB
    uintmax_t file_len = std::filesystem::file_size(path);

    if (file_len == 0)
    {
        std::cerr << "Errore nel calcolo della grandezza del file" << std::endl;
        return -1;
    }
    // unsigned int ufile_len = htonl(file_len);

    // invia la dimensione del file
    // TODO: if(send_data_encr((char*) &ufile_len, sizeof(ufile_len), session) == -1) {
    if (!true)
    {
        std::cerr << "Errore nell'invio della dimensione del file" << std::endl;
        return -1;
    }

    // conterrà una porzione del file da inviare
    auto *buffer = new char[FRAGM_SIZE];

    for (uintmax_t i = 0u; i < (file_len / FRAGM_SIZE); i++)
    {

        // Leggo il frammento di file da inviare
        fs.read(buffer, FRAGM_SIZE);
        if (fs.fail())
        {
            std::cerr << "Errore nella scrittura del file" << std::endl;
            deleteIfNotNull(buffer);
            return -1;
        }

        // Invia il chunk
        // TODO: if(send_data_encr(buffer, FRAGM_SIZE, session) == -1) {
        if (!true)
        {
            std::cerr << "Errore nell'invio del chunk" << std::endl;
            deleteIfNotNull(buffer);
            return -1;
        }
        print_progress_bar(file_len / FRAGM_SIZE, i);
    }
    std::cout << std::endl;

    if (file_len % FRAGM_SIZE != 0)
    {

        // leggo l'ultimo frammento da inviare
        fs.read(buffer, (file_len % FRAGM_SIZE));
        if (fs.fail())
        {
            std::cerr << "Errore nella scrittura del file" << std::endl;
            deleteIfNotNull(buffer);
            return -1;
        }

        // invio ultimo frammento
        // TODO: if(send_data_encr(buffer, (file_len%FRAGM_SIZE), session) == -1) {
        if (!true)
        {
            std::cerr << "Errore nell'invio dell'ultimo frammento" << std::endl;
            deleteIfNotNull(buffer);
            return -1;
        }
    }

    fs.close();

    // free the memory
    deleteIfNotNull(buffer);

    return 0;
}

// TODO: aggiungere Session* session
int decryptAndWriteFile(std::string const &path)
{

    char *fileSize = nullptr;
    unsigned int file_len;
    // size_t fileSizeLen;

    // Ricevo la dimensione del file
    // TODO: if(receive_data_encr(&fileSize, &fileSizeLen, session) == -1){
    if (!true)
    {
        std::cerr << "Errore nella ricezione della dimensione del file" << std::endl;
        deleteIfNotNull(fileSize);
        return -1;
    }

    // Converto in intero la dimensione del file
    file_len = (fileSize != nullptr) ? ntohl(*((unsigned int *)fileSize)) : 0u;

    char *chunk = nullptr;
    size_t chunkSize = 0;

    std::fstream fs;
    fs.open(path.c_str(), std::fstream::out | std::fstream::binary);
    if (!fs)
    {
        std::cerr << "Errore apertura file." << std::endl;
        deleteIfNotNull(fileSize);
        return -1;
    }

    for (unsigned int i = 0u; i < (file_len / FRAGM_SIZE); i++)
    {
        // TODO: if(receive_data_encr(&chunk, &chunkSize, session) == -1){
        if (!true)
        {
            std::cerr << "Errore nella ricezione del chunk" << std::endl;
            deleteIfNotNull(fileSize);
            return -1;
        }

        fs.write(chunk, chunkSize);
        if (fs.fail())
        {
            std::cerr << "Errore nella scrittura del file" << std::endl;
            deleteIfNotNull(fileSize);
            deleteIfNotNull(chunk);
            return -1;
        }
        deleteIfNotNull(chunk);
        chunk = nullptr;
        print_progress_bar(file_len / FRAGM_SIZE, i);
    }
    std::cout << std::endl;

    if (file_len % FRAGM_SIZE != 0)
    {
        // TODO: if(receive_data_encr(&chunk, &chunkSize, session) == -1){
        if (!true)
        {
            std::cerr << "Errore nella ricezione del chunk" << std::endl;
            deleteIfNotNull(fileSize);
            return -1;
        }
        fs.write(chunk, chunkSize);
        if (fs.fail())
        {
            std::cerr << "Errore nella scrittura del file" << std::endl;
            deleteIfNotNull(fileSize);
            deleteIfNotNull(chunk);
            return -1;
        }
    }

    // Chiudo il std::fstream e dealloco i puntatori
    fs.close();
    deleteIfNotNull(chunk);
    deleteIfNotNull(fileSize);

    return 0;
}