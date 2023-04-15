#include <arpa/inet.h>
#include <dirent.h>
#include <iostream>
#include <fstream>
#include <filesystem>

// #include <string.h>

constexpr size_t FRAGM_SIZE = 512000;

bool rename_file(std::string const & oldFilePath, std::string const & newFileName);
bool delete_file(std::string const & fileName);
std::string list_files(std::string const & path);
// TODO: check
    // TODO: aggiungere Session* session
// upload
    int decryptAndWriteFile(std::string const & path);
// download
    int encryptAndSendFile(std::string const & path);