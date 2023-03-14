#include <arpa/inet.h>
#include <dirent.h>
#include <iostream>
#include <fstream>
#include <filesystem>

// #include <string.h>

const std::string F_NAME = "users.csv";
constexpr size_t FRAGM_SIZE = 512000;

bool isRegistered(std::string_view const & username, std::string_view const & password);
bool rename_file(std::string const & oldFilePath, std::string const & newFileName);
bool delete_file(std::string const & fileName);
std::string list_files(std::string const & path);
// TODO: check
    // TODO: aggiungere Session* session
// upload
    int decryptAndWriteFile(std::string const & path);
// download
    int encryptAndSendFile(std::string const & path);