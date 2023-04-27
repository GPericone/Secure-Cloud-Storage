#include <iostream>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "utils.h"

struct sockaddr_in srvAddr;
const char* ipServer = "127.0.0.1";
int serverPort = 2;
int sd, ret;
