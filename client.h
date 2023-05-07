#include <iostream>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "utils.h"

struct sockaddr_in srvAddr;
const char* ip_server = "127.0.0.1";
int server_port = 4242;
int sd, ret;
