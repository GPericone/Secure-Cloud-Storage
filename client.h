#include <iostream>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>



struct sockaddr_in srvAddr;
char* ipServer;
int serverPort, sd, ret;
