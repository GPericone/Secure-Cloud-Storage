#include <iostream>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>

struct sockaddr_in myAddr, clAddr;
int port, sd, ret, len, newSd;
pid_t pid;

