#include <iostream>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>

struct sockaddr_in myAddr, clAddr;
socklen_t len;
int port, sd, ret, newSd;
pid_t pid;

