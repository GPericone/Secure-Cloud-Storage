#include "client.h"


int main(int argc, char** argv)
{
        
    if(argc == 1)
    {
        ipServer = "127.0.0.1";
        serverPort = 4242;
    }
    else 
    {
        ipServer = argv[1];
        serverPort = atoi(argv[2]);

    }

    //Create socket
    sd = socket(AF_INET, SOCK_STREAM, 0);

    memset(&srvAddr, 0, sizeof(srvAddr));
    srvAddr.sin_family = AF_INET;
    srvAddr.sin_port = htons(serverPort);
    inet_pton(AF_INET, ipServer, &srvAddr.sin_addr);
    ret = connect(sd, (struct sockaddr*)&srvAddr, sizeof(srvAddr));

    if(sd <0 || ret<0)
    {
        printf("LOG_ERR: Errore di connesione, sd=%d, ret=%d \n", sd, ret);
        exit(-1);
    }

    while(1)
    {

    }

    close(sd);
    
}