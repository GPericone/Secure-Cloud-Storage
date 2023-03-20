#include "server.h"

int main(int argc, char**argv)
{
    if(argc == 1)
    {
        port = 4242;
    }
    else
        port = atoi(argv[1]);
    

    sd = socket(AF_INET, SOCK_STREAM, 0);

    if(sd < 0)
    {
        exit(1);
    }

    memset(&myAddr, 0, sizeof(myAddr));
    myAddr.sin_family = AF_INET;
    myAddr.sin_port = htons(port);
    myAddr.sin_addr.s_addr = INADDR_ANY;

    ret = bind(sd, (struct sockaddr *)&myAddr, sizeof(myAddr));
    if(ret < 0)
        exit(-1);
    
    ret = listen(sd, 10);
    if(ret < 0)
        exit(-1);

    while(1)
    {
        len = sizeof(clAddr);
        newSd = accept(sd, (struct sockaddr *)&clAddr, &len);
        if( newSd < 0)
            exit(1);

        pid = fork();
        if(pid == 0)
        {
            int closeSd = close(sd);
            if(closeSd < 0)
            {
                printf("LOG_ERROR: Errore in fase di chiusura del socket\n");
                exit(1);
            }
            else
                printf("LOG_INFO: Socket chiuso correttamente");
            
        }

        /*while(1)
        { 


            
        }*/

    }

}   