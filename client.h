#include <iostream>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "utils.h"

std::map<std::string, std::unique_ptr<CommandClient>> client_command_map;
struct sockaddr_in srvAddr;
const char* ip_server = "127.0.0.1";
int server_port = 4242;
int sd, ret;
const std::string message = "La comunicazione è stata messa in sicurezza, adesso è possibile eseguire le seguenti operazioni:\n\n"
                      "- upload: per caricare un file dal tuo computer al server, utilizza il comando 'Upload' seguito dal nome del file che vuoi caricare. Il server salverà il file con il nome specificato da te. Se ciò non fosse possibile, il file non verrà caricato. Il limite di dimensione per il file caricato è di 4GB.\n"
                      "- download: per scaricare un file dal server, utilizza il comando 'Download' seguito dal nome del file che vuoi scaricare. Il nome del file scaricato sarà lo stesso usato dal server per salvarlo. Se ciò non fosse possibile, il file non verrà scaricato.\n"
                      "- delete: per eliminare un file dal server, utilizza il comando 'Delete' seguito dal nome del file che vuoi eliminare. Il server ti chiederà conferma prima di procedere con l'eliminazione del file.\n"
                      "- list: per ottenere la lista dei file disponibili sul server, utilizza il comando 'List'. La lista verrà stampata sullo schermo del client.\n"
                      "- rename: per rinominare un file sul server, utilizza il comando 'Rename' seguito dal nome del file che vuoi rinominare e dal nuovo nome che vuoi assegnargli. Se ciò non fosse possibile, il nome del file non verrà cambiato.\n"
                      "- logout: per chiudere la connessione con il server in modo corretto, utilizza il comando 'LogOut'.\n\n"
                      "Inserisci il comando dopo il carattere \">\" e premi invio per spedirlo al server.\n\n";
