#include "utility_function.h"

void error_handler(const string err)
{
    cout << "Errore: " << err << endl;
}

// void error_handl_exit(char *error_msg)
// {
//     error_handler(error_msg);
//     free_var(CLIENT);
//     close(socket_d);
//     exit(0);
// }

void print_manual()
{
    cout << endl
         << "Welcome in the cloud manual:" << endl
         << endl;
    cout << "manual: man" << endl;
    cout << "list: ls" << endl;
    cout << "upload: up -[filename]" << endl;
    cout << "download: dl -[filename]" << endl;
    cout << "rename: mv -[old_filename] (after prompt) [new_filename]" << endl;
    cout << "delete: rm -[filename]" << endl;
    cout << "logout: lo" << endl;
    cout << endl;
}
