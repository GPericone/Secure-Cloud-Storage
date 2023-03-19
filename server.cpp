#include "utility_struct.h"
#include "utility_function.h"

int main()
{

	int listner_socket, new_socket, ret, option = 1, k, fdmax;
	struct sockaddr_in my_addr, client_addr;
	user *list = NULL;

	fd_set master;
	fd_set read_set;

	socklen_t len = 0;

	FD_ZERO(&master);
	FD_ZERO(&read_set);

	if ((listner_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		error_handler("socket creation failed");
		exit(0);
	}

	// VIRTUAL MACHINE TEST ONLY
	setsockopt(listner_socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)); // permette di riusare il solito indirizzo per il socket, necessario per provare senza dover spengere la virtual machine
	//	END

	cout << "> Socket created successfully!" << endl;

	//	Clean up and initialization
	memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(4242);		  // RANDOM port number
	my_addr.sin_addr.s_addr = INADDR_ANY; // C & S in same net

	if ((ret = bind(listner_socket, (struct sockaddr *)&my_addr, sizeof(my_addr))) < 0)
	{
		error_handler("bind() failed");
		exit(0);
	}

	cout << "> Socket binded successfully!" << endl;

	if ((ret = listen(listner_socket, 10)) < 0)
	{ // RANDOM max tail constraint
		error_handler("listen() failed");
		exit(0);
	}

	cout << "> Socket listening..." << endl;

	FD_SET(listner_socket, &master);
	fdmax = listner_socket;

	len = sizeof(client_addr);
}