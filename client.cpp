#include "utility_struct.h"
#include "utility_function.h"

int main()
{
	int socket_d, ret, cmd, dim_f1, dim_f2;
	unsigned char *command = NULL, *command_copy = NULL, *path1 = NULL, *path2 = NULL, *file1 = NULL, *file2 = NULL;
	struct sockaddr_in sv_addr;
	user *this_user;
	char *cl_dir = NULL;

	cl_dir = (char *)malloc(MAX_PATH);
	if (!cl_dir)
	{
		error_handler("malloc failed");
		exit(0);
	}
	getcwd(cl_dir, MAX_PATH);
	strncat(cl_dir, "    ", strlen("  "));

	//	Cleanup and initialization
	memset(&sv_addr, 0, sizeof(sv_addr));
	sv_addr.sin_family = AF_INET;
	sv_addr.sin_port = htons(4242); // RANDOM port number
	if ((ret = inet_pton(AF_INET, "127.0.0.1", &(sv_addr.sin_addr))) == 0)
	{
		error_handler("address format not valid");
		exit(0);
	}

	if ((socket_d = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		error_handler("socket creation failed");
		exit(0);
	}

	cout << "> Socket created successfully!" << endl;

	if ((ret = connect(socket_d, (struct sockaddr *)&sv_addr, sizeof(sv_addr))) < 0)
	{
		error_handler("connect() failed");
		close(socket_d);
		exit(0);
	}

	for (int i = 0; i < 1024; i++)
		cl_free_buf[i] = 0;

	print_manual();

	// AUTHENTICATION PHASE
	this_user = new user;
	this_user->session_key = (unsigned char *)malloc(EVP_CIPHER_key_length(EVP_aes_256_gcm()));
	if (!this_user->session_key)
	{
		error_handler("Malloc failed");
		close(socket_d);
		free_var(CLIENT);
		exit(0);
	}
	this_user->c_counter = 0;
	this_user->s_counter = 0;
	if ((ret = c_authenticate(socket_d, &this_user)) < 0)
	{
		error_handler("authentication failed");
		close(socket_d);
		exit(0);
	}

	while (1)
	{
		memory_handler(CLIENT, socket_d, 128, &command);
		memory_handler(CLIENT, socket_d, 128, &command_copy);

		cout << "Enter a message.." << endl;
		cin.getline((char *)command, 128);
		if ((char)command[0] == '\0')
			continue;

		if ((cmd = get_cmd((char *)command)) < 0)
		{
			error_handler("Command not found. Type 'man' for the Manual");
			continue;
		}

		if (cmd == 5)
		{
			memory_handler(CLIENT, socket_d, 64, &path1);
			memory_handler(CLIENT, socket_d, 64, &path2);
			memory_handler(CLIENT, socket_d, 16, &file1);
			memory_handler(CLIENT, socket_d, 16, &file2);

			dim_f1 = split_file(command, &file1);

			cout << "Insert new filename: " << endl;

			cin.getline((char *)file2, 16);
			dim_f2 = strlen((char *)file2);
			if (dim_f1 < 0 || dim_f2 > 16)
			{
				error_handler("File name too long!");
				free_var(CLIENT);
				continue;
			}
			strncpy((char *)path1, cl_dir, strlen(cl_dir));
			path1 = (unsigned char *)strncat((char *)path1, (char *)file1, strlen((char *)file1));

			if (strstr((char *)file1, "|") != NULL || strstr((char *)file2, "|") != NULL)
			{
				error_handler("Pipe '|' is not allowed in file name");
				free_var(CLIENT);
				continue;
			}
		}
		else if (cmd == 3 || cmd == 4 || cmd == 6)
		{
			memory_handler(CLIENT, socket_d, 64, &path1);
			memory_handler(CLIENT, socket_d, 16, &file1);
			ret = split_file(command, &file1);
			if (ret < 0)
			{
				error_handler("File name too long!");
				free_var(CLIENT);
				continue;
			}
			if (strstr((char *)file1, "|") != NULL)
			{
				error_handler("Pipe '|' is not allowed in file name");
				free_var(CLIENT);
				continue;
			}

			strncpy((char *)path1, cl_dir, strlen(cl_dir));
			path1 = (unsigned char *)strncat((char *)path1, (char *)file1, strlen((char *)file1));
		}
	}
}