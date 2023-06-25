all: remove client server

remove: 
	# rm client
	# rm server

client: client_code/client.cpp client_code/handshake_utils.cpp client_code/utils.cpp client_code/crypto_utils.cpp
	g++ -g -Wall -o client_code/client client_code/client.cpp client_code/handshake_utils.cpp client_code/utils.cpp client_code/crypto_utils.cpp -lcrypto

server: server_code/server.cpp server_code/handshake_utils.cpp server_code/utils.cpp server_code/crypto_utils.cpp
	g++ -g -Wall -o server_code/server server_code/server.cpp server_code/handshake_utils.cpp server_code/utils.cpp server_code/crypto_utils.cpp -lcrypto
