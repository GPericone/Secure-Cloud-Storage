all: remove client server

remove: 
	# rm client
	# rm server

client: client_code/client.cpp client_code/tmp_handshake.cpp client_code/utils.cpp client_code/crypto_util.cpp
	g++ -g -Wall -o client_code/client client_code/client.cpp client_code/tmp_handshake.cpp client_code/utils.cpp client_code/crypto_util.cpp -lcrypto

server: server_code/server.cpp server_code/tmp_handshake.cpp server_code/utils.cpp server_code/crypto_util.cpp
	g++ -g -Wall -o server_code/server server_code/server.cpp server_code/tmp_handshake.cpp server_code/utils.cpp server_code/crypto_util.cpp -lcrypto
