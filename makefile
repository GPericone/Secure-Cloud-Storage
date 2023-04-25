all: remove client server

remove: 
	# rm client
	# rm server

client: client.cpp tmp_handshake.cpp utils.cpp crypto_util.cpp
	g++ -g -Wall -o client client.cpp tmp_handshake.cpp utils.cpp crypto_util.cpp -lcrypto

server: server.cpp tmp_handshake.cpp utils.cpp crypto_util.cpp
	g++ -g -Wall -o server server.cpp tmp_handshake.cpp utils.cpp crypto_util.cpp -lcrypto
