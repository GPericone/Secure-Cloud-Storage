all: remove server

remove: 
	# rm client
	# rm server

server: server.cpp handshake_utils.cpp utils.cpp crypto_utils.cpp
	g++ -g -Wall -o server server.cpp handshake_utils.cpp utils.cpp crypto_utils.cpp -lcrypto
