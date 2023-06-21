all: remove client

remove: 
	# rm client
	# rm server

client: client.cpp handshake_utils.cpp utils.cpp crypto_utils.cpp
	g++ -g -Wall -o client client.cpp handshake_utils.cpp utils.cpp crypto_utils.cpp -lcrypto