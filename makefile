all: remove client server

remove: 
# 	rm client
	rm server

client: msg_client.cpp client_util.cpp
	g++ -g -Wall -o client msg_client.cpp client_util.cpp common_util.cpp -lcrypto

server: testmain.cpp file_server_util.cpp
	g++ -g -Wall -o server testmain.cpp file_server_util.cpp
