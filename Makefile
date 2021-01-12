CC=gcc

comm: server client commlib

server: server.c
	$(CC) server.c -o server -lm

client: client.c
	$(CC) client.c -o client -lm

commlib: comm.h
testcomm:
	./server&
	./client&

clean:
	rm client server

