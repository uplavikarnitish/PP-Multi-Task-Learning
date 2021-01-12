CC=gcc
CFLAGS=-lgmp -lm

comm: server client commlib

all: s1 clients

s1: s1.c
	gcc s1.c -o s1 ${CFLAGS}

clients: clients.c
	gcc clients.c -o clients ${CFLAGS}

test:
	./s1 key_1024.txt ~/Downloads/deletethis&
	./clients 3 5 45 key_1024.txt ~/Downloads/deletethis&

server: server.c
	$(CC) server.c -o server -lm

client: client.c
	$(CC) client.c -o client -lm

commlib: comm.h
testcomm:
	./server&
	./client&

clean:
	rm client server s1 clients

