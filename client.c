// Client side C/C++ program to demonstrate Socket programming
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include "comm.h"
#define PORT 8080

#if 0
int main(int argc, char const *argv[])
{
	struct sockaddr_in address;
	int sock = 0, valread;
	struct sockaddr_in serv_addr;
	char *hello = "Hello from client";
	char buffer[1024] = {0};
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("\n Socket creation error \n");
		return -1;
	}

	memset(&serv_addr, '0', sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);

	// Convert IPv4 and IPv6 addresses from text to binary form
	if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) 
	{
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}

	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		printf("\nConnection Failed \n");
		return -1;
	}
	send(sock , hello , strlen(hello) , 0 );
	printf("Hello message sent\n");
	valread = read( sock , buffer, 1024);
	printf("%s\n",buffer );
	return 0;
}
#endif//0

int main(int argc, char const *argv[])
{
	int sock = 0, valread, err;
	char *hello = "Hello from client";
	char buffer[1024] = {0};
	char * file_name = NULL;
	FILE *fp = NULL;

	if ( argc != 2 )
	{
		fprintf(stderr, "Usage:\n%s <file_name_for_sending>\n", argv[1]);
		return -2;
	}

	file_name = (char *)argv[1];
	if ((sock = create_connect_socket_client("127.0.0.1", PORT )) < 0)
	{
		fprintf(stderr, "%s:%d:: ERROR! returned:%d", __func__, __LINE__, sock);
		return -1;
	}

	printf("Client: file to send:%s\n", argv[1]);
	//printf("Client: sizeof(ssize_t):%ld\n", sizeof(ssize_t));
	//printf("Client: sizeof(int):%ld\n", sizeof(int));
	//printf("Client: sizeof(long):%ld\n", sizeof(long));


//	send(sock , hello , strlen(hello) , 0 );
//	printf("Hello message sent\n");
//	valread = read( sock , buffer, 1024);
//	printf("%s\n",buffer );
	if ( (err = send_file(sock, file_name)) != 0 )
	{
		fprintf(stderr, "%s:%d:: ERROR! Cannot send file:%s!\n", __func__, __LINE__, file_name);
		return -3;
	}


	return 0;
}
