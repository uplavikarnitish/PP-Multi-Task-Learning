#include<stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <math.h>
#include "comm.h"
#include "ppmtlutils.h"


int main(int argc, char const *argv[])
{
	int /*server_fd,*/ valread, err = 0;
	char buffer[1024] = {0};
	char *hello = "Hello from server";
	int cl_s1_socket;
	char cl_recv_file_name[1024];
	char *public_key_file_name = NULL;
	char working_dir[1024];


	if ( argc != 3 )
	{
		fprintf(stderr, "%s:%d:: ERROR! Usage:\n%s <public_key_file> <working_dir>\n", __func__, __LINE__, argv[0]);
		return -1;
	}

	public_key_file_name = (char *)argv[1];
	strncpy(working_dir, argv[2], strlen(argv[2])>sizeof(working_dir)?
	sizeof(working_dir):strlen(argv[2])+1);
	memset(cl_recv_file_name, 0, sizeof(cl_recv_file_name));
	strcpy(cl_recv_file_name, working_dir);

	if ( (err = append_file_name_to_directory(cl_recv_file_name, sizeof(cl_recv_file_name), ENCR_DEB_LASSO_FRM_CL_FNAME)) != 0 )
	{
		fprintf(stderr, "%s:%d:: ERROR! appending err:%d\n", __func__, __LINE__, err);
		goto clean_up;
	}

	if ( (cl_s1_socket = create_accept_socket_server(C_TO_S1_PORT_NO)) < 0 )
	{
		fprintf(stderr, "%s:%d:: ERROR! return:%d\n", __func__, cl_s1_socket);
		return -1;
	}
	
	if ( (err = recv_file(cl_s1_socket, cl_recv_file_name, (char *)argv[0])) !=0 )
	{
		fprintf(stderr, "%s:%d:: ERROR!!! Cannot receive file!\n", __func__, __LINE__);
		return -2;
	}
	printf("[%s]: Received file from client\n", argv[0]);
	//valread = read( new_socket , buffer, 1024);
	//printf("%s\n",buffer );
	//send(new_socket , hello , strlen(hello) , 0 );
	//printf("Hello message sent\n");

clean_up:
	if ( cl_s1_socket )
	{
//		(shutdown(cl_s1_socket, SHUT_RDWR)==-1)?
//			fprintf(stderr, "%s:%d:: Cannot close socket! errno:%d", errno):
//			printf("[%s] Closed the connection with client!\n", argv[0]);
	}

	return 0;
}
