#include<stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <math.h>
#include <gmp.h>
//#include "comm.h"
#include "ppmtlutils.h"
#include "secure_vector_computations.h"

int main(int argc, char const *argv[])
{
	int /*server_fd,*/ valread, err = 0;
	char buffer[1024] = {0};
	int s1_s2_socket;
	char *public_key_file_name = NULL;
	char working_dir[1024];
	long m, p;
	long max_no_bits = 0, serv_req = -1;


	if ( argc != 3 )
	{
		fprintf(stderr, "%s:%d:: ERROR! Usage:\n%s <public_key_file> <working_dir>\n", __func__, __LINE__, argv[0]);
		err = -1;
		goto clean_up;
	}

	public_key_file_name = (char *)argv[1];
	strncpy(g_key_file_name, public_key_file_name, sizeof(g_key_file_name));//Copy the public key file name - to be used later
	strncpy(working_dir, argv[2], strlen(argv[2])>sizeof(working_dir)?
	sizeof(working_dir):strlen(argv[2])+1);

	//Read the Paillier variables
	init();
	printf("[%s] Waiting for connection request from server S1 ...\n", argv[0]);
	if ( (s1_s2_socket = create_accept_socket_server(S1_TO_S2_PORT_NO)) < 0 )
	{
		fprintf(stderr, "%s:%d:: ERROR! return:%d\n", __func__, s1_s2_socket);
		err = -2;
		goto clean_up;
	}
	printf("[%s] Accepted the connection with server S1!\n", argv[0]);

	while ( ((err = accept_service_reqs(&serv_req, s1_s2_socket))==0) /*&& 
			( ((serv_types)serv_req) != TERMINATE)*/ )
	{
		switch(serv_req)
		{
			case ENC_LSB:
				//printf("[%s] Service request:%lu - ENC_LSB received!\n", argv[0], serv_req);
				if ( (err = encrypted_lsb(NULL, NULL, -1, ALICE, s1_s2_socket)) != 0)
				{
					fprintf(stderr, "%s:%d:: ERROR!!! in encrypted_lsb(): %d\n", __func__, __LINE__, err);
					err = -3;
					goto clean_up;
				}
			break;

			case OSC:
				printf("[%s] Service request:%lu - OSC received!\n", argv[0], serv_req);
				if ( (err = sc_optimized(NULL, NULL, NULL, -1, working_dir, s1_s2_socket, ALICE)) != 0)
				{
					fprintf(stderr, "%s:%d:: ERROR!!! in sc_optimized(): %d\n", __func__, __LINE__, err);
					err = -4;
					goto clean_up;
				}
			break;

			case TERMINATE:
				printf("[%s] Service request:%lu - TERMINATE received!\n", argv[0], serv_req);

			break;

			default:
			fprintf(stderr, "%s:%d:: ERROR!!! Invalid service "
			"request passed! req:%lu\n", serv_req);
		}
		if ( serv_req == TERMINATE )
		{
			break;
		}
	}
	err = 0;
clean_up:
	clear();

	return err;

}
