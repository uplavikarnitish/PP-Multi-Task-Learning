#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <math.h>
//https://stackoverflow.com/questions/2613734/maximum-packet-size-for-a-tcp-connection?utm_medium=organic&utm_source=google_rich_qa&utm_campaign=google_rich_qa
//https://stackoverflow.com/questions/2613734/maximum-packet-size-for-a-tcp-connection?utm_medium=organic&utm_source=google_rich_qa&utm_campaign=google_rich_qa#comment81466713_3074427
#if 0
#define MAX_MTU 1500
#else
#define MAX_MTU 65536
//#define MAX_MTU 3072
#endif

#define MAX_OVERHEAD 128
#define MAX_SEND (MAX_MTU - MAX_OVERHEAD)
#define PORT 8080

typedef enum _serv_types{
	ENC_LSB,
	TERMINATE
}serv_types;

int create_connect_socket_client(char *ip_str, int port_no)
{
	struct sockaddr_in serv_addr;
	int sock = 0;

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("\n Socket creation error \n");
		return -1;
	}

	memset(&serv_addr, '0', sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port_no);
	
	// Convert IPv4 and IPv6 addresses from text to binary form
	if(inet_pton(AF_INET, ip_str, &serv_addr.sin_addr)<=0) 
	{
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}

	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		printf("\nConnection Failed \n");
		return -1;
	}
	return sock;
}


int create_accept_socket_server(int port_no)
{
	int server_fd, new_socket;
	int opt = 1;
	struct sockaddr_in address;
	int addrlen = sizeof(address);
	
	// Creating socket file descriptor
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
	{
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	// Forcefully attaching socket to the port 8080
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
				&opt, sizeof(opt)))
	{
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons( port_no );

	// Forcefully attaching socket to the port 8080
	if (bind(server_fd, (struct sockaddr *)&address, 
				sizeof(address))<0)
	{
		perror("bind failed");
		exit(EXIT_FAILURE);
	}
	if (listen(server_fd, 3) < 0)
	{
		perror("listen");
		exit(EXIT_FAILURE);
	}

	if ((new_socket = accept(server_fd, (struct sockaddr *)&address, 
					(socklen_t*)&addrlen))<0)
	{
		perror("accept");
		exit(EXIT_FAILURE);
	}
	return new_socket;
}

int send_long(int socket, long val)
{
	long bytes_sent = -1;
	if ( (bytes_sent = send(socket, &val, sizeof(val), 0)) == -1 )
	{
		fprintf(stderr, "%s:%d ERROR! Sending value! bytes_sent:%ld, errno:%d", __func__, __LINE__, bytes_sent, errno);
		return -1;
	}

	if ( bytes_sent != sizeof(val) )
	{
		fprintf(stderr, "%s:%d:: ERROR! bytes_sent=%d != sizeof(val)=%d\n", __func__, __LINE__, bytes_sent, sizeof(val));
		return -2;
	}

	return 0;
}

int send_bytes(int socket, char *val, long no_bytes)
{
	long bytes_sent = -1;
	if ( (bytes_sent = send(socket, val, no_bytes, 0)) == -1 )
	{
		fprintf(stderr, "%s:%d ERROR! Sending value! bytes_sent:%ld, errno:%d", __func__, __LINE__, bytes_sent, errno);
		return -1;
	}

	if ( bytes_sent != no_bytes )
	{
		fprintf(stderr, "%s:%d:: ERROR! bytes_sent=%ld != no_bytes=%ld\n", __func__, __LINE__, bytes_sent, no_bytes);
		return -2;
	}

	return 0;
}
int recv_long(int socket, long *op_val)
{
	long bytes_recvd = -1;
	if ( (bytes_recvd = read(socket, op_val, sizeof(*op_val))) == 0 )
	{
		fprintf(stderr, "%s:%d ERROR! Receiving value! bytes_recvd:%ld, expected:%ld, errno:%d\n", __func__, __LINE__, bytes_recvd, sizeof(*op_val), errno);
		return -1;
	}

	if ( bytes_recvd != sizeof(*op_val) )
	{
		fprintf(stderr, "%s:%d:: ERROR! bytes_recvd=%d != sizeof(*op_val)=%d\n", __func__, __LINE__, bytes_recvd, sizeof(*op_val));
		return -2;
	}
	return 0;
}

int recv_bytes(int socket, char *op_val, long no_bytes)
{
	long bytes_recvd = -1;
	if ( (bytes_recvd = read(socket, op_val, no_bytes)) < 0 )
	{
		fprintf(stderr, "%s:%d ERROR! Receiving value! bytes_recvd:%ld, expected:%ld, errno:%d", __func__, __LINE__, bytes_recvd, no_bytes, errno);
		return -1;
	}

//	if ( bytes_recvd != no_bytes )
//	{
//		fprintf(stderr, "%s:%d:: ERROR! bytes_recvd=%ld != no_bytes=%ld\n", __func__, __LINE__, bytes_recvd, no_bytes);
//		return -2;
//	}
	return 0;
}

int get_file_size( long *file_size, char *file_name)
{
	int err = 0;
	FILE *fp = NULL;
	char *buf = NULL;
	long bytes_read = 0;
	*file_size = 0;
	if ( (fp = fopen(file_name, "rb")) == NULL)
	{
		fprintf(stderr, "%s:%d:: ERROR! Cannot open file! socket:%d, file_name:%s\n", __func__, __LINE__, socket, file_name);
		return -2;
	}

	buf = malloc(MAX_SEND);
	if ( buf == NULL )
	{
		fprintf(stderr, "%s:%d:: Cannot allocate space!\n", __func__, __LINE__);
		goto clean_up;
	}
	while ( (bytes_read = fread(buf, 1, MAX_SEND, fp)) != 0 )
	{
		//printf("Bytes read:%lu\n", bytes_read);//dbg
		*file_size += bytes_read;
	}
//	if ( feof(fp) )
//	{
//		printf("End of file reached!\n");
//	}
//	else
//	{
//		printf("End of file NOT reached!\n");
//	}
//	printf("Bytes read(last unsuccessfull attempt):%lu\n", bytes_read);//dbg

	err = 0;
clean_up:
	if ( buf )
	{
		free(buf);
	}
	if ( fp )
	{
		fclose(fp);
	}
	return err;
}

int send_file(int socket, char *file_name, char *context)
{
	FILE *fp = NULL;
	int err;
	long bytes_read = 0;
	char *buf = NULL;
	long actual_file_size = 0;

	if ( (socket < 0) || (file_name == NULL) )
	{
		fprintf(stderr, "%s:%d:: ERROR! Bad arguments passed! socket:%d, file_name:%s\n", __func__, __LINE__, socket, file_name);
		return -1;
	}

	if (get_file_size(&actual_file_size, file_name)!=0)
	{
		fprintf(stderr, "%s:%d:: ERROR in file size!\n", __func__, __LINE__);
		return -1;
	}
	printf("[%s] Actual file size: %ld for file %s\n", context, actual_file_size, file_name);

	if ( (fp = fopen(file_name, "rb")) == NULL)
	{
		fprintf(stderr, "%s:%d:: ERROR! Cannot open file! socket:%d, file_name:%s\n", __func__, __LINE__, socket, file_name);
		return -2;
	}
	//Get file size
	long file_sz = 0;
	if ( (err = fseeko(fp, 0, SEEK_END)) != 0)
	{
		fprintf(stderr, "%s:%d:: ERROR:%d seeking the file pointer! errno:%u\n", __func__, __LINE__, err, errno);
		goto cleanup;
	}
	if ( (file_sz = ftello(fp)) == -1)
	{
		fprintf(stderr, "%s:%d:: ERROR:%d telling the file pointer! errno:%u\n", __func__, __LINE__, err, errno);
		goto cleanup;
	}
	printf("[%s] File size: %ld for file %s\n", context, file_sz, file_name);

	//send the file size in long
	if ( (err = send_long(socket, file_sz)) != 0 )
	{
		fprintf(stderr, "%s:%d:: ERROR! err=%d\n", __func__, __LINE__, err);
		goto cleanup;
	}

	//take the pointer at the start
	if ( (err = fseek(fp, 0, SEEK_SET)) != 0)
	{
		fprintf(stderr, "%s:%d:: ERROR:%d seeking the file pointer to start! errno:%u\n", __func__, __LINE__, err, errno);
		goto cleanup;
	}

	buf = malloc(MAX_SEND);
	if ( buf == NULL )
	{
		fprintf(stderr, "%s:%d:: Cannot allocate space!\n", __func__, __LINE__);
		goto cleanup;
	}

	int iter = 0;
	while ( (bytes_read = fread(buf, 1, MAX_SEND, fp)) != 0 )
	{
		if ( (err = send_bytes(socket, buf, bytes_read)) != 0 )
		{
			fprintf(stderr, "%s:%d:: ERROR!!! Cannot send bytes, err:%d\n", __func__, __LINE__, err);
			goto cleanup;
		}
		iter++;
	}
	printf("[%s] File %s transferred in %d iterations\n", context, file_name, iter);


cleanup:
	if ( buf )
	{
		free(buf);
	}
	if ( fp )
	{
		fclose(fp);
	}
}

int recv_file(int socket, char *file_name, char *context)
{
	FILE *fp = NULL;
	int err, i;
	long file_sz = 0;
	char *buf = NULL;
	if ( (socket < 0) || (file_name == NULL) )
	{
		fprintf(stderr, "%s:%d:: ERROR! Bad arguments passed! socket:%d, file_name:%s\n", __func__, __LINE__, socket, file_name);
		return -1;
	}

	if ( (fp = fopen(file_name, "wb")) == NULL)
	{
		fprintf(stderr, "%s:%d:: ERROR! Cannot open file! socket:%d, file_name:%s\n", __func__, __LINE__, socket, file_name);
		return -2;
	}

	//Get file size
	if ( (err = recv_long(socket, &file_sz)) != 0 )
	{
		fprintf(stderr, "%s:%d:: ERROR! err=%d\n", __func__, __LINE__, err);
		goto cleanup;
	}

	printf("[%s] Size of file to receive:%ld\n", context, file_sz);

	buf = malloc(MAX_SEND);
	if ( buf == NULL )
	{
		fprintf(stderr, "%s:%d:: Cannot allocate space!\n", __func__, __LINE__);

		goto cleanup;
	}

	long n = (long)ceil(((double)file_sz)/((double)MAX_SEND));
	printf("[%s] no. of iterations to transfer file:%lu\n", context, n);
	printf("[%s] file_sz:%lu, max. msg. size:%lu, last iter. bytes:%lu\n", context, file_sz, MAX_SEND, (file_sz % MAX_SEND));

	for( i=0; i<n; i++ )
	{
		long bytes_to_recv = MAX_SEND;
		if ( i == (n-1) )
		{
			//Last iteration - may not have full data, just partial
			bytes_to_recv = (file_sz % MAX_SEND);
		}
		if ( (err = recv_bytes(socket, buf, bytes_to_recv)) != 0 )
		{
			fprintf(stderr, "%s:%d:: ERROR! Cannot receive bytes, err:%d!\n", __func__, __LINE__, err);
			goto cleanup;
		}
		if ( ((err = fwrite(buf, 1, bytes_to_recv, fp)) <= 0) ||
			(err!=bytes_to_recv))
			{
				fprintf(stderr, "%s:%d:: ERROR! Cannot write designated bytes, exp.:%lu, actual:%lu\n", __func__, __LINE__, bytes_to_recv, err);
				goto cleanup;
			}
	}

	printf("[%s] file received in iter.:%d\n", context, i);
	err = 0;
cleanup:
	if ( fp )
	{
		fclose(fp);
	}
	if ( buf )
	{
		free(buf);
	}
	return err;
}

int accept_service_reqs(long *serv_type, int socket)
{
	int err = 0;
	
	if ( (err = recv_long(socket, serv_type)) != 0 )
	{
		fprintf(stderr, "%s:%d:: ERROR! err=%d\n", __func__, __LINE__, err);
		goto clean_up;
	}

	err = 0;
clean_up:
	return err;
}

int send_service_reqs(int socket, serv_types serv_req)
{
	int err = 0;
	
	if ( (err = send_long(socket, ((long)serv_req))) != 0 )
	{
		fprintf(stderr, "%s:%d:: ERROR! err=%d\n", __func__, __LINE__, err);
		goto clean_up;
	}

	err = 0;
clean_up:
	return err;
}
