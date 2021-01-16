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
//Assumption - init()|init_serv() has been called earlier before calling this function.
int ppmtl_mpz_prod_paillier(mpz_t rop, const mpz_t op1, const mpz_t op2)
{
	mpz_mul(rop, op1, op2);
	mpz_mod(rop, rop, n_square);
}

int compute_encr_norm2(long m, long p, char *cl_recv_file_name, char *op_encr_norm2_file_name)
{
	FILE *fp, *fp_out;
	int err = 0, last_elem_1D_indx = 0;
	long count = 0;
	mpz_t m_val;
	mpz_t norm2;
	char *delimiter;

	if ( (fp = fopen(cl_recv_file_name, "r")) == NULL )
	{
		fprintf(stderr, "%s:%d:: ERROR! Cannot open file:%s\n", __func__, __LINE__, cl_recv_file_name);
		err = -1;
		goto clean_up;
	}

	if ( (fp_out = fopen(op_encr_norm2_file_name, "w")) == NULL )
	{
		fprintf(stderr, "%s:%d:: ERROR! Cannot open file:%s\n", __func__, __LINE__, op_encr_norm2_file_name);
		err = -2;
		goto clean_up;
	}

	mpz_init(m_val);
	mpz_init(norm2);

	//the file to read is a csv file of big numbers,
	//it is arranged as p x m, where, p - no. of features/rows and
	//m - no. of clients/columns.
	count = 0;
	last_elem_1D_indx = (m * p) - 1;
	while ( ( err = gmp_fscanf(fp, "%Zd,", m_val))!=0/*Something parsed*/ && (err != EOF) )
	{
		//gmp_printf("%d>\tValue parsed:%Zd\n", count++, m_val);//debug
		//each row i contains m (i.e. 0 to m-1) encrypted debiased lasso for m clients
		//to calculate norm for each feature/row and put it in file
		if ( (count % m) == 0 )
		{
			//reset the norm2 to 0 for new row
			encrypt(norm2, 0);
		}
		//take product to obtain sum of plaintexts using the
		//additive homomorphic properties
		ppmtl_mpz_prod_paillier(norm2, norm2, m_val);

		if ( (count % m) == (m-1) )
		{
			//Now we have obtained the encrypted norm2 for the 
			//row. Dump this to the output file provided.
			//Align each norm2 on a new row, as row corresponds
			//to features and we have p features and hence,
			//p norm 2s, i.e. avoid comma as delimiter and use
			//newline '\n'.
			if ( count != last_elem_1D_indx )
			{
				//no delimiter after the last norm2 in the 
				//file.
				delimiter = "\n";
			}
			else
			{
				delimiter = "";
			}
			if( (err = gmp_fprintf(fp_out, "%Zd%s", norm2, delimiter)) < 0  )
			{
				fprintf(stderr, "%s:%d:: Cannot write to file:%s\n", __func__, __LINE__, op_encr_norm2_file_name);
				goto clean_up;
			}
			//debug - start
			//gmp_printf("%d\t> E(norm2):%Zd\n", (count/m), norm2);
			//decrypt(norm2);
			//gmp_printf("%d\t> norm2:%Zd\n\n", (count/m), norm2);
			//debug - end
		}
		
		count++;
	}



	err = 0;
clean_up:
	if ( fp )
	{
		fclose(fp);
	}
	if ( fp_out )
	{
		fclose(fp_out);
	}
	if ( m_val )
	{
		mpz_clear(m_val);
	}
	if ( norm2 )
	{
		mpz_clear(norm2);
	}
	return err;
}

/*
l - no. of bits representation
*file_name - output bits, stored as lsb first, separated by '\n'
*/
int convert_to_bin_write_to_file(long l, long val, char *file_name)
{
	int err = 0;
	FILE *fp;
	long i;
	char *separator;

	if ( (fp = fopen(file_name, "w")) == NULL )
	{
		fprintf(stderr, "%s:%d:: ERROR!!! Cannot open file:%s!", __func__, __LINE__, file_name);
		return -1;
	}

	for ( i=0; i<l; i++ )
	{
		if ( i!=0 )
		{
			separator = "\n";
		}
		else
		{
			separator = "";
		}
		if ( (err = fprintf(fp, "%s%d", separator, (val%2))) < 0 )
		{
			fprintf(stderr, "%s:%d:: ERROR!!! Cannot write to file:%s!", __func__, __LINE__, file_name);
			goto clean_up;
		}
		val = val / 2;
	}

	err = 0;
clean_up:
	if ( fp )
	{
		fclose(fp);
	}
	return err;
}

//int sc_optimized(mpz_t e_s, char *ip_encr_dec_bits_file_name, char *v_file_name, long max_no_bits, roles role)
//{
//	int err = 0;
//	FILE *fp_u, *fp_v;
//	long i;
//	mpz_t u_i;
//	mpz_t e_0;
//	mpz_t e_1;
//	mpz_t W_i;
//	mpz_t G_i;
//	mpz_t temp;
//	mpz_t H_i;
//	mpz_t H_i_1;
//	
//
//	if ( role == BOB )
//	{
//		long v_i;
//
//		mpz_init(u_i);
//		mpz_init(e_0);
//		mpz_init(e_1);
//		mpz_init(W_i);
//		mpz_init(G_i);
//		mpz_init(temp);
//		mpz_init(H_i);
//		mpz_init(H_i_1);
//		//s1
//		if ( (fp_u = fopen(ip_encr_dec_bits_file_name, "r"))==NULL )
//		{
//			fprintf(stderr, "%s:%d:: ERROR!!! Cannot open file:%s!", __func__, __LINE__, ip_encr_dec_bits_file_name);
//			err = -1;
//			goto clean_up;
//		}
//
//		if ( (fp_v = fopen(v_file_name, "r"))==NULL )
//		{
//			fprintf(stderr, "%s:%d:: ERROR!!! Cannot open file:%s!", __func__, __LINE__, v_file_name);
//			err = -2;
//			goto clean_up;
//		}
//
//		//1.1. Randomly choose F from {0, 1}
//		srand(time(NULL));
//		int F = ((int)rand()) % 2;
//		printf("[./s0] F:%d\n", F);//dbg
//
//		//1.2
//		for ( i = 1; i <= max_no_bits; i++ )
//		{
//			//read [u_i]
//			if ( (err = gmp_fscanf(fp_u, "%Zd\n", u_i)) <= 0 )
//			{
//				fprintf(stderr, "%s:%d:: ERROR!!! Cannot read file:%s! i:%ld, err:%d, errno:%d", __func__, __LINE__, ip_encr_dec_bits_file_name, i, err, errno);
//				goto clean_up;
//			}
//			//read v_i
//			if ( (err = fscanf(fp_v, "%d\n", &v_i)) <= 0 )
//			{
//				fprintf(stderr, "%s:%d:: ERROR!!! Cannot read file:%s! i:%ld, err:%d, errno:%d", __func__, __LINE__, v_file_name, i, err, errno);
//				goto clean_up;
//			}
//			//debug - start
//			//if ( (i==1) || (i==(max_no_bits-1)) || (i==max_no_bits) )
//			//{
//			//	gmp_printf("%Zd\n%d\n\n", u_i, v_i);
//			//}
//			//debug - stop
//			
//			//1.2.a
//			if (v_i == 0)
//			{
//				//1.2.a.i - TODO remove E_{pu}(u_i * v_i) <- E_{pu}(0) reference from paper
//				//1.2.a.ii.
//				if ( F == 0 )
//				{
//					//1.2.a.ii.A.
//					mpz_set(W_i, u_i);
//				}
//				else
//				{
//					//1.2.a.iii.A
//					//compute W_i<-E(0)
//					encrypt(W_i, 0);
//				}
//				//1.2.a.iv.
//				mpz_set(G_i, u_i);
//			}
//			else
//			{
//				//v_i == 1
//				if ( F == 0 )
//				{
//					//1.2.b.ii.A.
//					//W_i <- E(0)
//					encrypt(W_i, 0);
//				}
//				else
//				{
//					//1.2.b.iii.A
//					//compute W_i<-E(1)*E(u_i)^{N-1}
//					//compute temp<-inv(u_i)
//					mpz_powm(temp, u_i, n_minus_1, n_square);
//					//compute E(1)
//					encrypt(e_1, 1);
//					//compute W_i
//					prod_cipher_paillier(W_i, e_1, temp);//mod n_square taken care of
//				}
//				//1.2.b.iv.
//				//compute G_i
//				//get E(1)
//				encrypt(e_1, 1);
//				//compute temp<-inv(u_i)
//				mpz_powm(temp, u_i, n_minus_1, n_square);
//				//compute G_i
//				prod_cipher_paillier(W_i, e_1, temp);//mod n_square taken care of
//			}
//			//1.2.c. Compute H_i
//			if ( i == 1 )
//			{
//				//H_0 == E(0)
//				encrypt(H_i_1, 0);
//			}
//
//
//			
//		}
//
//	}
//	else if ( role == ALICE )
//	{
//		//s2
//	}
//	err = 0;
//clean_up:
//
//	if ( role == BOB )
//	{
//		if ( u_i )
//		{
//			mpz_clear(u_i);
//		}
//		if ( e_0 )
//		{
//			mpz_clear(e_0);
//		}
//		if ( e_1 )
//		{
//			mpz_clear(e_1);
//		}
//		if ( W_i )
//		{
//			mpz_clear(W_i);
//		}
//		if ( G_i )
//		{
//			mpz_clear(G_i);
//		}
//		if ( H_i )
//		{
//			mpz_clear(H_i);
//		}
//		if ( H_i_1 )
//		{
//			mpz_clear(H_i_1);
//		}
//		if ( temp )
//		{
//			mpz_clear(temp);
//		}
//		if ( fp_u )
//		{
//			fclose(fp_u);
//		}
//		if ( fp_v )
//		{
//			fclose(fp_v);
//		}
//	}
//	else if ( role == ALICE )
//	{
//		
//	}
//	return err;
//}

int main(int argc, char const *argv[])
{
	int /*server_fd,*/ valread, err = 0;
	char buffer[1024] = {0};
	char *hello = "Hello from server";
	int cl_s1_socket, s1_s2_socket ;
	char cl_recv_file_name[1024];
	char op_encr_norm2_file_name[1024];
	char op_encr_dec_bits_file_name[1024];
	char v_file_name[1024];
	char *public_key_file_name = NULL;
	char working_dir[1024];
	long m, p;
	long max_no_bits = 0;


	if ( argc != 3 )
	{
		fprintf(stderr, "%s:%d:: ERROR! Usage:\n%s <public_key_file> <working_dir>\n", __func__, __LINE__, argv[0]);
		return -1;
	}

	public_key_file_name = (char *)argv[1];
	strncpy(g_key_file_name, public_key_file_name, sizeof(g_key_file_name));//Copy the public key file name - to be used later
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
	printf("[%s]: Received encr. deb. lasso sq. from client\n", argv[0]);
	//valread = read( new_socket , buffer, 1024);
	//printf("%s\n",buffer );
	//send(new_socket , hello , strlen(hello) , 0 );
	//printf("Hello message sent\n");

	//Accept m
	if ( (err = recv_long(cl_s1_socket, &m)) != 0 )
	{
		fprintf(stderr, "%s:%d:: [%s] ERROR! Cannot receive m, err:%d!\n", __func__, __LINE__, argv[0], err);
		return -4;
	}
	printf("[%s] Received m:%lu from clients!\n", argv[0], m);

	//Accept p
	if ( (err = recv_long(cl_s1_socket, &p)) != 0 )
	{
		fprintf(stderr, "%s:%d:: [%s] ERROR! Cannot receive p, err:%d!\n", __func__, __LINE__, argv[0], err);
		return -5;
	}
	printf("[%s] Received p:%lu from clients!\n", argv[0], p);

	//Compute the encrypted norm 2 for each feature i, 0<=i<p
	memset(op_encr_norm2_file_name, 0, sizeof(op_encr_norm2_file_name));
	strcpy(op_encr_norm2_file_name, working_dir);

	if ( (err = append_file_name_to_directory(op_encr_norm2_file_name, sizeof(op_encr_norm2_file_name), ENCR_DEB_LASSO_NORM2)) != 0 )
	{
		fprintf(stderr, "%s:%d:: ERROR! appending err:%d\n", __func__, __LINE__, err);
		goto clean_up;
	}

	//we require secure operations from this stage onwards, initialize
	//Paillier variables
	init();
	if ( (err = compute_encr_norm2(m, p, cl_recv_file_name, op_encr_norm2_file_name)) != 0 )
	{
		fprintf(stderr, "%s:%d:: ERROR! return:%d\n", __func__, __LINE__, err);
		goto clean_up;
	}
	printf("[%s] Computed norm 2!\n", argv[0]);

	if ( (err = get_n_size_in_bits(&max_no_bits)) != 0 )
	{
		fprintf(stderr, "%s:%d:: ERROR! return:%d\n", __func__, __LINE__, err);
		goto clean_up;
	}

	printf("[%s] Max. no. of bits (based on n): %ld!\n", argv[0], max_no_bits);

	//Open connection to S2
	if ((s1_s2_socket = create_connect_socket_client(S2_HOSTNAME, S1_TO_S2_PORT_NO )) < 0)
	{
		fprintf(stderr, "%s:%d:: ERROR! returned:%d", __func__, __LINE__, s1_s2_socket);
		err = -3;
		goto clean_up;
	}
	printf("[%s] Established the connection with server S2!\n", argv[0]);
	
	//printf("[%s] Calling append to store encr. dec. bits", argv[0]);//dbg
	//Run the SBD on the program
	memset(op_encr_dec_bits_file_name, 0, sizeof(op_encr_dec_bits_file_name));
	//printf("[%s] Calling append to store encr. dec. bits", argv[0]);//dbg
	strcpy(op_encr_dec_bits_file_name, working_dir);

	//printf("[%s] Calling append to store encr. dec. bits", argv[0]);//dbg
	if ( (err = append_file_name_to_directory(op_encr_dec_bits_file_name, sizeof(op_encr_dec_bits_file_name), ENCR_DEC_BITS_FNAME)) != 0 )
	{
		fprintf(stderr, "%s:%d:: ERROR! appending err:%d\n", __func__, __LINE__, err);
		goto clean_up;
	}
	//debug - start
	mpz_t temp;
	srand(time(NULL));
	int val = ((int)rand()) % 128;
	//mpz_init_set_ui(temp, 31);
	encrypt(temp, val);
	printf("[%s] Calling sbd for e_x:%d rev. bin.: ", argv[0], val);//dbg
	if ((err = sbd(op_encr_dec_bits_file_name, /*op_encr_norm2_file_name*/temp, max_no_bits, s1_s2_socket)) != 0)
	{
		fprintf(stderr, "%s:%d:: ERROR! returned:%d\n", __func__, __LINE__, err);
		goto clean_up;
	}
	printf("[%s] SBD executed successfully!\n", argv[0]);//dbg

	//call the function to reverse the encr. bit order in file
	if ( (err = reverse_file_line_by_line(op_encr_dec_bits_file_name, working_dir)) !=0 )
	{
		fprintf(stderr, "%s:%d:: ERROR! returned:%d\n", __func__, __LINE__, err);
		goto clean_up;
	}
	printf("[%s] Reversed the dec. bit encr. successfully!\n", argv[0]);//dbg
	//Now generate v
	long v = rand() % 128;//TODO: remove mod
	if ( v < 0 )
	{
		v = v * (-1);
	}
	printf("[%s] For sc_optimized(), v:%ld!\n", argv[0], v);//dbg
	
	//Decompose v in bits in the file, ordering is lsb first
	memset(v_file_name, 0, sizeof(v_file_name));
	strcpy(v_file_name, working_dir);
	if ( (err = append_file_name_to_directory(v_file_name, sizeof(v_file_name), V_FNAME)) != 0 )
	{
		fprintf(stderr, "%s:%d:: ERROR! appending err:%d\n", __func__, __LINE__, err);
		goto clean_up;
	}

	if ( (err = convert_to_bin_write_to_file(max_no_bits, v, v_file_name)) != 0 )
	{
		fprintf(stderr, "%s:%d:: ERROR! converting v:%ld, err:%d\n", __func__, __LINE__, v, err);
		goto clean_up;
	}
	printf("[%s] v's binary decomposition performed successfully, v:%ld!\n", argv[0], v);//dbg

	//call the function to reverse the bit order in file to MSB first
	if ( (err = reverse_file_line_by_line(v_file_name, working_dir)) !=0 )
	{
		fprintf(stderr, "%s:%d:: ERROR! returned:%d\n", __func__, __LINE__, err);
		goto clean_up;
	}
	printf("[%s] Reversed the dec. bit successfully!\n", argv[0]);//dbg
	
	mpz_t e_s;
	mpz_init(e_s);
	if ( (err = sc_optimized(e_s, op_encr_dec_bits_file_name, v_file_name, max_no_bits, BOB))!=0 )
	{
		fprintf(stderr, "%s:%d:: ERROR! sc_optimized(), err:%d\n", __func__, __LINE__, err);
		goto clean_up;
	}
	//debug - stop

clean_up:
	clear();
	if ( temp )
	{
		mpz_clear(temp);
	}
	if ( e_s )
	{
		mpz_clear(e_s);
	}
	if ( cl_s1_socket )
	{
//		(shutdown(cl_s1_socket, SHUT_RDWR)==-1)?
//			fprintf(stderr, "%s:%d:: Cannot close socket! errno:%d", errno):
//			printf("[%s] Closed the connection with client!\n", argv[0]);
	}

	return 0;
}
