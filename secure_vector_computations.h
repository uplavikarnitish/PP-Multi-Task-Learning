#include <math.h>
#include<stdio.h>
#include<stdlib.h>
#include<assert.h>
#include<gmp.h>
#include<stdint.h>
#include<inttypes.h>
#include<errno.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

//#include <jni.h>
//#include "preprocess_EncryptNativeC.h"
#include "gen_vectors.h"
#include "comm.h"


#define VSIZE 10
#define KEY_SIZE_BINARY 4096	//n^{2} size
#define KEY_SIZE_BASE10 2*KEY_SIZE_BINARY*log10(2)
#define BIG_NUM_SZ KEY_SIZE_BASE10*sizeof(char)
#define J_DOUBLE_SZ_BYTES 2048
#define MAX_DIGITS_IN_NO KEY_SIZE_BINARY*4
#define ALICE_ROLE 0
#define BOB_ROLE 1
#define	L_PRIME_F_NAME "L_prime.dat"
#define	L_PRIME_RECVD_F_NAME "L_prime_recvd.dat"
typedef enum _roles{ALICE, BOB}roles;

//Use this when storing mpz's value in string with base 10 form, instead
//of repeated malloc and callocs
char mpz_buffer[MAX_DIGITS_IN_NO];
//global encrypt-decryption variables
mpz_t big_temp;
mpz_t n;
mpz_t n_plus_1;        //n+1, the public key
mpz_t n_minus_1;        //n-1, SBD required
mpz_t n_square;        //n^2
mpz_t r;
mpz_t r_pow_n;         //r^n mod n^2
mpz_t d;               //d=lcm(p-1, q-1), the private key
mpz_t d_inverse;       //d^{-1} mod n^2
//gmp_randstate_t state; //seed for randomization

char g_key_file_name[256];

//function prototypes

//Paillier's public key encrytion and decryption
//set c = (n+1)^m * r^n mod n^2
void encrypt(mpz_t c, int m);
void encrypt_big_num(mpz_t c, mpz_t m);

//return m = 
void decrypt(mpz_t c);

//set r to a random value between 1 and n-1
void get_random_r();

//initialize global variables for client
void init();

//initialize global variables for server
void init_serv();

//release memory allocated to the global variables
void clear();

void gen_random_input(int v[], int size);

int encrypt_vec_to_file( int vsizelocal, const char * input_file_name, const char * output_file_name, const char * key_file_name);
int encrypt_vec_to_file_mem_opt( int vsizelocal, const char * input_file_name, const char * output_file_name, const char * key_file_name);

int get_n_and_d_from_file();
//Size of vector in dimensions
int vsize;

void get_random_r_given_modulo( mpz_t random_no, mpz_t modulo );

char buf[J_DOUBLE_SZ_BYTES];
//assume state has been initialized
void get_random_r_given_modulo( mpz_t random_no, mpz_t modulo )
{

	do{
		mpz_urandomm(random_no, state, modulo);
	}while(mpz_cmp_ui(random_no, 0) == 0);
}

int prod_cipher_paillier(mpz_t rop, const mpz_t op1, const mpz_t op2)
{
	mpz_mul(rop, op1, op2);
	mpz_mod(rop, rop, n_square);
}

int append_file_name_to_directory( char *dir, int dir_sz, char *fname )
{
	if ( dir == NULL || fname == NULL )
	{
		fprintf(stderr, "%s:%d:: ERROR! BAD ARGS PASSED!\n", __func__, __LINE__);
		return -1;
	}
	strncat(dir, "/", dir_sz - 1);
	strncat(dir, fname, dir_sz - 1);
	return 0;
}

int encrypt_vec_to_file( int vsizelocal, const char * input_file_name, const char * output_file_name, const char * key_file_name)
{
	int input_size = 0, i, temp;
	mpz_t *vec1;
	char* temp_str = NULL;
	FILE *input_file, *output_file;


	vsize = vsizelocal;
	input_file = fopen(input_file_name, "r");
	output_file = fopen(output_file_name, "w");

	strncpy(g_key_file_name, key_file_name, sizeof(g_key_file_name));

	//printf("Number of vector dimensions = %d\n", vsizelocal);
	//printf("p_vec2:%p, ENOMEM:%d\n", p_vec2, (errno == ENOMEM)?1:0);



	//initialize vectors and big number variables
	//Dynamically creating the array
	vec1 = (mpz_t *)malloc(vsizelocal*sizeof(mpz_t));

	//We have to write encrypted values to file
	//to hold each value in string before we need
	//a large string to copy the big number
	//Although the key size is 4096 bits,
	//we will allocate the chars capable of storing
	//8192 bit values. No. of chars required = 
	//log(2^{8192}) base 10 = keysize*log 2 = 8192 * log 2 = 2466.03<2500
	temp_str = (char *)malloc(BIG_NUM_SZ);

	//initialize vectors and big number variables
	for (i = 0; i < vsizelocal; i++)
		mpz_init(*(vec1+i));

	//variables are set to 0

	init();

	for (i = 0; i < vsizelocal; i++)
	{
		mpz_init(*(vec1+i));
	}

	//variables are set to 0

	//init();



	//check if files are opened properly
	if (input_file == NULL) {
		printf("\n%s", "Error: open input_file!");
		return -2;
	}

	if (output_file == NULL) {
		printf("\n%s", "Error: open output_file!");
		return -3;
	}

	//fprintf(stderr, "\n\nIp:%s, op:%s\n", input_file_name, output_file_name);
	//fill in the first vector
	//TODO read as a long %lu or %ld
	for( fscanf(input_file,"%d", &temp); temp != EOF && input_size < vsizelocal; 
			fscanf(input_file, "%d", &temp) ){

		//temp = (int) temp2;
		//printf("doc1:: temp2: %" PRId64 ", temp:%d\n", temp2, temp);
		//printf("doc1::Wt:%d\n", temp);

		//fprintf(stderr, "tempWt:%d\n", temp);
		encrypt(*(vec1+input_size), temp);
		//gmp_printf("No. of chars:%d, BIGNO:%s\n", gmp_sprintf(temp_str, "%Zd", *(vec1+input_size)), temp_str);
		//TODO: Optimization area use fprintf directly using %Zd instead of temp_str. No memory needed.
		gmp_sprintf(temp_str, "%Zd", *(vec1+input_size));
		//decrypt(vec1[input_size]);
		//gmp_printf("%d: %Zd\n", input_size, *(vec1+input_size));
		fprintf(output_file, "%s", temp_str);
		input_size ++;
		if ( vsizelocal!=1 && input_size < vsizelocal )
		{
			fprintf(output_file, "\n");
		}
	} 




	fclose(input_file);  
	fflush(output_file);
	sync();
	fclose(output_file);

	//release space used by big number variables
	for (i = 0; i < vsizelocal; i++)
		mpz_clear(*(vec1+i));


	clear();
	free(vec1);
	free(temp_str);

	return 0;

}

/*Memory efficient version of encrypt_vec_to_file()*/
int encrypt_vec_to_file_mem_opt( int vsizelocal, const char * input_file_name, const char * output_file_name, const char * key_file_name)
{
	int input_size = 0, temp;
	mpz_t vec1;
	char* temp_str = NULL;
	FILE *input_file, *output_file;


	vsize = vsizelocal;
	input_file = fopen(input_file_name, "r");
	output_file = fopen(output_file_name, "w");

	strncpy(g_key_file_name, key_file_name, sizeof(g_key_file_name));

	//printf("Number of vector dimensions = %d\n", vsizelocal);
	//printf("p_vec2:%p, ENOMEM:%d\n", p_vec2, (errno == ENOMEM)?1:0);



	//initialize vectors and big number variables
	//Dynamically creating the array
	//vec1 = (mpz_t *)malloc(vsizelocal*sizeof(mpz_t));

	//We have to write encrypted values to file
	//to hold each value in string before we need
	//a large string to copy the big number
	//Although the key size is 4096 bits,
	//we will allocate the chars capable of storing
	//8192 bit values. No. of chars required = 
	//log(2^{8192}) base 10 = keysize*log 2 = 8192 * log 2 = 2466.03<2500
	temp_str = (char *)malloc(BIG_NUM_SZ);

	//initialize vectors and big number variables
	//for (i = 0; i < vsizelocal; i++)
	//	mpz_init(*(vec1+i));

	//variables are set to 0

	init();

	//for (i = 0; i < vsizelocal; i++)
	//{
	mpz_init(vec1);
	//}

	//variables are set to 0

	//init();



	//check if files are opened properly
	if (input_file == NULL) {
		printf("\n%s", "Error: open input_file!");
		return -2;
	}

	if (output_file == NULL) {
		printf("\n%s", "Error: open output_file!");
		return -3;
	}

	//fprintf(stderr, "\n\nIp:%s, op:%s\n", input_file_name, output_file_name);
	//fill in the first vector
	//TODO read as a long %lu or %ld
	for( fscanf(input_file,"%d", &temp); temp != EOF && input_size < vsizelocal; 
			fscanf(input_file, "%d", &temp) ){

		//temp = (int) temp2;
		//printf("doc1:: temp2: %" PRId64 ", temp:%d\n", temp2, temp);
		//printf("doc1::Wt:%d\n", temp);

		//fprintf(stderr, "tempWt:%d\n", temp);
		encrypt(vec1, temp);
		//gmp_printf("No. of chars:%d, BIGNO:%s\n", gmp_sprintf(temp_str, "%Zd", *(vec1+input_size)), temp_str);
		//TODO: Optimization area use fprintf directly using %Zd instead of temp_str. No memory needed.
		gmp_sprintf(temp_str, "%Zd", vec1);
		//decrypt(vec1[input_size]);
		//gmp_printf("%d: %Zd\n", input_size, *(vec1+input_size));
		fprintf(output_file, "%s", temp_str);
		input_size ++;
		if ( vsizelocal!=1 && input_size < vsizelocal )
		{
			fprintf(output_file, "\n");
		}
	} 




	fclose(input_file);  
	fflush(output_file);
	sync();
	fclose(output_file);

	//release space used by big number variables
	mpz_clear(vec1);


	clear();
	free(temp_str);

	return 0;

}

int rem_double_str_effects(char *double_in_str)
{
	int len = 0, dot_present = 0, i;
	if ( double_in_str == NULL )
	{
		fprintf(stderr, "%s:%d::ERROR! Bad Pointer!", __func__, __LINE__);
		return -1;
	}
	len = strlen(double_in_str);
	for ( i=0; i<len; i++ )
	{
		if ( double_in_str[i] == '.' )
		{
			dot_present = 1;
			break;
		}
	}
	if ( dot_present == 1 )
	{
		double_in_str[i] = '\0';
	}
	return 0;
}

int corr_sub(mpz_t dot_prod, mpz_t corr, mpz_t exp, mpz_t big_temp)
{

	if ( (dot_prod == NULL) || (corr == NULL) || (exp == NULL) || (big_temp == NULL))
	{
		fprintf(stderr, "ERROR! Bad pointer! dot_prod:%p, corr:%p, exp:%p, big_temp:%p", dot_prod, corr, exp, big_temp);
		return -1;
	}

	//corr in Z*_n. If corr < 0, this will correct it
	mpz_mod(corr, corr, n);

	//exp = n-1
	mpz_set(exp, n);//exp == n
	mpz_sub_ui(exp, exp, 1);//exp == n-1
	mpz_mod(exp, exp, n);//exp == n-1 mod n

	//get E(corr)
	encrypt_big_num(big_temp, corr);//big_temp = E(corr)

	//find E(-corr) = E(corr)^(n-1)
	mpz_powm(corr, big_temp, exp, n_square);//corr = E(-corr)

	//find correction. E(dot_prod).E(-corr) = E(dot_prod - corr)
	mpz_mul(dot_prod, dot_prod, corr);
	mpz_mod(dot_prod, dot_prod, n_square);

	return 0;
}

int negative_test()
{
	mpz_t num;
	mpz_t zero;
	mpz_t big_temp;
	mpz_t big;

	mpz_init(num);
	mpz_init(zero);
	mpz_init(big_temp);
	mpz_init(big);

	encrypt(zero, 0);//0
	gmp_printf("E(0):%Zd\n\n", zero);
	encrypt(num, 12313);//E(12313)
	gmp_printf("E(12313):%Zd\n\n", num);

	mpz_set_ui(big, 12313);

	corr_sub(num, big, zero, big_temp);
	/*
	mpz_set(zero, n);
	mpz_sub_ui(big_temp, zero, 1);
	mpz_powm(big_temp, num, big_temp, n_square);
	mpz_set(zero, big_temp);
	decrypt(zero);
	mpz_add_ui(zero, zero, 12313);
	mpz_mod(zero, zero, n);
	gmp_printf("0?:%Zd\n\n", zero);
	gmp_printf("E(-12313):%Zd\n\n", big_temp);
	mpz_mul(zero, num, big_temp);
	mpz_mod(big_temp, zero, n_square);
	gmp_printf("E(12313)*E(-12313):%Zd\n\n", big_temp);
	mpz_set(zero, big_temp);*/
	decrypt(num);
	gmp_printf("D(E(12313)*E(-12313)):%Zd\n\n", num);

	

	mpz_clear(num);
	mpz_clear(zero);
	mpz_clear(big_temp);
	mpz_clear(big);
	return 0;
}

/*
 * This function reads the encrypted query sent by client, computes the intermediate cosine tfidf product and cosine co-ordination factor,
 * randomizes these two values and writes them along with respective randomizing values into the output_file_name.
 * */
int read_encrypt_vec_from_file_comp_inter_sec_prod( int vsizelocal, const char * input_encr_tfidf_file_name, const char * input_encr_bin_file_name, const char * input_tfidf_vec_file_name, const char * input_bin_vec_file_name, const char * output_file_name, const char * key_file_name, const char *tfidf_row_corr_str, const char *bin_row_corr_str)
{
	int input_size = 0, i, temp, *p_tfidf_vec, *p_bin_vec;
	mpz_t *vec1;	//holds input encrypted tfidf q values
	mpz_t *vec2;	//holds input encrypted binary q values
	mpz_t cosine_result;
	mpz_t co_ord_factor;
	mpz_t cosine_result_rand;
	mpz_t co_ord_factor_rand;
	mpz_t random_no_1;
	mpz_t random_no_2;
	mpz_t encr_random_no_1;
	mpz_t encr_random_no_2;
	mpz_t neg_term;
	mpz_t sum_neg_terms;
	mpz_t rand_prod;
	mpz_t exponent;
	mpz_t tfidf_row_corr;
	mpz_t bin_row_corr;
	mpz_t big_temp;
	mpz_t exp;
	FILE *input_encr_tfidf_file, *input_tfidf_vec_file, *input_bin_vec_file, *output_file, *input_encr_bin_file;


	vsize = vsizelocal;
	input_encr_tfidf_file = fopen(input_encr_tfidf_file_name, "r");
	input_encr_bin_file = fopen(input_encr_bin_file_name, "r");
	input_tfidf_vec_file = fopen(input_tfidf_vec_file_name, "r");
	input_bin_vec_file = fopen(input_bin_vec_file_name, "r");
	output_file = fopen(output_file_name, "w");

	strncpy(g_key_file_name, key_file_name, sizeof(g_key_file_name));

	//printf("Number of vector dimensions = %d\n", vsizelocal);
	//printf("p_tfidf_vec:%p, ENOMEM:%d\n", p_tfidf_vec, (errno == ENOMEM)?1:0);



	//initialize vectors and big number variables
	//Dynamically creating the array
	vec1 = (mpz_t *)malloc(vsizelocal*sizeof(mpz_t));
	vec2 = (mpz_t *)malloc(vsizelocal*sizeof(mpz_t));
	p_tfidf_vec = (int*)malloc(vsize*sizeof(int));
	p_bin_vec = (int*)malloc(vsize*sizeof(int));
	if ( errno == ENOMEM )
	{
		printf("p_tfidf_vec:%p, ENOMEM:%d\n", p_tfidf_vec, (errno == ENOMEM)?1:0);
	}

	//initialize vectors and big number variables
	for (i = 0; i < vsizelocal; i++)
		mpz_init(*(vec1+i));
	for (i = 0; i < vsizelocal; i++)
		mpz_init(*(vec2+i));

	//variables are set to 0
	mpz_init(cosine_result);
	mpz_init(co_ord_factor);
	mpz_init(cosine_result_rand);
	mpz_init(co_ord_factor_rand);
	mpz_init(random_no_1);
	mpz_init(random_no_2);
	mpz_init(encr_random_no_1);
	mpz_init(encr_random_no_2);
	mpz_init(neg_term);
	mpz_init(sum_neg_terms);
	mpz_init(rand_prod);
	mpz_init(exponent);
	mpz_init(tfidf_row_corr);
	mpz_init(bin_row_corr);
	mpz_init(big_temp);
	mpz_init(exp);

	init_serv();

	//variables are set to 0

	//init();



	//check if files are opened properly
	if (input_encr_tfidf_file == NULL) {
		printf("\n%s", "Error: open input_encr_tfidf_file!");
		return -2;
	}

	if (input_encr_bin_file == NULL) {
		printf("\n%s", "Error: open input_encr_bin_file!");
		return -2;
	}

	if (input_tfidf_vec_file == NULL) {
		printf("\n%s", "Error: open input_tfidf_vec_file!");
		return -3;
	}

	if (input_bin_vec_file == NULL) {
		printf("\n%s", "Error: open input_bin_vec_file!");
		return -4;
	}

	if (output_file == NULL) {
		printf("\n%s", "Error: open output_file!");
		exit(1);
	}


	//fill in the first vector
	input_size = 0;
	while ( (input_size < vsizelocal) )
	{
		if ( input_size == vsizelocal - 1 )
		{
			gmp_fscanf(input_encr_tfidf_file,"%Zd", (vec1+input_size));
		}
		else
		{
			gmp_fscanf(input_encr_tfidf_file,"%Zd\n", (vec1+input_size));
		}
		//gmp_printf("%d>> READ %Zd\n", input_size+1, *(vec1+input_size));

		input_size++;
	}
	if ( !( input_size == vsizelocal ) )
	{
		fprintf(stderr, "%s:%d::ERROR! TFIDF: Nothing to read OR parsing error! input_size:%d, vsizelocal:%d\n", 
				__func__, __LINE__, input_size, vsizelocal);
		return -4;
	}

	input_size = 0;
	while ( (input_size < vsizelocal) )
	{
		if ( input_size == vsizelocal - 1 )
		{
			gmp_fscanf(input_encr_bin_file,"%Zd", (vec2+input_size));
		}
		else
		{
			gmp_fscanf(input_encr_bin_file,"%Zd\n", (vec2+input_size));
		}
		//gmp_printf("%d>> READ %Zd\n", input_size+1, *(vec2+input_size));

		input_size++;
	}
	if ( !( input_size == vsizelocal ) )
	{
		fprintf(stderr, "%s:%d::ERROR! Binary: Nothing to read OR parsing error! input_size:%d, vsizelocal:%d\n", 
				__func__, __LINE__, input_size, vsizelocal);
		return -4;
	}


	//printf("\n");
	input_size = 0;

	//fill in the second vector
	for( fscanf(input_tfidf_vec_file,"%d", &temp); temp != EOF && input_size < vsize; 
			fscanf(input_tfidf_vec_file, "%d", &temp) ){

		//printf("Non encrypted TFIDF Input::Wt.:%d\n", temp);
		*(p_tfidf_vec + input_size) = temp;
		input_size ++;
	} 

	input_size = 0;
	for( fscanf(input_bin_vec_file,"%d", &temp); temp != EOF && input_size < vsize; 
			fscanf(input_bin_vec_file, "%d", &temp) ){

		//printf("Non encrypted Binary Input::Wt.:%d\n", temp);
		*(p_bin_vec + input_size) = temp;
		input_size ++;
	} 

	encrypt(cosine_result, 0);
	//compute encrypted the vec1 * p_tfidf_vec (dot product)
	for (i = 0; i < input_size; i++) {
		//compute m1 * m2
		mpz_powm_ui(big_temp, *(vec1+i), *(p_tfidf_vec+i), n_square);
		//compute m1 + m2
		mpz_mul(cosine_result, cosine_result, big_temp);
		mpz_mod(cosine_result, cosine_result, n_square);
	}

	encrypt(co_ord_factor, 0);
	//compute encrypted the vec2 * co_ord_factor (dot product)
	for (i = 0; i < input_size; i++) {
		//compute m1 * m2
		mpz_powm_ui(big_temp, *(vec2+i), *(p_bin_vec+i), n_square);
		//compute m1 + m2
		mpz_mul(co_ord_factor, co_ord_factor, big_temp);
		mpz_mod(co_ord_factor, co_ord_factor, n_square);
	}

	//TODO: Here we add code to incorporate the LSI changes - START
	if ( (strlen(tfidf_row_corr_str)!=0) ) 
	{
		//LSI and there is a correction for tfidf row
		strncpy(buf, tfidf_row_corr_str, sizeof(J_DOUBLE_SZ_BYTES));
		rem_double_str_effects(buf);
		mpz_set_str(tfidf_row_corr, buf, 10);
		//gmp_fprintf(stderr, "LSI Row correction for TFIDF!\nstr:%s\nmpz:%Zd\n\n", buf, tfidf_row_corr);
		//gmp_printf("Tfidf dot prod. before: %Zd\n\n", cosine_result);
		corr_sub(cosine_result, tfidf_row_corr, exp, big_temp);
		//gmp_printf("Tfidf dot prod. after: %Zd\n\n", cosine_result);
	}
	else
	{
		//No LSI mode
		mpz_set_ui(tfidf_row_corr, 0);
		//gmp_fprintf(stderr, "No LSI Row correction for TFIDF!\nstr:%s\nmpz:%Zd\n\n", tfidf_row_corr_str, tfidf_row_corr);
	}
	
	if ( (strlen(bin_row_corr_str)!=0) )
	{
		//LSI and there is a correction for binary row
		strncpy(buf, bin_row_corr_str, sizeof(J_DOUBLE_SZ_BYTES));
		rem_double_str_effects(buf);
		mpz_set_str(bin_row_corr, buf, 10);
		//gmp_fprintf(stderr, "LSI Row correction for BINARY!\nstr:%s\nmpz:%Zd\n\n", buf, bin_row_corr);
		//gmp_printf("Binary dot prod. before: %Zd\n\n", co_ord_factor);
		corr_sub(co_ord_factor, bin_row_corr, exp, big_temp);
		//gmp_printf("Binary dot prod. after: %Zd\n\n", co_ord_factor);
	}
	else
	{
		//No LSI mode
		mpz_set_ui(bin_row_corr, 0);
		//gmp_fprintf(stderr, "No LSI Row correction for BINARY!\nstr:%s\nmpz:%Zd\n\n", bin_row_corr_str, bin_row_corr);
	}
	//TODO: Here we add code to incorporate the LSI changes - END

	//negative_test();

	/*
	 * Donot decrypt here as we would not be having the CORRESPONDING private key
	 * */
	//decrypt the encrypted dot product
	//decrypt(cosine_result);

	//TODO: Remove this debug decryption. - START
	/*
	mpz_t dot_prod;
	mpz_init(dot_prod);
	mpz_t dot_prod2;
	mpz_init(dot_prod2);
	mpz_set(dot_prod, cosine_result);
	decrypt(dot_prod);
	//gmp_fprintf(stderr, "\n%s:%d:: Query*%s TFIDF cosine product: %Zd\n", __func__, __LINE__, input_encr_tfidf_file_name, dot_prod);

	mpz_set(dot_prod2, co_ord_factor);
	decrypt(dot_prod2);
	//gmp_fprintf(stderr, "\n%s:%d:: Query*%s CO-ORD. cosine product: %Zd\n\n", __func__, __LINE__, input_encr_bin_file_name, dot_prod2);

	mpz_mul(dot_prod2, dot_prod2, dot_prod);
	mpz_mod(dot_prod2, dot_prod2, n);
	//gmp_fprintf(stderr, "\n\n%s:%d EXPECTED SIMILARITY SCORE = %Zd\n\n", __func__, __LINE__, dot_prod2);
	//fflush(stderr);

	mpz_clear(dot_prod);
	mpz_clear(dot_prod2);
	*/
	//TODO: Remove this debug decryption. - END

	//decrypt the encrypted co ordination factor
	//decrypt(co_ord_factor);

	/*
	 * Generate two random numbers of the modulo n_square and the add these two
	 * to the two results - cosine product and co_ord_factor. 
	 * Write these two random values one after the other
	 * and then the randomized values after them in the output file
	 * given for performing the secure multiplication
	 * protocol. All should be seperated by a newline except maybe the last one
	 * written to the file. FORMAT - output file
	 * ===START===
	 * r_1
	 * randomized cosine tfidf product
	 * r_2
	 * randomized cosine co-ord. product
	 * derandomizing factor
	 *  ===END===
	 * */

	//Generate random number, say r_1
	get_random_r_given_modulo(random_no_1, n);
	//encrypt for using homomophic property
	encrypt_big_num(encr_random_no_1, random_no_1);	//E(r_1)
	//Write r_1 to outputfile
	mpz_out_str(output_file, 10, random_no_1);
	fprintf(output_file, "\n");
	//Calculate randomized cosine tfidf product, MULTIPLYING to add
	mpz_mul(cosine_result_rand, cosine_result, encr_random_no_1);	//E(r_1)
	//Compute modulus
	mpz_mod(cosine_result_rand, cosine_result_rand, n_square);
	//Write randomized cosine tfidf product to output file
	mpz_out_str(output_file, 10, cosine_result_rand);
	fprintf(output_file, "\n");

	//Generate random number, say r_2
	get_random_r_given_modulo(random_no_2, n);
	//encrypt for using homomophic property
	encrypt_big_num(encr_random_no_2, random_no_2);	//E(r_2)
	//Write r_2 to outputfile
	mpz_out_str(output_file, 10, random_no_2);
	fprintf(output_file, "\n");
	//Calculate randomized cosine binary product, MULTIPLYING to add
	mpz_mul(co_ord_factor_rand, co_ord_factor, encr_random_no_2);	//E(r_2)
	//Compute modulus
	mpz_mod(co_ord_factor_rand, co_ord_factor_rand, n_square);
	//Write randomized cosine co_ord product to output file
	mpz_out_str(output_file, 10, co_ord_factor_rand);
	fprintf(output_file, "\n");

	//gmp_printf("\nThus similarity of %s and %s score = %Zd written in %s\n", input_encr_tfidf_file_name, input_tfidf_vec_file_name, cosine_result, output_file_name);
#if 0
	//print the cosine_result
	if (mpz_out_str(output_file, 10, cosine_result) == 0)
		printf("ERROR: Not able to write the cosine_result!\n");

	fprintf(output_file, "\n");
#endif
	//gmp_printf("\nThus co-ord. factor of %s and %s score = %Zd written in %s\n", input_encr_bin_file_name, input_bin_vec_file_name, co_ord_factor, output_file_name);
#if 0
	//print the co_ord_factor
	if (mpz_out_str(output_file, 10, co_ord_factor) == 0)
		printf("ERROR: Not able to write the co_ord_factor!\n");
#endif

	//These following steps are required in the later stage of the MP protocol
	//We will calculate the complement of random number added in both the products
	//In the later stage, we will just add(or multiply for homomorphic additive
	//encryption) E(-( a*r_2 + b*r_1 + r_1*r_2 )) in E( a*b + a*r_2 + b*r_1 + r_1*r_2 )
	//To get E(a*b), where, 'a' is the tfidf vector product, 'b' is the binary vector
	//product(co-ord factor)
	//'r_i' is the random number for i = 1,2.
	//This is basically an optimization step which we are computing early to avoid unnecessary
	//multiple file I/Os.
	//Assume cosine_result as E(a), co_ord_factor as E(b)
	//and random_no_1 as r_1, random_no_2 as r_2
	
	//Resetting to zero
	//Set the encrypted value of 0 to sum_neg_terms
	encrypt(sum_neg_terms, 0);	//sum_neg_terms = E(0)

	//Calculating E(a)^r_2 = E(a*r_2)
	
	mpz_powm(neg_term, cosine_result, random_no_2, n_square);

	//neg_term(E(a*r_2))*sum_neg_terms(E(0)) = E(0+a*r_2)
	mpz_mul(sum_neg_terms, sum_neg_terms, neg_term);
	mpz_mod(sum_neg_terms, sum_neg_terms, n_square);
	
	//Calculating E(b)^r_1 = E(b*r_1)
	
	mpz_powm(neg_term, co_ord_factor, random_no_1, n_square);
	
	//neg_term(E(b*r_1))*sum_neg_terms(E(a*r_2)) = E(a*r_2 + b*r_1)
	mpz_mul(sum_neg_terms, sum_neg_terms, neg_term);
	mpz_mod(sum_neg_terms, sum_neg_terms, n_square);

	//Calculating E(r_1 * r_2)
	
	//Calculating E(r_1)^r_2 = E(r_1*r_2)
	mpz_powm(rand_prod, encr_random_no_1, random_no_2, n_square);
	//Calculating neg_term = E(r_1 * r_2)
	mpz_set(neg_term, rand_prod);

	//neg_term(E(r_1 * r_2))*sum_neg_terms(E(a*r_2 + b*r_1)) = E(a*r_2 + b*r_1 + r_1*r_2)
	mpz_mul(sum_neg_terms, sum_neg_terms, neg_term);
	mpz_mod(sum_neg_terms, sum_neg_terms, n_square);
	
	//Calculating E(-(a*r_2 + b*r_1 + r_1*r_2))
	mpz_set(exponent, n);
	mpz_sub_ui(exponent, exponent, 1);//exponent=n_square-1
	mpz_powm(sum_neg_terms, sum_neg_terms, exponent, n_square);
	
	//Write the result E(-a*r_2 - b*r_1 - r_1*r_2)
	//to file so that it can be used in next phase
	mpz_out_str(output_file, 10, sum_neg_terms);
	
	//gmp_fprintf(stderr, "\n%s:%d:: De-randomizing factor: %Zd written"
	//" in file %s\n", __func__, __LINE__, sum_neg_terms, output_file_name);
	

	fclose(input_encr_tfidf_file);  
	fclose(input_encr_bin_file);  
	//fflush(input_tfidf_vec_file);
	fclose(input_tfidf_vec_file);
	//fflush(input_bin_vec_file);
	fclose(input_bin_vec_file);
	fflush(output_file);
	fclose(output_file);

	//release space used by big number variables
	for (i = 0; i < vsizelocal; i++)
		mpz_clear(*(vec1+i));
	for (i = 0; i < vsizelocal; i++)
		mpz_clear(*(vec2+i));


	mpz_clear(cosine_result);
	mpz_clear(co_ord_factor);
	mpz_clear(cosine_result_rand);
	mpz_clear(co_ord_factor_rand);
	mpz_clear(random_no_1);
	mpz_clear(random_no_2);
	mpz_clear(encr_random_no_1);
	mpz_clear(encr_random_no_2);
	mpz_clear(neg_term);
	mpz_clear(sum_neg_terms);
	mpz_clear(rand_prod);
	mpz_clear(exponent);
	mpz_clear(tfidf_row_corr);
	mpz_clear(bin_row_corr);
	mpz_clear(big_temp);
	mpz_clear(exp);
	clear();
	free(vec1);
	free(vec2);
	free(p_tfidf_vec);
	free(p_bin_vec);

	return 0;
}

/*
 * This function reads the encrypted query sent by client, computes the intermediate cosine tfidf product and cosine co-ordination factor,
 * randomizes these two values and writes them along with respective randomizing values into the output_file_name.
 * Memory optimized version of read_encrypt_vec_from_file_comp_inter_sec_prod_mem_opt().
 * */
int read_encrypt_vec_from_file_comp_inter_sec_prod_mem_opt( int vsizelocal, const char * input_encr_tfidf_file_name, const char * input_encr_bin_file_name, const char * input_tfidf_vec_file_name, const char * input_bin_vec_file_name, const char * output_file_name, const char * key_file_name, const char *tfidf_row_corr_str, const char *bin_row_corr_str)
{
	int input_size = 0, i, p_tfidf_vec, p_bin_vec;
	mpz_t vec1;	//holds input encrypted tfidf q values
	mpz_t vec2;	//holds input encrypted binary q values
	mpz_t cosine_result;
	mpz_t co_ord_factor;
	mpz_t cosine_result_rand;
	mpz_t co_ord_factor_rand;
	mpz_t random_no_1;
	mpz_t random_no_2;
	mpz_t encr_random_no_1;
	mpz_t encr_random_no_2;
	mpz_t neg_term;
	mpz_t sum_neg_terms;
	mpz_t rand_prod;
	mpz_t exponent;
	mpz_t tfidf_row_corr;
	mpz_t bin_row_corr;
	mpz_t big_temp;
	mpz_t exp;
	FILE *input_encr_tfidf_file, *input_tfidf_vec_file, *input_bin_vec_file, *output_file, *input_encr_bin_file;


	vsize = vsizelocal;
	input_encr_tfidf_file = fopen(input_encr_tfidf_file_name, "r");
	input_encr_bin_file = fopen(input_encr_bin_file_name, "r");
	input_tfidf_vec_file = fopen(input_tfidf_vec_file_name, "r");
	input_bin_vec_file = fopen(input_bin_vec_file_name, "r");
	output_file = fopen(output_file_name, "w");

	strncpy(g_key_file_name, key_file_name, sizeof(g_key_file_name));

	//printf("Number of vector dimensions = %d\n", vsizelocal);
	//printf("p_tfidf_vec:%p, ENOMEM:%d\n", p_tfidf_vec, (errno == ENOMEM)?1:0);



	//initialize vectors and big number variables
	//Dynamically creating the array
	//vec1 = (mpz_t *)malloc(vsizelocal*sizeof(mpz_t));
	//vec2 = (mpz_t *)malloc(vsizelocal*sizeof(mpz_t));
	//p_tfidf_vec = (int*)malloc(vsize*sizeof(int));
	//p_bin_vec = (int*)malloc(vsize*sizeof(int));
	//if ( errno == ENOMEM )
	//{
	//	printf("p_tfidf_vec:%p, ENOMEM:%d\n", p_tfidf_vec, (errno == ENOMEM)?1:0);
	//}

	//initialize vectors and big number variables
	//for (i = 0; i < vsizelocal; i++)
	mpz_init(vec1);
	//for (i = 0; i < vsizelocal; i++)
	mpz_init(vec2);

	//variables are set to 0
	mpz_init(cosine_result);
	mpz_init(co_ord_factor);
	mpz_init(cosine_result_rand);
	mpz_init(co_ord_factor_rand);
	mpz_init(random_no_1);
	mpz_init(random_no_2);
	mpz_init(encr_random_no_1);
	mpz_init(encr_random_no_2);
	mpz_init(neg_term);
	mpz_init(sum_neg_terms);
	mpz_init(rand_prod);
	mpz_init(exponent);
	mpz_init(tfidf_row_corr);
	mpz_init(bin_row_corr);
	mpz_init(big_temp);
	mpz_init(exp);

	init_serv();

	//variables are set to 0

	//init();



	//check if files are opened properly
	if (input_encr_tfidf_file == NULL) {
		printf("\n%s", "Error: open input_encr_tfidf_file!");
		return -2;
	}

	if (input_encr_bin_file == NULL) {
		printf("\n%s", "Error: open input_encr_bin_file!");
		return -2;
	}

	if (input_tfidf_vec_file == NULL) {
		printf("\n%s", "Error: open input_tfidf_vec_file!");
		return -3;
	}

	if (input_bin_vec_file == NULL) {
		printf("\n%s", "Error: open input_bin_vec_file!");
		return -4;
	}

	if (output_file == NULL) {
		printf("\n%s", "Error: open output_file!");
		exit(1);
	}



	//printf("\n");

	//fill in the second vector

	encrypt(cosine_result, 0);
	input_size = vsize;
	//compute encrypted the vec1 * p_tfidf_vec (dot product)
	for (i = 0; i < input_size; i++) {

		//Get the vec1
		if ( i == input_size - 1 )
		{
			gmp_fscanf(input_encr_tfidf_file,"%Zd", vec1);
		}
		else
		{
			gmp_fscanf(input_encr_tfidf_file,"%Zd\n", vec1);
		}

		//Get p_tfidf_vec
		fscanf(input_tfidf_vec_file,"%d", &p_tfidf_vec);
		if ( p_tfidf_vec == EOF )
		{
			fprintf(stderr, "%s:%d:: ERROR! EOF detected!\n", __func__, __LINE__);
			return -5;
		}

		//compute m1 * m2
		mpz_powm_ui(big_temp, vec1, p_tfidf_vec, n_square);
		//compute m1 + m2
		mpz_mul(cosine_result, cosine_result, big_temp);
		mpz_mod(cosine_result, cosine_result, n_square);
	}
	if ( !( i == input_size ) )
	{
		fprintf(stderr, "%s:%d::ERROR! TFIDF: Nothing to read OR parsing error! i:%d, input_size:%d\n", 
				__func__, __LINE__, i, input_size);
		return -7;
	}

	encrypt(co_ord_factor, 0);
	input_size = vsize;
	//compute encrypted the vec2 * co_ord_factor (dot product)
	for (i = 0; i < input_size; i++) {

		//Get the vec2

		if ( i == input_size - 1 )
		{
			gmp_fscanf(input_encr_bin_file,"%Zd", vec2);
		}
		else
		{
			gmp_fscanf(input_encr_bin_file,"%Zd\n", vec2);
		}

		//Get p_bin_vec
		fscanf(input_bin_vec_file,"%d", &p_bin_vec);
		if ( p_bin_vec == EOF )
		{
			fprintf(stderr, "%s:%d:: ERROR! EOF detected!\n", __func__, __LINE__);
			return -6;
		}

		//compute m1 * m2
		mpz_powm_ui(big_temp, vec2, p_bin_vec, n_square);
		//compute m1 + m2
		mpz_mul(co_ord_factor, co_ord_factor, big_temp);
		mpz_mod(co_ord_factor, co_ord_factor, n_square);
	}
	if ( !( i == input_size ) )
	{
		fprintf(stderr, "%s:%d::ERROR! BINARY: Nothing to read OR parsing error! i:%d, input_size:%d\n", 
				__func__, __LINE__, i, input_size);
		return -7;
	}

	//TODO: Here we add code to incorporate the LSI changes - START
	if ( (strlen(tfidf_row_corr_str)!=0) ) 
	{
		//LSI and there is a correction for tfidf row
		strncpy(buf, tfidf_row_corr_str, sizeof(J_DOUBLE_SZ_BYTES));
		rem_double_str_effects(buf);
		mpz_set_str(tfidf_row_corr, buf, 10);
		//gmp_fprintf(stderr, "LSI Row correction for TFIDF!\nstr:%s\nmpz:%Zd\n\n", buf, tfidf_row_corr);
		//gmp_printf("Tfidf dot prod. before: %Zd\n\n", cosine_result);
		corr_sub(cosine_result, tfidf_row_corr, exp, big_temp);
		//gmp_printf("Tfidf dot prod. after: %Zd\n\n", cosine_result);
	}
	else
	{
		//No LSI mode
		mpz_set_ui(tfidf_row_corr, 0);
		//gmp_fprintf(stderr, "No LSI Row correction for TFIDF!\nstr:%s\nmpz:%Zd\n\n", tfidf_row_corr_str, tfidf_row_corr);
	}
	
	if ( (strlen(bin_row_corr_str)!=0) )
	{
		//LSI and there is a correction for binary row
		strncpy(buf, bin_row_corr_str, sizeof(J_DOUBLE_SZ_BYTES));
		rem_double_str_effects(buf);
		mpz_set_str(bin_row_corr, buf, 10);
		//gmp_fprintf(stderr, "LSI Row correction for BINARY!\nstr:%s\nmpz:%Zd\n\n", buf, bin_row_corr);
		//gmp_printf("Binary dot prod. before: %Zd\n\n", co_ord_factor);
		corr_sub(co_ord_factor, bin_row_corr, exp, big_temp);
		//gmp_printf("Binary dot prod. after: %Zd\n\n", co_ord_factor);
	}
	else
	{
		//No LSI mode
		mpz_set_ui(bin_row_corr, 0);
		//gmp_fprintf(stderr, "No LSI Row correction for BINARY!\nstr:%s\nmpz:%Zd\n\n", bin_row_corr_str, bin_row_corr);
	}
	//TODO: Here we add code to incorporate the LSI changes - END

	//negative_test();

	/*
	 * Donot decrypt here as we would not be having the CORRESPONDING private key
	 * */
	//decrypt the encrypted dot product
	//decrypt(cosine_result);

	//TODO: Remove this debug decryption. - START
	/*
	mpz_t dot_prod;
	mpz_init(dot_prod);
	mpz_t dot_prod2;
	mpz_init(dot_prod2);
	mpz_set(dot_prod, cosine_result);
	decrypt(dot_prod);
	//gmp_fprintf(stderr, "\n%s:%d:: Query*%s TFIDF cosine product: %Zd\n", __func__, __LINE__, input_encr_tfidf_file_name, dot_prod);

	mpz_set(dot_prod2, co_ord_factor);
	decrypt(dot_prod2);
	//gmp_fprintf(stderr, "\n%s:%d:: Query*%s CO-ORD. cosine product: %Zd\n\n", __func__, __LINE__, input_encr_bin_file_name, dot_prod2);

	mpz_mul(dot_prod2, dot_prod2, dot_prod);
	mpz_mod(dot_prod2, dot_prod2, n);
	//gmp_fprintf(stderr, "\n\n%s:%d EXPECTED SIMILARITY SCORE = %Zd\n\n", __func__, __LINE__, dot_prod2);
	//fflush(stderr);

	mpz_clear(dot_prod);
	mpz_clear(dot_prod2);
	*/
	//TODO: Remove this debug decryption. - END

	//decrypt the encrypted co ordination factor
	//decrypt(co_ord_factor);

	/*
	 * Generate two random numbers of the modulo n_square and the add these two
	 * to the two results - cosine product and co_ord_factor. 
	 * Write these two random values one after the other
	 * and then the randomized values after them in the output file
	 * given for performing the secure multiplication
	 * protocol. All should be seperated by a newline except maybe the last one
	 * written to the file. FORMAT - output file
	 * ===START===
	 * r_1
	 * randomized cosine tfidf product
	 * r_2
	 * randomized cosine co-ord. product
	 * derandomizing factor
	 *  ===END===
	 * */

	//Generate random number, say r_1
	get_random_r_given_modulo(random_no_1, n);
	//encrypt for using homomophic property
	encrypt_big_num(encr_random_no_1, random_no_1);	//E(r_1)
	//Write r_1 to outputfile
	mpz_out_str(output_file, 10, random_no_1);
	fprintf(output_file, "\n");
	//Calculate randomized cosine tfidf product, MULTIPLYING to add
	mpz_mul(cosine_result_rand, cosine_result, encr_random_no_1);	//E(r_1)
	//Compute modulus
	mpz_mod(cosine_result_rand, cosine_result_rand, n_square);
	//Write randomized cosine tfidf product to output file
	mpz_out_str(output_file, 10, cosine_result_rand);
	fprintf(output_file, "\n");

	//Generate random number, say r_2
	get_random_r_given_modulo(random_no_2, n);
	//encrypt for using homomophic property
	encrypt_big_num(encr_random_no_2, random_no_2);	//E(r_2)
	//Write r_2 to outputfile
	mpz_out_str(output_file, 10, random_no_2);
	fprintf(output_file, "\n");
	//Calculate randomized cosine binary product, MULTIPLYING to add
	mpz_mul(co_ord_factor_rand, co_ord_factor, encr_random_no_2);	//E(r_2)
	//Compute modulus
	mpz_mod(co_ord_factor_rand, co_ord_factor_rand, n_square);
	//Write randomized cosine co_ord product to output file
	mpz_out_str(output_file, 10, co_ord_factor_rand);
	fprintf(output_file, "\n");

	//gmp_printf("\nThus similarity of %s and %s score = %Zd written in %s\n", input_encr_tfidf_file_name, input_tfidf_vec_file_name, cosine_result, output_file_name);
#if 0
	//print the cosine_result
	if (mpz_out_str(output_file, 10, cosine_result) == 0)
		printf("ERROR: Not able to write the cosine_result!\n");

	fprintf(output_file, "\n");
#endif
	//gmp_printf("\nThus co-ord. factor of %s and %s score = %Zd written in %s\n", input_encr_bin_file_name, input_bin_vec_file_name, co_ord_factor, output_file_name);
#if 0
	//print the co_ord_factor
	if (mpz_out_str(output_file, 10, co_ord_factor) == 0)
		printf("ERROR: Not able to write the co_ord_factor!\n");
#endif

	//These following steps are required in the later stage of the MP protocol
	//We will calculate the complement of random number added in both the products
	//In the later stage, we will just add(or multiply for homomorphic additive
	//encryption) E(-( a*r_2 + b*r_1 + r_1*r_2 )) in E( a*b + a*r_2 + b*r_1 + r_1*r_2 )
	//To get E(a*b), where, 'a' is the tfidf vector product, 'b' is the binary vector
	//product(co-ord factor)
	//'r_i' is the random number for i = 1,2.
	//This is basically an optimization step which we are computing early to avoid unnecessary
	//multiple file I/Os.
	//Assume cosine_result as E(a), co_ord_factor as E(b)
	//and random_no_1 as r_1, random_no_2 as r_2
	
	//Resetting to zero
	//Set the encrypted value of 0 to sum_neg_terms
	encrypt(sum_neg_terms, 0);	//sum_neg_terms = E(0)

	//Calculating E(a)^r_2 = E(a*r_2)
	
	mpz_powm(neg_term, cosine_result, random_no_2, n_square);

	//neg_term(E(a*r_2))*sum_neg_terms(E(0)) = E(0+a*r_2)
	mpz_mul(sum_neg_terms, sum_neg_terms, neg_term);
	mpz_mod(sum_neg_terms, sum_neg_terms, n_square);
	
	//Calculating E(b)^r_1 = E(b*r_1)
	
	mpz_powm(neg_term, co_ord_factor, random_no_1, n_square);
	
	//neg_term(E(b*r_1))*sum_neg_terms(E(a*r_2)) = E(a*r_2 + b*r_1)
	mpz_mul(sum_neg_terms, sum_neg_terms, neg_term);
	mpz_mod(sum_neg_terms, sum_neg_terms, n_square);

	//Calculating E(r_1 * r_2)
	
	//Calculating E(r_1)^r_2 = E(r_1*r_2)
	mpz_powm(rand_prod, encr_random_no_1, random_no_2, n_square);
	//Calculating neg_term = E(r_1 * r_2)
	mpz_set(neg_term, rand_prod);

	//neg_term(E(r_1 * r_2))*sum_neg_terms(E(a*r_2 + b*r_1)) = E(a*r_2 + b*r_1 + r_1*r_2)
	mpz_mul(sum_neg_terms, sum_neg_terms, neg_term);
	mpz_mod(sum_neg_terms, sum_neg_terms, n_square);
	
	//Calculating E(-(a*r_2 + b*r_1 + r_1*r_2))
	mpz_set(exponent, n);
	mpz_sub_ui(exponent, exponent, 1);//exponent=n_square-1
	mpz_powm(sum_neg_terms, sum_neg_terms, exponent, n_square);
	
	//Write the result E(-a*r_2 - b*r_1 - r_1*r_2)
	//to file so that it can be used in next phase
	mpz_out_str(output_file, 10, sum_neg_terms);
	
	//gmp_fprintf(stderr, "\n%s:%d:: De-randomizing factor: %Zd written"
	//" in file %s\n", __func__, __LINE__, sum_neg_terms, output_file_name);
	

	fclose(input_encr_tfidf_file);  
	fclose(input_encr_bin_file);  
	//fflush(input_tfidf_vec_file);
	fclose(input_tfidf_vec_file);
	//fflush(input_bin_vec_file);
	fclose(input_bin_vec_file);
	fflush(output_file);
	fclose(output_file);

	//release space used by big number variables
	//for (i = 0; i < vsizelocal; i++)
	mpz_clear(vec1);
	//for (i = 0; i < vsizelocal; i++)
	mpz_clear(vec2);


	mpz_clear(cosine_result);
	mpz_clear(co_ord_factor);
	mpz_clear(cosine_result_rand);
	mpz_clear(co_ord_factor_rand);
	mpz_clear(random_no_1);
	mpz_clear(random_no_2);
	mpz_clear(encr_random_no_1);
	mpz_clear(encr_random_no_2);
	mpz_clear(neg_term);
	mpz_clear(sum_neg_terms);
	mpz_clear(rand_prod);
	mpz_clear(exponent);
	mpz_clear(tfidf_row_corr);
	mpz_clear(bin_row_corr);
	mpz_clear(big_temp);
	mpz_clear(exp);
	clear();
	//free(vec1);
	//free(vec2);
	//free(p_tfidf_vec);
	//free(p_bin_vec);

	return 0;
}



//using the formula: y = (int){ (double)rand() / [ ( (double)RAND_MAX + (double)1 ) / M] }
//For y, if M is an integer then the result is between 0 and M-1 inclusive
//http://members.cox.net/srice1/random/crandom.html 
void gen_random_input(int v[], int size){

	int i, m = 2;

	srand(time(NULL));

	for(i = 0; i < size; i++) {
		v[i] = (int) ( (double)rand() / ( ( (double)RAND_MAX + (double)1 ) / m) );

		//printf("%d\n", v[i]);
	}
}

//assume c has been initialized
void encrypt(mpz_t c, int m){ 

	get_random_r();

	//set r^n mod n^2
	mpz_powm(r_pow_n, r, n, n_square);

	//set big_temp = (n+1)^m mod n^2
	mpz_powm_ui(big_temp, n_plus_1, m, n_square);

	//set c = (n+1)^m*r^n mod n^2
	mpz_mul(c, big_temp, r_pow_n);
	mpz_mod(c, c, n_square);
}

//assume c has been initialized
void encrypt_big_num(mpz_t c, mpz_t m){ 

	get_random_r();

	//set r^n mod n^2
	mpz_powm(r_pow_n, r, n, n_square);

	//set big_temp = (n+1)^m mod n^2
	mpz_powm(big_temp, n_plus_1, m, n_square);

	//set c = (n+1)^m*r^n mod n^2
	mpz_mul(c, big_temp, r_pow_n);
	mpz_mod(c, c, n_square);
}

void decrypt(mpz_t c){

	//set big_temp = c^d mod n^2
	mpz_powm(big_temp, c, d, n_square);

	//set big_temp = big_temp -1
	mpz_sub_ui(big_temp, big_temp, 1);

	//divide big_temp by n
	mpz_divexact(big_temp, big_temp, n);

	//d^-1 * big_temp
	mpz_mul(big_temp, d_inverse, big_temp);

	mpz_mod(c, big_temp, n);
}

//assume state has been initialized
void get_random_r(){

	do{
		mpz_urandomm(r, state, n);
	}while(mpz_cmp_ui(r, 0) == 0);
}


/* File should have keys in order of:
 * #1. p
 * #2. q
 * #3. n - We require n.
 * #4. n+1 (public key)
 * #5. d (private key) - We require d
 * These are seperated by a newline
 * */

int get_n_and_d_from_file()
{
	FILE *key_fp = NULL;
	int count=1, err=-1;
	mpz_t temp;

	mpz_init(temp);

	if ( (key_fp = fopen(g_key_file_name, "r"))==NULL )
	{
		fprintf(stderr, "File:%s for key not present", g_key_file_name);
		err = errno;
	}


	while ( mpz_inp_str(temp, key_fp, 10) != 0  )
	{
		//ignore p, q and n+1
		if ( count==3 )
		{
			// read n
			mpz_set(n, temp);
		}
		else if ( count==5 )
		{
			//read d
			mpz_set(d, temp);
		}
		count++;
	}

	mpz_clear(temp);
	if ( key_fp )
	{
		fclose(key_fp);
	}
	err = 0;
	return err;
}

/* File should have keys in order of:
 * #1. n - We require n.
 * These are seperated by a newline
 * */

int get_n_from_file()
{
	FILE *key_fp = NULL;
	int count=1, err=-1;
	mpz_t temp;

	mpz_init(temp);

	if ( (key_fp = fopen(g_key_file_name, "r"))==NULL )
	{
		fprintf(stderr, "File:%s for key not present", g_key_file_name);
		err = errno;
	}


	while ( mpz_inp_str(temp, key_fp, 10) != 0  )
	{
		//First line has n - public key
		if ( count==1 )
		{
			// read n
			mpz_set(n, temp);
			break;
		}
		count++;
	}

	mpz_clear(temp);
	if ( key_fp )
	{
		fclose(key_fp);
	}
	err = 0;
	return err;
}

int initialize_variables()
{
	mpz_init(big_temp);
	mpz_init(n);
	mpz_init(n_plus_1);
	mpz_init(n_minus_1);
	mpz_init(n_square);      
	mpz_init(r);
	mpz_init(r_pow_n);       
	gmp_randinit_default(state);
	gmp_randseed_ui(state, time(NULL));     
	return 0;
}

void clear_serv(){

	gmp_randclear(state);
	mpz_clear(big_temp);
	mpz_clear(n);
	mpz_clear(n_plus_1);
	mpz_clear(n_minus_1);
	mpz_clear(n_square);
	mpz_clear(r);
	mpz_clear(r_pow_n);

}

int compute_nplus1_nsquare()
{
	mpz_add_ui(n_plus_1, n, 1);
	mpz_pow_ui(n_square, n, 2);
	mpz_sub_ui(n_minus_1, n, 1);//SBD specific only
	return 0;
}

void init(){
	initialize_variables();
	mpz_init(d);             
	mpz_init(d_inverse);

#if 0

	//if (mpz_set_str(n, "179681631915977638526315179067310074434153390395025087607016290555239821629901731559598243352941859391381209211619271844002852733873844383750232911574662592776713675341534697696513241904324622555691981004726000585832862539270063589746625628692671893634789450932536008307903467370375372903436564465076676639793", 10) == -1) {
	if (mpz_set_str(n, "32317006071311007300714876688666765257611171752763855809160912665177570453236751584543954797165007338356871062761077928870875400023524429983317970103631801129940018920824479704435252236861111449159643484346382578371909996991024782612350354546687409434034812409194215016861565205286780300229046771688880430612167916071628041661162278649907703501859979953765149466990620201855101883306321620552981581118638956530490592258880907404676403950212619825592177687668726740525457667131084835164607889060249698382116887240122647424904709577375839097384133219410477128893432015573232511359202702215050502392962065602621373646633", 10) == -1) {
		printf("\n n = %s is invalid \n", n);
		exit(0);
	}
#endif

	// Get the values of n and d from already generated file
	get_n_and_d_from_file();
	//gmp_printf("n read = %Zd\n", n);
	//gmp_printf("d read = %Zd\n", d);
	compute_nplus1_nsquare();


	//d=lcm(p-1, q-1)
#if 0

	//if (mpz_set_str(d, "11230101994748602407894698691706879652134586899689067975438518159702488851868858222474890209558866211961325575726204490250178295867115273984389556973416410372977387708241492548657648934473794873887265114170151559636690542947614482279486573108720489183236783924737117351777821606184702946528449106783160617728", 10) == -1) {
	if (mpz_set_str(d, "16158503035655503650357438344333382628805585876381927904580456332588785226618375792271977398582503669178435531380538964435437700011762214991658985051815900564970009460412239852217626118430555724579821742173191289185954998495512391306175177273343704717017406204597107508430782602643390150114523385844440215305904188722327789239808208805874958140879652760769485822638556957710893419557319777578361302813366793271881989825323106333296234499565420424474500540721018071974424406358805685133447529623729447991492181271325655526833481571159446598626059774013428343748622306000136795074246791265885436988193283384961017822594", 10) == -1) {
		printf("\n d = %s is invalid \n", d);
		exit(0);
	}
#endif

	if (mpz_invert (d_inverse, d, n_square) == 0) {

		printf("\n%s\n", "d^-1 does not exist!");
		exit(0);
	}  


}

void init_serv(){
	initialize_variables();

#if 0

	//if (mpz_set_str(n, "179681631915977638526315179067310074434153390395025087607016290555239821629901731559598243352941859391381209211619271844002852733873844383750232911574662592776713675341534697696513241904324622555691981004726000585832862539270063589746625628692671893634789450932536008307903467370375372903436564465076676639793", 10) == -1) {
	if (mpz_set_str(n, "32317006071311007300714876688666765257611171752763855809160912665177570453236751584543954797165007338356871062761077928870875400023524429983317970103631801129940018920824479704435252236861111449159643484346382578371909996991024782612350354546687409434034812409194215016861565205286780300229046771688880430612167916071628041661162278649907703501859979953765149466990620201855101883306321620552981581118638956530490592258880907404676403950212619825592177687668726740525457667131084835164607889060249698382116887240122647424904709577375839097384133219410477128893432015573232511359202702215050502392962065602621373646633", 10) == -1) {
		printf("\n n = %s is invalid \n", n);
		exit(0);
	}
#endif

	// Get the values of n and d from already generated file
	get_n_from_file();
	//gmp_printf("n read = %Zd\n", n);
	//gmp_printf("d read = %Zd\n", d);
	compute_nplus1_nsquare();


	//d=lcm(p-1, q-1)
#if 0

	//if (mpz_set_str(d, "11230101994748602407894698691706879652134586899689067975438518159702488851868858222474890209558866211961325575726204490250178295867115273984389556973416410372977387708241492548657648934473794873887265114170151559636690542947614482279486573108720489183236783924737117351777821606184702946528449106783160617728", 10) == -1) {
	if (mpz_set_str(d, "16158503035655503650357438344333382628805585876381927904580456332588785226618375792271977398582503669178435531380538964435437700011762214991658985051815900564970009460412239852217626118430555724579821742173191289185954998495512391306175177273343704717017406204597107508430782602643390150114523385844440215305904188722327789239808208805874958140879652760769485822638556957710893419557319777578361302813366793271881989825323106333296234499565420424474500540721018071974424406358805685133447529623729447991492181271325655526833481571159446598626059774013428343748622306000136795074246791265885436988193283384961017822594", 10) == -1) {
		printf("\n d = %s is invalid \n", d);
		exit(0);
	}
#endif

}

void clear(){

	gmp_randclear(state);
	mpz_clear(big_temp);
	mpz_clear(n);
	mpz_clear(n_plus_1);
	mpz_clear(n_minus_1);
	mpz_clear(n_square);
	mpz_clear(r);
	mpz_clear(r_pow_n);
	mpz_clear(d);
	mpz_clear(d_inverse);

}

/*
 * Implementing second part of secure MP protocol. This function reads the input file containing the two encrypted products seperated by a newline, decrypts them, multiplies them and again encrypts their 
 * product and writes to the output file. If the other party has n documents in its collection, this should be called n times by the native Jav API i.e. this acts per remotely-based collection document.
 * */
int read_decrypt_mul_encrypt_write_encrypted_rand_prod( const char * input_interm_prods_file_name, const char * output_encrypt_rand_prod_file_name, const char * key_file_name)
{
	mpz_t tfidf_prod1;	//holds input randomized, encrypted tfidf vector products
	mpz_t coord_prod2;	//holds input randomized, encrypted binary vector products
	mpz_t out_enc_ran_prod;	//holds the encrypted product of tfidf_prod1, coord_prod2

	FILE *input_interm_prods_file=NULL, *output_encrypt_rand_prod_file=NULL;


	input_interm_prods_file = fopen(input_interm_prods_file_name, "r");
	output_encrypt_rand_prod_file = fopen(output_encrypt_rand_prod_file_name, "w");

	strncpy(g_key_file_name, key_file_name, sizeof(g_key_file_name));

	//Initialize
	mpz_init(tfidf_prod1);
	mpz_init(coord_prod2);

	mpz_init(out_enc_ran_prod);

	init();

	//variables are set to 0

	//init();



	//check if files are opened properly
	if (input_interm_prods_file == NULL) {
		fprintf(stderr, "Error: open %s!", input_interm_prods_file_name);
		return -2;
	}

	if (output_encrypt_rand_prod_file == NULL) {
		fprintf(stderr, "Error: open %s!", output_encrypt_rand_prod_file_name);
		return -2;
	}

	//Read the product values
	//File structure can be found in the Java function in which it is written i.e. 
	//<Class_name>:<function_name> :: DocSimSecApp:acceptIntermValues()
	gmp_fscanf(input_interm_prods_file, "%Zd", tfidf_prod1);
	gmp_fscanf(input_interm_prods_file, "%Zd\n", coord_prod2);

	//gmp_fprintf(stderr, "TFIDF Product read = %Zd\n\n", tfidf_prod1);
	//gmp_fprintf(stderr, "Co-ord Product read = %Zd\n\n", coord_prod2);

	//Decrypt both
	decrypt(tfidf_prod1);
	decrypt(coord_prod2);

	//gmp_fprintf(stderr, "After decrypting, TFIDF Product read = %Zd\n\n", tfidf_prod1);
	//gmp_fprintf(stderr, "After decrypting, Co-ord Product read = %Zd\n\n", coord_prod2);


	//Multiply both
	mpz_mul(out_enc_ran_prod, tfidf_prod1, coord_prod2);
	mpz_mod(out_enc_ran_prod, out_enc_ran_prod, n);
	
	//gmp_fprintf(stderr, "Unencrypted Product = %Zd\n\n", out_enc_ran_prod);

	//note obtained product is not encrypted, hence, encrypting it
	encrypt_big_num(out_enc_ran_prod, out_enc_ran_prod);
	//gmp_fprintf(stderr, "Encrypted Product = %Zd\n\n", out_enc_ran_prod);
	gmp_fprintf(output_encrypt_rand_prod_file, "%Zd", out_enc_ran_prod);

	fflush(output_encrypt_rand_prod_file);
	fclose(input_interm_prods_file);
	fclose(output_encrypt_rand_prod_file);


	mpz_clear(tfidf_prod1);
	mpz_clear(coord_prod2);
	mpz_clear(out_enc_ran_prod);
	clear();

	return 0;
}

/*
This function will generate random numbers between 0 to 2^{l-1}
and add them to the encrypted plaintext given its ciphertext using the 
additive homomorphic properties. Random values and randomized values
would be written to files indicated by random_f_name, randomized_f_name.
Inputs would be l (bound on number of bits, eg. l==64, generates
random number between 0 to 2^{62}-1, MSB bit is not utilized as addition operation
has to be performed in later stage) and encr_scores_ip_f_name, the file name containing
encrypted scores. n is the number of documents.
*/
int secure_threshold_randomize(int l, long n, char *encr_scores_ip_f_name, char *key_ip_f_name, char *random_op_f_name, char *randomized_op_f_name)
{
	int err	= 0;
	long i = 0;
	mpz_t encr_val, random_val, randomized, temp_val, temp_val2;

	if (   encr_scores_ip_f_name == NULL ||
		    random_op_f_name == NULL ||
		    key_ip_f_name == NULL ||
		randomized_op_f_name == NULL )
	{
		fprintf(stderr, "%s:%d: Error! Null parameter(s) passed!\nencr_scores_ip_f_name:%s, "
		"random_op_f_name:%s, randomized_op_f_name:%s, key_ip_f_name:%s\n", __func__, __LINE__, encr_scores_ip_f_name, random_op_f_name, randomized_op_f_name, key_ip_f_name);
		return -1;
	}
	FILE *fp_encr, *fp_rand, *fp_randomized;

	if ( ( fp_encr = fopen(encr_scores_ip_f_name, "r") ) == NULL )
	{
		fprintf(stderr, "%s:%d Error cannot open %s\n", __func__,
		__LINE__, encr_scores_ip_f_name);
		return -1;
	}

	if ( ( fp_rand = fopen(random_op_f_name, "w") ) == NULL )
	{
		fprintf(stderr, "%s:%d Error cannot open %s\n", __func__,
		__LINE__, random_op_f_name);
		return -2;
	}

	if ( ( fp_randomized = fopen(randomized_op_f_name, "w") ) == NULL )
	{
		fprintf(stderr, "%s:%d Error cannot open %s\n", __func__,
		__LINE__, randomized_op_f_name);
		return -3;
	}

	strncpy(g_key_file_name, key_ip_f_name, sizeof(g_key_file_name));
	init_serv();

	mpz_init(encr_val);
	mpz_init(random_val);
	mpz_init(randomized);
	mpz_init(temp_val);
	mpz_init(temp_val2);
	initialize_random_state_and_seed( state );
	while ( (i<n) && ( gmp_fscanf(fp_encr, "%Zu", &encr_val) != EOF ) )
	{
		gmp_fprintf(stdout, "Encrypted value read:%Zu\n", encr_val);
		generate_urandom_number((l-1), random_val);
		gmp_fprintf(stdout, "Random value(of max. bit size = %d):%Zu\n", (l-1), encr_val);
		//temp_val=E(r)
		encrypt_big_num(temp_val, random_val);

		//temp_val2=E(m+r)=E(m)E(r)
		mpz_mul(temp_val2, encr_val, temp_val);
		//take mod by N^{2}
		mpz_mod(temp_val, temp_val2, n_square);


		//Write the randomized value and the random value to files
		gmp_fprintf(fp_randomized, "%Zu\n", temp_val);
		gmp_fprintf(fp_rand, "%Zu\n", random_val);

		i++;
	}
	
	fclose(fp_encr);
	fclose(fp_rand);
	fclose(fp_randomized);
	mpz_clear(temp_val2);
	mpz_clear(temp_val);
	mpz_clear(encr_val);
	mpz_clear(random_val);
	mpz_clear(randomized);
	clear_serv();
	return err;
}

/*
 * This function will take the derandomizing encrypted factor, computed in the last phase and add(multiply for homomorphic additive property)
 * it to the encrypted, randomized similarity product obtained from peer. Input would be the file names containing these values.
 * derandomizing factor would be found on the fifth line and encrypted, randomized product on the one and only line in the file.
 * */
int derandomize_encrypted_sim_prod( const char * input_rand_encr_prod_file_name, const char * input_derand_file_name, const char * output_encrypted_sim_val_file_name, const char * key_file_name)
{
	int line_of_derand_factor = 5, i;
	mpz_t derandomize_fact;
	mpz_t encr_rand_prod;
	mpz_t temp;
	FILE *input_rand_encr_prod_file, *input_derand_file, *output_encrypted_sim_val_file;

	mpz_init(derandomize_fact);
	mpz_init(encr_rand_prod);
	mpz_init(temp);

	strncpy(g_key_file_name, key_file_name, sizeof(g_key_file_name));
	init_serv();

	input_rand_encr_prod_file = fopen(input_rand_encr_prod_file_name, 
	"r");

	input_derand_file = fopen(input_derand_file_name, "r");

	output_encrypted_sim_val_file = fopen(output_encrypted_sim_val_file_name, "w");

	if (input_rand_encr_prod_file == NULL) {
		fprintf(stderr, "Error: open %s!", input_rand_encr_prod_file_name);
		return -2;
	}

	if (input_derand_file == NULL) {
		fprintf(stderr, "Error: open %s!", input_derand_file_name);
		return -3;
	}

	if (output_encrypted_sim_val_file == NULL) {
		fprintf(stderr, "Error: open %s!", output_encrypted_sim_val_file_name);
		return -4;
	}
	gmp_fscanf(input_rand_encr_prod_file, "%Zd", &encr_rand_prod);
	int line_no = 1;
	for( (i=gmp_fscanf(input_derand_file,"%Zd", &temp)); i != EOF && line_no <= line_of_derand_factor; 
			gmp_fscanf(input_derand_file, "%Zd", &temp) ){

		if ( line_no == line_of_derand_factor)
		{
			mpz_set(derandomize_fact, temp);
		}
		line_no ++;
	}

	if ( line_no <= line_of_derand_factor )
	{
		fprintf(stderr, "\n%s:%d: ERROR!! Derandomizing factor not read!!\n", __func__, __LINE__);
		return -5;
	}
	//gmp_fprintf(stderr, "Derandomizing factor read: %Zd", derandomize_fact);
	//Calculate the E(a*b) by adding(multiplying) the numbers
	mpz_mul(temp, encr_rand_prod, derandomize_fact);
	mpz_mod(temp, temp, n_square);

	gmp_fprintf(output_encrypted_sim_val_file, "%Zd", temp);
	//gmp_fprintf(stderr, "\nEncrypted similarity = %Zd\n", temp);

	fflush(output_encrypted_sim_val_file);
	fclose(input_rand_encr_prod_file);
	fclose(input_derand_file);
	fclose(output_encrypted_sim_val_file);




	mpz_clear(derandomize_fact);
	mpz_clear(encr_rand_prod);
	mpz_clear(temp);
	clear_serv();
	return 0;
}

/*This function reads the file containing the oneline encrypted similarity score, decrypts and returns the score*/
double decrypt_sim_score(const char * input_encr_prod_file_name, const char * output_sim_score_file_name, const char * key_file_name)
{
	double val = -1;
	mpz_t encr_sim_score;
	mpz_t sim_score;

	FILE *input_file, *output_file;

	input_file = fopen(input_encr_prod_file_name, "r");
	output_file = fopen(output_sim_score_file_name, "w");



	mpz_init(encr_sim_score);
	mpz_init(sim_score);
	
	strncpy(g_key_file_name, key_file_name, sizeof(g_key_file_name));
	init();

	if (input_file == NULL) {
		fprintf(stderr, "Error: open %s!", input_encr_prod_file_name);
		return -3;
	}

	if (output_file == NULL) {
		fprintf(stderr, "Error: open %s!", output_sim_score_file_name);
		return -4;
	}

	gmp_fscanf(input_file, "%Zd", &encr_sim_score);
	//gmp_fprintf(stderr, "%s:%d: Encrypted Similarity Score read = %Zd\n", __func__, __LINE__, encr_sim_score);

	decrypt(encr_sim_score);

	gmp_fprintf(output_file, "%Zd", encr_sim_score);

	val = mpz_get_d(encr_sim_score);
	//gmp_fprintf(stderr, "%s:%d: Similarity Score Decrypted = %Zd; after double conversion: %lf\n", __func__, __LINE__, encr_sim_score, val);


	fflush(output_file);
	fclose(input_file);
	fclose(output_file);
	mpz_clear(encr_sim_score);
	mpz_clear(sim_score);
	return val;
	
}

int get_n_size_in_bits(long *n_bit_sz)
{
	char *n_in_str = NULL;
	
	n_in_str = malloc(MAX_DIGITS_IN_NO);
	if ( n_in_str == NULL )
	{
		return -1;
	}

	*n_bit_sz = gmp_sprintf(n_in_str, "%Zd", n);
	free(n_in_str);
	*n_bit_sz = ((double)((*n_bit_sz)))/((double)log10(2));
	(*n_bit_sz)++;
	return 0;
}

int reverse_file_line_by_line(char *file_name, char *working_dir)
{
	char *temp_file_name = "temp_rev.dat", *delimiter;
	char full_temp_file_name[1024];
	long file_sz, i, postn_last_no_found = -1;;
	FILE *fp_r, *fp_w;
	int err, cur_byte;
	mpz_t val;
	long num_read = 0, bytes_written = 0;

	memset(full_temp_file_name, 0, sizeof(full_temp_file_name));
	//printf("[%s] Calling append to store encr. dec. bits", argv[0]);//dbg
	strcpy(full_temp_file_name, working_dir);

	//printf("[%s] Calling append to store encr. dec. bits", argv[0]);//dbg
	if ( (err = append_file_name_to_directory(full_temp_file_name, sizeof(full_temp_file_name), temp_file_name)) != 0 )
	{
		fprintf(stderr, "%s:%d:: ERROR! appending err:%d\n", __func__, __LINE__, err);
		goto clean_up;
	}

	if ( (fp_r = fopen(file_name, "rb")) == NULL )
	{
		fprintf(stderr, "%s:%d:: Cannot open file for reading: %s", __func__, __LINE__, file_name);
		err = -1;
		goto clean_up;
	}
	if ( (fp_w = fopen(full_temp_file_name, "wb")) == NULL )
	{
		fprintf(stderr, "%s:%d:: Cannot open file for reading: %s", __func__, __LINE__, full_temp_file_name);
		err = -2;
		goto clean_up;
	}

	if ( (err = get_file_size(&file_sz, file_name)) != 0 )
	{
		fprintf(stderr, "%s:%d:: Cannot file size: %s", __func__, __LINE__, file_name);
		err = -3;
		goto clean_up;
	}

//	printf("Source file size:%ld\n", file_sz);//dbg

	//if ( (err = fseek(fp_r, -1, SEEK_END)) < 0 )
	//{
	//	fprintf(stderr, "%s:%d:: ERROR! Cannot fseek(), err:%d, errno:%d\n", err, errno);
	//	goto clean_up;
	//}
	//printf("ftell:%ld\n", ftell(fp_r));
	//int last_byte = fgetc(fp_r);
//	if ( last_byte == EOF )
//	{
//		printf("This is EOF:%d\n", last_byte);
//	}
//	else
//	{
//		printf("This is NOT EOF:%d\n", last_byte);
//	}

	mpz_init(val);
	num_read = 0;
	bytes_written = 0;
	i = 1;
	while( i<=file_sz )
	{
	//	if ( (err = fseek(fp_r, -i, SEEK_END)) < 0 )
	//	{
	//		fprintf(stderr, "%s:%d:: ERROR! Cannot fseek(), err:%d, errno:%d\n", err, errno);
	//		goto clean_up;
	//	}
		//pass the '\n's i.e. delimiter(s) 
		while ( (i<=file_sz) && 
			((err = fseek(fp_r, -i, SEEK_END)) >= 0) &&
			((cur_byte = fgetc(fp_r)) == '\n') )
		{
			i++;
		}
		if ( err < 0 )
		{
			fprintf(stderr, "%s:%d:: fseek() error! i:%d, err:%d, errno:%d\n", __func__, __LINE__, i, err, errno);
			goto clean_up;
		}
		
		//-i should now point to a non delimiter i.e. a number in this case
		//go to the start of this number i.e. unless you get a '\n' delimiter
		while ( (i<=file_sz) && 
			((err = fseek(fp_r, -i, SEEK_END)) >= 0) &&
			((cur_byte = fgetc(fp_r)) != '\n') )
		{
			i++;
			//if ( i == file_sz +1) //There is no '\n' at first location in file
			//{}
		}
		if ( err < 0 )
		{
			fprintf(stderr, "%s:%d:: fseek() error! i:%d, err:%d, errno:%d\n", __func__, __LINE__, i, err, errno);
			goto clean_up;
		}

		//i points to '\n' element
		if ( i <= file_sz )
		{
			//point it to the non '\n' element after the detected '\n'
			i--;
		}
		else if ( i == file_sz + 1 )
		{
			//special case, i points to imaginary location
			//printf("EOF (from beginning) detected at i:%d\n", i);//dbg
			i--;
		}

		if( i == postn_last_no_found )
		{
			//back to where we read the previous number
			fprintf(stderr, "ERROR! back to where we read the previous number\n");
			break;
		}
		if ( ((err = fseek(fp_r, -i, SEEK_END)) >= 0) && //Can be commented for optimization
			(err = gmp_fscanf(fp_r, "%Zd", val)) > 0 )
		{
			postn_last_no_found = i;
			if ( num_read != 0 )
			{
				delimiter = "\n";
			}
			else
			{
				delimiter = "";
			}

			if ( (err = gmp_fprintf(fp_w, "%s%Zd", delimiter, val)) < 0 )
			{
				fprintf(stderr, "%s:%d:: fprintf() error! i:%d, err:%d\n", __func__, __LINE__, i, err);
				goto clean_up;
			}
			bytes_written += err;
			num_read++;
			i++;//Important: to get to the preceeding number, currently points to non'\n' need to point to'\n' or first char
			//printf("Source file size:%ld, numbers found:%ld, bytes written:%ld, i:%ld\n\n", file_sz, num_read, bytes_written, i);
			if ( i == file_sz )
			{
				//we have read till the first number in a reverse order starting from number at end of file to number at the start
				break;
			}
		}
	}

//	printf("Reverse operation completed successfully\n"
//			"Source file size:%ld, numbers found:%ld, bytes written:%ld, i:%ld\n\n", file_sz, num_read, bytes_written, i);

	//rename the files such that original is replaced with newly reversed one
	if ( (rename( full_temp_file_name, file_name )) < 0 )
	{
		fprintf(stderr, "%s:%d:: ERROR! Cannot rename/replace the files! err:%d, errno:%d\n", __func__, __LINE__, err, errno);
		goto clean_up;
	}
	err = 0;
clean_up:

	if ( val )
	{
		mpz_clear(val);
	}
	if (fp_r)
		fclose(fp_r);
	if (fp_w)
		fclose(fp_w);
}

int send_mpz(mpz_t val, int socket)
{
	int err = 0, no_bytes;

	////debug - start here
	//FILE *fp = NULL;
	//if ( (fp = fopen("/home/nuplavikar/Downloads/deletethis/Y_Bob.dat", "a"))==NULL )
	//{
	//	fprintf(stderr, "%s:%d:: ERROR!!! Cannot open file! errno:%d\n", __func__, __LINE__, errno);
	//	goto clean_up;
	//}
	//if (  (err = gmp_fprintf(fp, "\n%Zd", val))<0)
	//{
	//	fprintf(stderr, "%s:%d:: ERROR!!! Cannot open file!\n", __func__, __LINE__);
	//	goto clean_up;
	//}
	//fclose(fp);
	////debug - end here

	if ( (no_bytes = gmp_snprintf(mpz_buffer, sizeof(mpz_buffer), "%Zd", val)) < 0)
	{
		fprintf(stderr, "%s:%d:: Error!!! snprintf():%d\n", __func__, __LINE__, no_bytes);
		err = no_bytes;
		goto clean_up;
	}
	if ( no_bytes >= sizeof(mpz_buffer) )
	{
		fprintf(stderr, "%s:%d:: Error!!! Overflow in gmp_snprintf():%d bytes to send, but can send:%d only!\n", __func__, __LINE__, no_bytes, sizeof(mpz_buffer));
		err = -1;
		goto clean_up;
	}

	//Also send the \0 byte
	no_bytes++;

	//send no_bytes to transfer
	if ( (err = send_long(socket, no_bytes)) != 0 )
	{
		fprintf(stderr, "%s:%d:: ERROR! err=%d\n", __func__, __LINE__, err);
		goto clean_up;
	}
	//send actual bytes
	if ( (err = send_bytes(socket, mpz_buffer, no_bytes)) != 0 )
	{
		fprintf(stderr, "%s:%d:: ERROR!!! Cannot send bytes, err:%d\n", __func__, __LINE__, err);
		goto clean_up;
	}

	err = 0;
clean_up:
	return err;
}

int recv_mpz(mpz_t val, int socket)
{
	int err = 0;
	long no_bytes;
	/*if ( (no_bytes = gmp_snprintf(mpz_buffer, sizeof(mpz_buffer), "%Zd", val)) < 0)
	{
		fprintf(stderr, "%s:%d:: Error!!! snprintf():%d\n", __func__, __LINE__, no_bytes);
		err = no_bytes;
		goto clean_up;
	}
	if ( no_bytes >= sizeof(mpz_buffer) )
	{
		fprintf(stderr, "%s:%d:: Error!!! Overflow in gmp_snprintf():%d bytes to send, but can send:%d only!\n", __func__, __LINE__, no_bytes, sizeof(mpz_buffer));
		err = -1;
		goto clean_up;
	}*/

	//Also send the \0 byte
	no_bytes++;

	//send no_bytes to transfer
	if ( (err = recv_long(socket, &no_bytes)) != 0 )
	{
		fprintf(stderr, "%s:%d:: ERROR! err=%d\n", __func__, __LINE__, err);
		goto clean_up;
	}
	//send actual bytes
	if ( (err = recv_bytes(socket, mpz_buffer, no_bytes)) != 0 )
	{
		fprintf(stderr, "%s:%d:: ERROR!!! Cannot send bytes, err:%d\n", __func__, __LINE__, err);
		goto clean_up;
	}
	mpz_set_str(val, mpz_buffer, 10);

//	//debug - start here
//	FILE *fp = NULL;
//	if ( (fp = fopen("/home/nuplavikar/Downloads/deletethis/Y_Alice.dat", "a"))==NULL )
//	{
//		fprintf(stderr, "%s:%d:: ERROR!!! Cannot open file! errno:%d\n", __func__, __LINE__, errno);
//		goto clean_up;
//	}
//	if (  (err = gmp_fprintf(fp, "\n%Zd", val))<0)
//	{
//		fprintf(stderr, "%s:%d:: ERROR!!! Cannot open file!\n", __func__, __LINE__);
//		goto clean_up;
//	}
//	fclose(fp);
//	//debug - end here


	err = 0;
clean_up:
	return err;
}

/*
Sets E(-1) as e_alpha if function cannot be evaluated, this should never happen ideally, expected E(1) or E(0).
Returns 0 on success and -ve on failure.
*/
int get_e_alpha_from_L_prime_contents(mpz_t e_alpha, char *source_file, long lines_exp)
{
	FILE *fp_s, *fp_d;
	int err = 0;
	long num_read = 0;
	mpz_t L_prime_i;
	int success_eval = 0;


	if ( (fp_s = fopen(source_file, "r"))==NULL )
	{
		fprintf(stderr, "%s:%d:: ERROR!!! Cannot open file:%s!\n", __func__, __LINE__, source_file);
		err = -1;
		goto clean_up;
	}

	if ( e_alpha == NULL )
	{
		fprintf(stderr, "%s:%d:: ERROR!!! Bad argument passed! e_alpha == NULL!\n", __func__, __LINE__);
		err = -3;
		goto clean_up;
	}
	mpz_init(L_prime_i);
	mpz_set_si(e_alpha, -1);//IMPORTANT: note the signed part
	encrypt_big_num(e_alpha, e_alpha);//IMP: E(-1)
	success_eval = 0;
	while ( (err = gmp_fscanf(fp_s, "%Zd\n", L_prime_i)) > 0 )
	{
		num_read++;
		//2.1
		decrypt(L_prime_i);
		//2.3.
		long L_prime_i_long = mpz_get_si (L_prime_i); 
		if ( (L_prime_i_long == 1) || (L_prime_i_long == 0) )
		{
			printf("[./s2] SUCCESS - found result at position(from left - 1, 2, ...):%ld!\n", num_read);//dbg
			//alpha <- M_i
			mpz_set_si(e_alpha, L_prime_i_long);
			//compute E(alpha)
			encrypt_big_num(e_alpha, e_alpha);
			//Evaluation succeeded
			success_eval = 1;
			break;//Able to successfully evaluate
		}

	}
	printf("[./s2] Total exp. numbers:%ld, numbers read:%ld, success in eval:%d!\n", lines_exp, num_read, success_eval);
	if ( success_eval != 1 )
	{
		fprintf(stderr, "%s:%d:: Cannot successfully find the output! No M_i == 0 OR 1, lines_exp:%ld, lines_eval:%ld\n", __func__, __LINE__, lines_exp, num_read);
		err = -5;
		goto clean_up;
	}
	err = 0;
clean_up:

	if ( L_prime_i )
	{
		mpz_clear(L_prime_i);
	}
	if ( fp_s )
	{
		fclose(fp_s);
	}
	return err;
}

int sc_optimized(mpz_t e_s, char *ip_encr_dec_bits_file_name, char *v_file_name, long max_no_bits, char *working_dir, int socket, roles role)
{
	int err = 0;
	FILE *fp_u, *fp_v, *fp_l;
	long i;
	char *l_prime_file_name;
	char l_prime_full_file_name[1024];
	mpz_t u_i;
	mpz_t e_0;
	mpz_t e_1;
	mpz_t W_i;
	mpz_t G_i;
	mpz_t temp;
	mpz_t H_i;
	mpz_t H_i_1;
	mpz_t K_i;
	mpz_t L_i;
	mpz_t e_alpha;
	char *delimiter;
	

	memset(l_prime_full_file_name, 0, sizeof(l_prime_full_file_name));
	strcpy(l_prime_full_file_name, working_dir);

	if ( role == BOB )
	{
		long v_i;
		
		if ( (err = append_file_name_to_directory(l_prime_full_file_name, sizeof(l_prime_full_file_name), L_PRIME_F_NAME)) != 0 )
		{
			fprintf(stderr, "%s:%d:: ERROR! appending err:%d\n", __func__, __LINE__, err);
			goto clean_up;
		}
		mpz_init(u_i);
		mpz_init(e_0);
		mpz_init(e_1);
		mpz_init(W_i);
		mpz_init(G_i);
		mpz_init(temp);
		mpz_init(H_i);
		mpz_init(H_i_1);
		mpz_init(K_i);
		mpz_init(L_i);
		//s1
		if ( (fp_u = fopen(ip_encr_dec_bits_file_name, "r"))==NULL )
		{
			fprintf(stderr, "%s:%d:: ERROR!!! Cannot open file:%s!", __func__, __LINE__, ip_encr_dec_bits_file_name);
			err = -1;
			goto clean_up;
		}

		if ( (fp_v = fopen(v_file_name, "r"))==NULL )
		{
			fprintf(stderr, "%s:%d:: ERROR!!! Cannot open file:%s!", __func__, __LINE__, v_file_name);
			err = -2;
			goto clean_up;
		}

		if ( (fp_l = fopen(l_prime_full_file_name, "w"))==NULL )
		{
			fprintf(stderr, "%s:%d:: ERROR!!! Cannot open file:%s!", __func__, __LINE__, l_prime_full_file_name);
			err = -3;
			goto clean_up;
		}

		//1.1. Randomly choose F from {0, 1}
		srand(time(NULL));
		int F = ((int)rand()) % 2;
		printf("[./s0] F:%d\n", F);//dbg

		//fprintf(stderr, "%s:%d HERE!\n", __func__, __LINE__);

		//1.2
		for ( i = 1; i <= max_no_bits; i++ )
		{
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
			//read [u_i]
			if ( (err = gmp_fscanf(fp_u, "%Zd\n", u_i)) <= 0 )
			{
				fprintf(stderr, "%s:%d:: ERROR!!! Cannot read file:%s! i:%ld, err:%d, errno:%d", __func__, __LINE__, ip_encr_dec_bits_file_name, i, err, errno);
				goto clean_up;
			}
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
			//read v_i
			if ( (err = fscanf(fp_v, "%d\n", &v_i)) <= 0 )
			{
				fprintf(stderr, "%s:%d:: ERROR!!! Cannot read file:%s! i:%ld, err:%d, errno:%d", __func__, __LINE__, v_file_name, i, err, errno);
				goto clean_up;
			}
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
			//debug - start
			//if ( (i==1) || (i==(max_no_bits-1)) || (i==max_no_bits) )
			//{
			//	gmp_printf("%Zd\n%d\n\n", u_i, v_i);
			//}
			//debug - stop
			
			//1.2.a
			if (v_i == 0)
			{
				//1.2.a.i - TODO remove E_{pu}(u_i * v_i) <- E_{pu}(0) reference from paper
				//1.2.a.ii.
				if ( F == 0 )
				{
					//1.2.a.ii.A.
					mpz_set(W_i, u_i);
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
				}
				else
				{
					//1.2.a.iii.A
					//compute W_i<-E(0)
					encrypt(W_i, 0);
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
				}
				//1.2.a.iv.
				mpz_set(G_i, u_i);
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
			}
			else
			{
				//v_i == 1
				if ( F == 0 )
				{
					//1.2.b.ii.A.
					//W_i <- E(0)
					encrypt(W_i, 0);
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
				}
				else
				{
					//1.2.b.iii.A
					//compute W_i<-E(1)*E(u_i)^{N-1}
					//compute temp<-inv(u_i)
					mpz_powm(temp, u_i, n_minus_1, n_square);
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
					//compute E(1)
					encrypt(e_1, 1);
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
					//compute W_i
					prod_cipher_paillier(W_i, e_1, temp);//mod n_square taken care of
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
				}
				//1.2.b.iv.
				//compute G_i
				//get E(1)
				encrypt(e_1, 1);
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
				//compute temp<-inv(u_i)
				mpz_powm(temp, u_i, n_minus_1, n_square);
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
				//compute G_i
				prod_cipher_paillier(G_i, e_1, temp);//mod n_square taken care of
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
			}

			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
			//1.2.c. Compute H_i
			if ( i == 1 )
			{
				//H_0 == E(0)
				encrypt(H_i_1, 0);
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
			}
			//r<-random in Z_n
			get_random_r();
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
			//comp H_i <- H_i_1^r
			mpz_powm(H_i, H_i_1, r, n_square);
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
			//comp H_i <- H_i_1^r * G_i
			prod_cipher_paillier(H_i, H_i, G_i);
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
			//compute H_i_1 as H_i for next iteration
			mpz_set(H_i_1, H_i);
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg

			//1.2.d. 
			//compute temp <- -1
			mpz_set_si(temp, -1);//NOTE TODO: note the si i.e. signed int and not ui i.e. unsigned int
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
			//compute temp <- -1 mod n i.e. -1 in Z_n
			mpz_mod(temp, temp, n);
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
			//compute temp <- E(-1)
			encrypt_big_num(temp, temp);
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
			//compute kappa_i <- E(-1)*H_i
			prod_cipher_paillier(K_i, temp, H_i);//mod n^2 handled by func.
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg

			//1.2.e.
			//compute L_i
			prod_cipher_paillier(L_i, W_i, K_i);//mod n^2 handled by func.
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg

			//TODO: write L_i to file
			if ( i != 1 )
			{
				delimiter = "\n";
			}
			else
			{
				//i==1
				delimiter = "";
			}
			if ( (err = gmp_fprintf(fp_l, "%s%Zd", delimiter, L_i))<0 )
			{
				fprintf(stderr, "%s:%d ERROR!!! Cannot write to file:%s! i:%ld\n", __func__, __LINE__, l_prime_full_file_name, i);
				goto clean_up;
			}


			//debug - start - check if there is a 0 or 1 for L_i
			mpz_set(temp, L_i);
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
			decrypt(temp);
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
			long int L_i_decr = mpz_get_si(temp);
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
			if ( (L_i_decr == 0) || (L_i_decr == 1) )
			{
				printf("[./s1] SUCCESS - FOUND!!! L_i_decr:%ld at i:%ld\n", L_i_decr, i);
			//fprintf(stderr, "%s:%d HERE! i:%ld\n", __func__, __LINE__, i);//dbg
			}
			//debug - stop - check if there is a 0 or 1 for L_i
			
		}
		//close the file to send
		fclose(fp_l);
		fp_l = NULL;
		//TODO: Add code to shift the Ls in file -START
		//TODO: Add code to shift the Ls in file -STOP

		//Send service request to S2 to be ready to accept L_prime file and execute step 2
		if ( (err = send_service_reqs(socket, OSC)) != 0 )
		{
			fprintf(stderr, "%s:%d:: ERROR! Bob Cannot send service req.s! err = %d\n", err);
			goto clean_up;
		}

		if ( (err = send_long(socket, max_no_bits)) != 0 )
		{
			fprintf(stderr, "%s:%d:: ERROR! Bob Cannot send max_no_bits:%lu as long! err = %d\n", max_no_bits, err);
			goto clean_up;
		}

		if ( (err = send_file(socket, l_prime_full_file_name, "./s1")) != 0 )
		{
			fprintf(stderr, "%s:%d:: ERROR! Cannot send file:%s!\n", __func__, __LINE__, l_prime_full_file_name);
			goto clean_up;
		}


		//fprintf(stderr, "%s:%d HERE!\n", __func__, __LINE__);

	}
	else if ( role == ALICE )
	{
		//s2


		mpz_init(e_alpha);
		if ( (err = append_file_name_to_directory(l_prime_full_file_name, sizeof(l_prime_full_file_name), L_PRIME_RECVD_F_NAME)) != 0 )
		{
			fprintf(stderr, "%s:%d:: ERROR! appending err:%d\n", __func__, __LINE__, err);
			goto clean_up;
		}

		if ( (err = recv_long(socket, &max_no_bits)) != 0 )
		{
			fprintf(stderr, "%s:%d:: ERROR! Alice Cannot receive max_no_bits as long! err = %d\n", err);
			goto clean_up;
		}

		if ( (err = recv_file(socket, l_prime_full_file_name, "./s2")) != 0 )
		{
			fprintf(stderr, "%s:%d:: ERROR! Cannot receive file:%s!\n", __func__, __LINE__, l_prime_full_file_name);
			goto clean_up;
		}

		if ( (err = get_e_alpha_from_L_prime_contents(e_alpha, l_prime_full_file_name, max_no_bits)) != 0 )
		{
			fprintf(stderr, "%s:%d:: ERROR! Unsuccessful evaluation: get_e_alpha_from_L_prime_contents(), err:%d!\n", __func__, __LINE__, err);
			goto clean_up;
		}

		
		printf("[./s2] max_no_bits:%ld\n", max_no_bits);

	}
	err = 0;
		//fprintf(stderr, "%s:%d HERE!\n", __func__, __LINE__);
clean_up:

		//fprintf(stderr, "%s:%d HERE!\n", __func__, __LINE__);
	if ( role == BOB )
	{
		if ( u_i )
		{
			mpz_clear(u_i);
		}
		if ( e_0 )
		{
			mpz_clear(e_0);
		}
		if ( e_1 )
		{
			mpz_clear(e_1);
		}
		if ( W_i )
		{
			mpz_clear(W_i);
		}
		if ( G_i )
		{
			mpz_clear(G_i);
		}
		if ( H_i )
		{
			mpz_clear(H_i);
		}
		if ( H_i_1 )
		{
			mpz_clear(H_i_1);
		}
		if ( K_i )
		{
			mpz_clear(K_i);
		}
		if ( L_i )
		{
			mpz_clear(L_i);
		}
		if ( temp )
		{
			mpz_clear(temp);
		}
		if ( fp_u )
		{
			fclose(fp_u);
		}
		if ( fp_v )
		{
			fclose(fp_v);
		}
		if ( fp_l )
		{
			fclose(fp_l);
		}
	}
	else if ( role == ALICE )
	{
		if ( e_alpha )
		{
			mpz_clear(e_alpha);
		}
		
	}
	return err;
}
/*
Alice role = 0,
Bob role = 1
*/
int encrypted_lsb( mpz_t e_x_i, mpz_t T, long i, roles role, int socket )
{
	int err = 0;
	mpz_t rand, Y, e_rand, alpha;

	mpz_init(Y);
	mpz_init(alpha);
	if ( role == ALICE )
	{

		//2.a. - Accept Y from S1/BOB
		if ( (err = recv_mpz(Y, socket)) != 0 )
		{
			fprintf(stderr, "%s:%d:: ERROR! ALICE Cannot receive Y! err = %d\n", err);
			goto clean_up;
		}
		//printf("[./s2] Accepted Y from S1/BOB!\n");dbg

		//2.b. - Y <- D(Y)
		decrypt(Y);
		//printf("[./s2] Decrypted Y!\n");dbg

		//2.c. - Calculate alpha
		mpz_mod_ui(Y, Y, 2);
		if ( mpz_get_ui(Y) == 0 )
		{
			//even
			encrypt(alpha, 0);
		}
		else
		{
			//odd
			encrypt(alpha, 1);
		}

		//2.d - Send alpha to S1/Bob
		if ( (err = send_mpz(alpha, socket)) != 0 )
		{
			fprintf(stderr, "%s:%d:: ERROR! ALICE Cannot send alpha! err = %d\n", err);
			goto clean_up;
		}

	}
	else if ( role == BOB )
	{
		mpz_init(rand);
		mpz_init(e_rand);

		//1.a. Compute Y<-T*E(r) mod N^2, r in Z_N
		//get r
		get_random_r_given_modulo(rand, n);
		//get E(r)
		encrypt_big_num(e_rand, rand);
		//compute Y
		prod_cipher_paillier(Y, T, e_rand);//mod N^2 done in this func.
		//send request to S2 to start the protocol of encrypted_lsb
		//on its end, so that he can be ready when we send Y
		if ( (err = send_service_reqs(socket, ENC_LSB)) != 0 )
		{
			fprintf(stderr, "%s:%d:: ERROR! Bob Cannot send service req.s! err = %d\n", err);
			goto clean_up;
		}
		//printf("[./s1] sent the sevice req. %ld err:%d\n", i, err);//DBG
		//Send Y to S2/ALICE
		if ( (err = send_mpz(Y, socket)) != 0 )
		{
			fprintf(stderr, "%s:%d:: ERROR! Bob Cannot send Y! err = %d\n", err);
			goto clean_up;
		}
		//printf("[./s1] sent the Y %ld err:%d\n", i, err);//DBG
		//3.a. Receive alpha from S2/Alice
		if ( (err = recv_mpz(alpha, socket)) != 0 )
		{
			fprintf(stderr, "%s:%d:: ERROR! Bob Cannot receive alpha! err = %d\n", err);
			goto clean_up;
		}

		//3.b. compute E(x_i) i.e. e_x_i
		//Obtain r <- r % 2 to know if odd or even
		mpz_mod_ui(rand, rand, 2);
		unsigned long remainder = mpz_get_ui(rand);
		if ( remainder == 0 )
		{
			//even
			mpz_set(e_x_i, alpha);
		}
		else
		{
			//odd
			//compute E(x_i)<-E(1)*alpha^{N-1} mod N^2
			mpz_t e_one;
			mpz_init(e_one);

			//compute E(1)
			encrypt(e_one, 1);
			//compute alpha^{N-1} i.e. get encr. for flipped bit
			//of plaintext stored in alpha by S2/Alice
			//cal. alpha^{N-1} mod N^2
			mpz_powm(alpha, alpha, n_minus_1, n_square);
			//compute E(1)*alpha^{N-1} mod N^2
			prod_cipher_paillier(e_x_i, e_one, alpha);//mod with n_square included

			mpz_clear(e_one);

		}

	}
	else
	{
		fprintf(stderr, "%s:%d:: ERROR! Invalid role provided role:%d, expected"
		" ALICE:%d or BOB:%d\n", __func__, __LINE__, role, ALICE, BOB);
		return -1;
	}


	err = 0;
clean_up:

	if ( Y )
	{
		mpz_clear(Y);
	}
	if ( alpha )
	{
		mpz_clear(alpha);
	}
	if ( role == BOB )
	{
		if ( rand )
		{
			mpz_clear(rand);
		}
		if ( e_rand )
		{
			mpz_clear(e_rand);
		}
	}
	else if ( role == ALICE )
	{
	}
	return err;
}

int sbd( char *op_encr_dec_bits_file_name, mpz_t e_x, long m/*max. no. of bits*/, int socket )
{
	int err = 0;
	long i;
	mpz_t l;
	mpz_t T;
	mpz_t e_x_i;
	mpz_t Z;
	//mpz_t temp;//dbg
	FILE *fp = NULL;
	char *delimiter;

	if ( (fp = fopen(op_encr_dec_bits_file_name, "w")) == NULL )
	{
		fprintf(stderr, "%s:%d:: ERROR! Cannot open file: %s!\n", __func__, __LINE__, op_encr_dec_bits_file_name);
		err = -1;
		goto clean_up;
	}

	mpz_init(Z);
	//mpz_init(temp);//dbg
	//1: calculate 2^{-1}mod N
	mpz_init_set_ui(l, 2);
	mpz_invert(l, l, n);
	//2: initialize T
	mpz_init_set(T, e_x);

	//3: for loop
	mpz_init(e_x_i);

	//if ( (err = send_service_reqs(socket, ENC_LSB)) != 0 )
	//{
	//	fprintf(stderr, "%s:%d:: ERROR! Cannot send service req.s! err = %d\n", err);
	//	goto clean_up;
	//}

	//if ( (err = send_service_reqs(socket, TERMINATE)) != 0 )
	//{
	//	fprintf(stderr, "%s:%d:: ERROR! Cannot send service req.s! err = %d\n", err);
	//	goto clean_up;
	//}
	//printf("[./s1] e_x:31 rev. bin.: ");//dbg
	for ( i=0; i<m; i++ )
	{
		if ( (err = encrypted_lsb(e_x_i, T, i, BOB, socket))!=0 )
		{
			fprintf(stderr, "%s:%d:: encrypted_lsb errored: %d\n",
			__func__, __LINE__, err);
			goto clean_up;
		}
		//debug - start
		//mpz_set(temp, e_x_i);
		//decrypt(temp);
		//gmp_printf("%Zd", temp);
		//debug - stop
		//write the encrypted decomposed (l-i) th bit of 
		if ( i != (m-1) )
		{
			delimiter = "\n";
		}
		else
		{
			delimiter = "";
		}
		if ( (err = gmp_fprintf(fp, "%Zd%s", e_x_i, delimiter)) < 0 )
		{
			fprintf(stderr, "%s:%d:: gmp_fprintf() errored: %d\n", 
			__func__, __LINE__, err);
			goto clean_up;
		}

		//5. Compute Z <- T*E(x_i)^{N-1} mod N^2
		//Compute e_x_i <- e_x_i^{N-1} mod N^2
		mpz_powm(e_x_i, e_x_i, n_minus_1, n_square);
		//Compute Z <- T*e_x_i mod N^2
		prod_cipher_paillier(Z, T, e_x_i);//mod N^2 take care of

		//6. Compute T <- Z^l mod N^2
		mpz_powm(T, Z, l, n_square);
	}
	printf("\n");//dbg
	

	
	err = 0;
clean_up:
	if ( fp )
	{
		fclose(fp);
	}
	if ( l )
	{
		mpz_clear(l);
	}
	if ( T )
	{
		mpz_clear(T);
	}
	if ( e_x_i )
	{
		mpz_clear(e_x_i);
	}
	if ( Z )
	{
		mpz_clear(Z);
	}
	//if ( temp )
	//{
	//	mpz_clear(temp);
	//}
	return err;
}


#if 0

	JNIEXPORT jint JNICALL Java_preprocess_EncryptNativeC_encrypt_1vec_1to_1file
(JNIEnv *env, jobject obj, jint vsize, jstring input_file_name, jstring output_encr_file_name, jstring name_key_file)
{
	int err = -1;
	const char *ip_file_name = (*env)->GetStringUTFChars(env, input_file_name, 0);
	const char *op_file_name = (*env)->GetStringUTFChars(env, output_encr_file_name, 0);
	const char *key_file_name = (*env)->GetStringUTFChars(env, name_key_file, 0);


	//printf("Number of dimensions:%d\n", vsize);
	//printf("Query's Un-Encrypted vectors stored at: %s\n", ip_file_name);
	//printf("Query's Encrypted vectors stored at: %s\n", op_file_name);
	//printf("Key file used from : %s\n", key_file_name);


	//err = encrypt_vec_to_file(vsize, ip_file_name, op_file_name, key_file_name);
	err = encrypt_vec_to_file_mem_opt(vsize, ip_file_name, op_file_name, key_file_name);

	(*env)->ReleaseStringUTFChars(env, input_file_name, ip_file_name);
	(*env)->ReleaseStringUTFChars(env, output_encr_file_name, op_file_name);
	(*env)->ReleaseStringUTFChars(env, name_key_file, key_file_name);

	return err;
}

/*
 * Class:     preprocess_EncryptNativeC
 * Method:    read_encrypt_vec_from_file_comp_inter_sec_prod
 * Signature: (ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I
 */

	JNIEXPORT jint JNICALL Java_preprocess_EncryptNativeC_read_1encrypt_1vec_1from_1file_1comp_1inter_1sec_1prod
(JNIEnv *env, jobject obj, jint vsize, jstring ip_encr_tfidf_f_name, jstring ip_encr_bin_f_name, jstring ip_unencr_tfidf_f_name, jstring ip_unencr_bin_f_name, jstring op_encr_rand_inter_prod_f_name, jstring ip_key_f_name, jstring tfidf_row_corr, jstring bin_row_corr)
{
	int err = -1;
	const char *ip_encr_tfidf_q_file 			= (*env)->GetStringUTFChars(env, ip_encr_tfidf_f_name, 0);
	const char *ip_encr_bin_q_file 			= (*env)->GetStringUTFChars(env, ip_encr_bin_f_name, 0);
	const char *ip_unencr_tfidf_file 		= (*env)->GetStringUTFChars(env, ip_unencr_tfidf_f_name, 0);
	const char *ip_unencr_bin_file 			= (*env)->GetStringUTFChars(env, ip_unencr_bin_f_name, 0);
	const char *op_encr_rand_inter_prod_file 	= (*env)->GetStringUTFChars(env, op_encr_rand_inter_prod_f_name, 0);
	const char *key_file_name 			= (*env)->GetStringUTFChars(env, ip_key_f_name, 0);
	const char *tfidf_row_corr_str 			= (*env)->GetStringUTFChars(env, tfidf_row_corr, 0);
	const char *bin_row_corr_str 			= (*env)->GetStringUTFChars(env, bin_row_corr, 0);


	//printf("Number of dimensions:%d\n", vsize);
	//printf("Query's Encrypted TFIDF vector obtained from client stored at: %s\n", ip_encr_tfidf_q_file);
	//printf("Query's Encrypted binary vector obtained from client stored at: %s\n", ip_encr_bin_q_file);
	//printf("Collection document's unencrypted, scaled tfidf vector stored at: %s\n", ip_unencr_tfidf_file);
	//printf("Collection document's unencrypted, scaled binary vector stored at: %s\n", ip_unencr_bin_file);
	//printf("Output: random nos., encrypted intermediate dot products stored at: %s\n", op_encr_rand_inter_prod_file);
	//printf("Key file used from : %s\n", key_file_name);


	//Call the function here
	//err = read_encrypt_vec_from_file_comp_inter_sec_prod(vsize, ip_encr_tfidf_q_file, ip_encr_bin_q_file, ip_unencr_tfidf_file, ip_unencr_bin_file, op_encr_rand_inter_prod_file, key_file_name, tfidf_row_corr_str, bin_row_corr_str);
	err = read_encrypt_vec_from_file_comp_inter_sec_prod_mem_opt(vsize, ip_encr_tfidf_q_file, ip_encr_bin_q_file, ip_unencr_tfidf_file, ip_unencr_bin_file, op_encr_rand_inter_prod_file, key_file_name, tfidf_row_corr_str, bin_row_corr_str);


	(*env)->ReleaseStringUTFChars(env, ip_encr_tfidf_f_name, ip_encr_tfidf_q_file);
	(*env)->ReleaseStringUTFChars(env, ip_encr_bin_f_name, ip_encr_bin_q_file);
	(*env)->ReleaseStringUTFChars(env, ip_unencr_tfidf_f_name, ip_unencr_tfidf_file);
	(*env)->ReleaseStringUTFChars(env, ip_unencr_bin_f_name, ip_unencr_bin_file);
	(*env)->ReleaseStringUTFChars(env, op_encr_rand_inter_prod_f_name, op_encr_rand_inter_prod_file);
	(*env)->ReleaseStringUTFChars(env, ip_key_f_name, key_file_name);
	(*env)->ReleaseStringUTFChars(env, tfidf_row_corr, tfidf_row_corr_str);
	(*env)->ReleaseStringUTFChars(env, bin_row_corr, bin_row_corr_str);

	return err;
}

JNIEXPORT jint JNICALL Java_preprocess_EncryptNativeC_read_1decrypt_1mul_1encrypt_1write_1encrypted_1rand_1prod
  (JNIEnv *env, jobject obj, jstring ip_two_prods_file_name, jstring op_encr_rand_product_file_name, jstring ip_key_file_name)
  {
  	int err = -1;
	const char *ip_two_prods_file 				= (*env)->GetStringUTFChars(env, ip_two_prods_file_name, 0);
	const char *op_encr_rand_product_file 			= (*env)->GetStringUTFChars(env, op_encr_rand_product_file_name, 0);
	const char *key_file                       		= (*env)->GetStringUTFChars(env, ip_key_file_name, 0);
	
	
	err = read_decrypt_mul_encrypt_write_encrypted_rand_prod( ip_two_prods_file, op_encr_rand_product_file, key_file);
	
	(*env)->ReleaseStringUTFChars(env, ip_two_prods_file_name, ip_two_prods_file);
	(*env)->ReleaseStringUTFChars(env, op_encr_rand_product_file_name, op_encr_rand_product_file);
	(*env)->ReleaseStringUTFChars(env, ip_key_file_name, key_file);
	return err;
  }

JNIEXPORT jint JNICALL Java_preprocess_EncryptNativeC_derandomize_1encr_1encr_1sim_1prod
  (JNIEnv *env, jobject obj, jstring input_rand_encr_prod_file_name, jstring input_derand_file_name, jstring output_encrypted_sim_val_file_name, jstring key_file_name)
  {
  	int err = -1;
	const char *input_rand_encr_prod_file		= (*env)->GetStringUTFChars(env, input_rand_encr_prod_file_name, 0);
	const char *input_derand_file 			= (*env)->GetStringUTFChars(env, input_derand_file_name, 0);
	const char *output_encrypted_sim_val_file	= (*env)->GetStringUTFChars(env, output_encrypted_sim_val_file_name, 0);
	const char *key_file                       	= (*env)->GetStringUTFChars(env, key_file_name, 0);

	err = derandomize_encrypted_sim_prod( input_rand_encr_prod_file, input_derand_file, output_encrypted_sim_val_file, key_file );

	(*env)->ReleaseStringUTFChars(env, input_rand_encr_prod_file_name, input_rand_encr_prod_file);
	(*env)->ReleaseStringUTFChars(env, input_derand_file_name, input_derand_file);
	(*env)->ReleaseStringUTFChars(env, output_encrypted_sim_val_file_name, output_encrypted_sim_val_file);
	(*env)->ReleaseStringUTFChars(env, key_file_name, key_file);

	return err;
  }

JNIEXPORT jdouble JNICALL Java_preprocess_EncryptNativeC_decrypt_1sim_1score
  (JNIEnv *env, jobject obj, jstring input_encr_prod_file_name, jstring output_sim_score_file_name, jstring key_file_name)
  {
  	double err = -1;

	const char *input_encr_prod_file		= (*env)->GetStringUTFChars(env, input_encr_prod_file_name, 0);
	const char *output_sim_score_file		= (*env)->GetStringUTFChars(env, output_sim_score_file_name, 0);
	const char *key_file                       	= (*env)->GetStringUTFChars(env, key_file_name, 0);

	err = decrypt_sim_score(input_encr_prod_file, output_sim_score_file, key_file);

	(*env)->ReleaseStringUTFChars(env, input_encr_prod_file_name, input_encr_prod_file);
	(*env)->ReleaseStringUTFChars(env, output_sim_score_file_name, output_sim_score_file);
	(*env)->ReleaseStringUTFChars(env, key_file_name, key_file);
	return err;
  }

JNIEXPORT jint JNICALL Java_preprocess_EncryptNativeC_test_func
  (JNIEnv *env, jobject obj, jint test_no)
  {
  	double err = -1;

	mpz_t a;
	mpz_init(a);

	mpz_set_ui(a, test_no);
	printf("\nWorking! Test number: %d\n", test_no);
	gmp_printf("\nWorking! Big number: %Zd\n", a);
	mpz_clear(a);
	err = 0;


	return err;
  }
#endif
