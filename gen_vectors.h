#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/time.h>
#include<sys/stat.h>
#include<gmp.h>

#define MAX_FILE_NAME_LEN 256
const char PathSeparator =
#ifdef _WIN32
'\\';
#else
'/';
#endif

gmp_randstate_t state;
int state_initialized = 0;

int print_help( char *prog_name );
int initialize_random_state_and_seed(gmp_randstate_t state);
int generate_random_number( int k, mpz_t random_no );
int clear_random_state( gmp_randstate_t state );
int write_random_values_to_file(char *output_file_name, int no_bits, int no_dims);
int generate_urandom_number( int k, mpz_t random_no );

int initialize_random_state_and_seed(gmp_randstate_t state)
{
	if ( state_initialized != 0 )
	{
		//already initialized
		return 0;
	}
	
	gmp_randinit_mt( state );
#if DBG
	fprintf(stdout, "%s:%d:: Should be called just once! state:%p\n", __func__, __LINE__, state);
#endif /*DBG*/

	struct timeval tv;
	gettimeofday(&tv, NULL);
	unsigned long long millisecondsSinceEpoch =
		(unsigned long long)(tv.tv_sec) * 1000 +
		(unsigned long long)(tv.tv_usec) / 1000;

	gmp_randseed_ui( state, (long) millisecondsSinceEpoch );
	state_initialized = 1;
	return 0;
}

int generate_random_number( int k, mpz_t random_no )
{
	if ( k <= 0 )
	{
		fprintf(stderr, "k:%d\n", k);
		return -1;
	}
	
	if ( random_no == NULL )
	{
		fprintf(stderr, "Bad arg. random_no:NULL\n");
		return -2;
	}

#if DBG
	fprintf(stdout, "%s:%d:: Debug! state:%p\n", __func__, __LINE__, state);
#endif /*DBG*/
	if ( state_initialized == 0 )
	{
#if DBG
		fprintf(stdout, "%s:%d:: Debug! state:%p\n", __func__, __LINE__, state);
#endif /*DBG*/
		initialize_random_state_and_seed(state);
#if DBG
		fprintf(stdout, "%s:%d:: Debug! state:%p\n", __func__, __LINE__, state);
#endif /*DBG*/
	}
#if DBG
	fprintf(stdout, "%s:%d:: Debug! state:%p, random_no:%p\n", __func__, __LINE__, state, random_no);
#endif /*DBG*/

	mpz_rrandomb( random_no, state, k );
#if DBG
	fprintf(stdout, "%s:%d:: Debug! state:%p\n", __func__, __LINE__, state);
#endif /*DBG*/

		return 0;
}

/*
Generates random number between 0 to 2^{k}-1
*/
int generate_urandom_number( int k, mpz_t random_no )
{
	if ( k <= 0 )
	{
		fprintf(stderr, "k:%d\n", k);
		return -1;
	}
	
	if ( random_no == NULL )
	{
		fprintf(stderr, "Bad arg. random_no:NULL\n");
		return -2;
	}

#if DBG
	fprintf(stdout, "%s:%d:: Debug! state:%p\n", __func__, __LINE__, state);
#endif /*DBG*/
	if ( state_initialized == 0 )
	{
#if DBG
		fprintf(stdout, "%s:%d:: Debug! state:%p\n", __func__, __LINE__, state);
#endif /*DBG*/
		initialize_random_state_and_seed(state);
#if DBG
		fprintf(stdout, "%s:%d:: Debug! state:%p\n", __func__, __LINE__, state);
#endif /*DBG*/
	}
#if DBG
	fprintf(stdout, "%s:%d:: Debug! state:%p, random_no:%p\n", __func__, __LINE__, state, random_no);
#endif /*DBG*/

	mpz_urandomb( random_no, state, k );
#if DBG
	fprintf(stdout, "%s:%d:: Debug! state:%p\n", __func__, __LINE__, state);
#endif /*DBG*/

		return 0;
}

int write_random_values_to_file(char *output_file_name, int no_bits, int no_dims)
{
	int err = 0, i;
	mpz_t random_no;
	FILE *fp = NULL;

	if ( ( fp = fopen(output_file_name, "w") ) != NULL )
	{
		mpz_init(random_no);
		for ( i=0; i<no_dims; i++ )
		{
#if DBG
	fprintf(stdout, "%s:%d:: Debug!\n", __func__, __LINE__);
#endif /*DBG*/
			generate_random_number(no_bits, random_no);
#if DBG
	fprintf(stdout, "%s:%d:: Debug!\n", __func__, __LINE__);
#endif /*DBG*/
			if ( i < no_dims - 1 )
			{
				gmp_fprintf(fp, "%Zu\n", random_no);
			}
			else
			{
				gmp_fprintf(fp, "%Zu", random_no);
			}
		}
		fclose(fp);
		mpz_clear(random_no);
	}
	else
	{
		fprintf(stderr, "Cannot open file: %s\n", output_file_name);
		return -1;
	}
	return err;
}

int clear_random_state( gmp_randstate_t state )
{
	if ( state_initialized != 0 )
	{
		gmp_randclear( state );
	}
	return 0;
}
