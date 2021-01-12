#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <assert.h>
#include "gmp.h"

void paillier_key(int size, FILE* keys);
void paillier_threshold_key(int size, FILE* keys);
void gen_safe_primes(mpz_t p1, mpz_t p, int size);

int main(int argc, char* argv[]){
 
  int key_size;
  //The file contains the public and private keys
  FILE* output_file;

  if (argc != 3){
    printf("\n%s", "Usage: key_gen.o output_file key_size<n^2: cipher text size>\n");
    exit(1);
  }

  //open a file
  if ((output_file = fopen(argv[1], "w")) == NULL)
    fprintf(stderr, "Cannot open %s\n", argv[1]);

  //get the key size (size of p and q)
  key_size = atoi(argv[2]);
  printf("\n%s%d\n","Key size: ", key_size);

  assert(key_size > 0 && key_size < (32*2048));

  //paillier_key(key_size, output_file);
  paillier_threshold_key((key_size/4), output_file);

  fclose(output_file);
  exit(1);
}


void paillier_key(int key_size, FILE* keys){
    //public key n_plus_1
    //private key lcm
    mpz_t n, p, q, p_minus_1, n_plus_1, lcm, temp;
    char* str;
    int done = 0;
    gmp_randstate_t state;

    mpz_init(n);
    mpz_init(n_plus_1);
    mpz_init(p);
    mpz_init(p_minus_1);
    mpz_init(q);
    mpz_init(lcm); 
    mpz_init(temp); 

    //generate encryption paramters
    do {
	
	//initializing a random state
	gmp_randinit_default(state);
	gmp_randseed_ui(state, time(NULL));
	
	//generate the primes p < q
	mpz_rrandomb(temp, state, key_size); 
	mpz_nextprime(p, temp);
	mpz_nextprime(q, p);

	//sent p minus 1
	mpz_sub_ui(p_minus_1, p, 1);
	
	//Now verify that p-1 does not divide q
	mpz_gcd(temp, p_minus_1, q);
	if(mpz_cmp_ui(temp, 1) == 0)
	    done = 1;
	
    }while(!done);
    
    //write p to a file
    fprintf(keys, "Prime p: ");
    fprintf(keys, "Size = %d\n", mpz_sizeinbase(p, 2));
    if (mpz_out_str(keys, 10, p) == 0)
	printf("Not able to write p\n");
    fprintf(keys, "\n\n");
    
    //write q to a file
    fprintf(keys, "Prime q: ");
    fprintf(keys, "Size = %d\n", mpz_sizeinbase(q, 2));
    if (mpz_out_str(keys, 10, q) == 0)
	printf("Not able to write q\n");
    fprintf(keys, "\n\n");
    
    //compute n
    mpz_mul(n, p, q);
    
    //write n to a file
    fprintf(keys, "n: ");
    fprintf(keys, "Size = %d\n", mpz_sizeinbase(n, 2));
    if (mpz_out_str(keys, 10, n) == 0)
	printf("Not able to write n\n");
    fprintf(keys, "\n\n");
    
    //compute n+1 (the public key)
    mpz_add_ui(n_plus_1, n, 1);
    
    //write n+1 to a file
    fprintf(keys, "n_plus_1: ");
    fprintf(keys, "Size = %d\n", mpz_sizeinbase(n_plus_1, 2));
    if (mpz_out_str(keys, 10, n_plus_1) == 0)
	printf("Not able to write n_plus_1\n");
    fprintf(keys, "\n\n");
    
    //compute lcm(p-1,q-1) (private key), first set temp = q-1
    mpz_sub_ui(temp, q, 1);
    mpz_lcm(lcm, p_minus_1, temp);
    
    //write lcm to a file
    fprintf(keys, "lcm: ");
    fprintf(keys, "Size = %d\n", mpz_sizeinbase(lcm, 2));
    if (mpz_out_str(keys, 10, lcm) == 0)
	printf("Not able to write lcm\n");
    fprintf(keys, "\n\n");

    gmp_randclear(state);
    mpz_clear(temp);
    mpz_clear(n);
    mpz_clear(n_plus_1);
    mpz_clear(p);
    mpz_clear(p_minus_1);
    mpz_clear(q);
    mpz_clear(lcm);
}

/*
 * This function returns the public and private keys for two party 
 * paillier threshold scheme
 *
 * @param size: specifies the number of bits of the key
 * @param keys: is a file containing the produced keys including the following:
 *              s1 - share of the key for party 1
 *              v1 - proof of the key for party 1
 *              s2 - share of the key for party 2
 *              v2 - proof of the key for party 2
 *               v - public v value
 *               n - public n value
 */
void paillier_threshold_key(int size, FILE* keys){
  
    // local variables
  int done = 0;
  mpz_t r, temp;

  // both p1 and q1 are primes with size = size - 1
  mpz_t p1;
  mpz_t q1;
  
  // p is a prime and p = 2*p1 + 1;
  mpz_t p;
  // q is a prime and p = 2*q1 + 1;
  mpz_t q;
  
  // m is set to p1*q1
  mpz_t m;
  // n is set to p*q
  mpz_t n;
  
  // $n^2$
  mpz_t nn;
  // n*m
  mpz_t nm;
  
  // v is a generator of $Z^*_{n^2}$
  mpz_t v;
  // d = 1 mod n and d = 0 mod m
  mpz_t d;
  
  // keys shares
  mpz_t s1;
  mpz_t v1;
  mpz_t s2;
  mpz_t v2;


  // a0 is the random number used for generating the polynomial
  // between 0 ... n*m - 1
  mpz_t a0;
  
  gmp_randstate_t state;
  
  // initialize all the big numbers
  mpz_init(r);
  mpz_init(temp);
  mpz_init(p1);
  mpz_init(q1);
  mpz_init(p);
  mpz_init(q); 
  mpz_init(m);
  mpz_init(n);
  mpz_init(nn);
  mpz_init(nm);
  mpz_init(v);
  mpz_init(d);
  mpz_init(s1);
  mpz_init(v1);
  mpz_init(s2);
  mpz_init(v2);
  mpz_init(a0);
  
  gmp_randinit_default(state);
  gmp_randseed_ui(state, time(NULL));
  // generate a0 value
  mpz_rrandomb(a0, state, 4*(size - 1)); 

  printf("Generating p1, p! \n");
  gen_safe_primes(p1, p, size);
  
  printf("Generating q1, q! \n");
  gen_safe_primes(q1, q, size);
  
  // n = p*q
  mpz_mul(n, p, q);
  // m = p1*q1
  mpz_mul(m, p1, q1);
  // nm = n*m
  mpz_mul(nm, n, m);
  // nn = n*n
  //mpz_mul(nn, n, n);
  mpz_pow_ui(nn, n, 2);
  
  /*
   * We need to generate v here. Although v needs to be the generator of
   * $Z^*_{n^2}$, we can use a heuristic that gives a generator with high
   * probability. Get a random element r such that gcd(r, n^2) = 1 and set
   * v = r*r mod nn. This heuristic is used in the Vicor Shoup threshold
   * signature paper.
   */

  
  do {
    //initializing a random state
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));
    
    mpz_rrandomb(r, state, 4*size);
    
    //Now check if gcd(r, n) = 1 => gcd(r, n^2) = 1
    mpz_gcd(temp, r, n);
    if(mpz_cmp_ui(temp, 1) == 0)
      done = 1;
    
  }while(!done);
  
  // set v = r*r mod nn
  mpz_powm_ui(v, r, 2, nn);

  /* 
   * next we choose d such that d = 0 mod m and d = 1 mod n using
   * Chinese remainder theorem. Note that $d = m * (m^{-1} mod n)$
   */
  // check if the inverse of m exists
  if(mpz_invert(temp, m, n) == 0){
    printf("m^{-1} does not exist!\n");
    exit(0);
  }
  mpz_mul(d, m, temp);

  // s1 = (a0 + d) mod nm, v1 = v^{2*s1} mod nn
  printf("Generating s1 and v1!\n");
  mpz_add(temp, a0, d);
  mpz_mod(s1, temp, nm);
  mpz_mul_ui(temp, s1, 2);
  mpz_powm(v1, v, temp, nn);
  
  // s2 = (2*a0 + d) mod nm, v2 = $v^{2*s2}$
  printf("Generating s2 and v2!\n");
  mpz_mul_ui(temp, a0, 2);
  mpz_add(temp, temp, d);
  mpz_mod(s2, temp, nm);
  mpz_mul_ui(temp, s2, 2);
  mpz_powm(v2, v, temp, nn);

  // output all the keys to a file

  //write p1 to a file
  fprintf(keys, "p1: ");
  fprintf(keys, "Size = %d\n", mpz_sizeinbase(p1, 2));
  if (mpz_out_str(keys, 10, p1) == 0)
    printf("Not able to write p1\n");
  fprintf(keys, "\n\n");

  //write p to a file
  fprintf(keys, "p: ");
  fprintf(keys, "Size = %d\n", mpz_sizeinbase(p, 2));
  if (mpz_out_str(keys, 10, p) == 0)
    printf("Not able to write p\n");
  fprintf(keys, "\n\n");

  //write q1 to a file
  fprintf(keys, "q1: ");
  fprintf(keys, "Size = %d\n", mpz_sizeinbase(q1, 2));
  if (mpz_out_str(keys, 10, q1) == 0)
    printf("Not able to write q1\n");
  fprintf(keys, "\n\n");

  //write q to a file
  fprintf(keys, "q: ");
  fprintf(keys, "Size = %d\n", mpz_sizeinbase(q, 2));
  if (mpz_out_str(keys, 10, q) == 0)
    printf("Not able to write q\n");
  fprintf(keys, "\n\n");

  //write nm to a file
  fprintf(keys, "nm: ");
  fprintf(keys, "Size = %d\n", mpz_sizeinbase(nm, 2));
  if (mpz_out_str(keys, 10, nm) == 0)
    printf("Not able to write nm\n");
  fprintf(keys, "\n\n");

  //write a0 to a file
  fprintf(keys, "a0: ");
  fprintf(keys, "Size = %d\n", mpz_sizeinbase(a0, 2));
  if (mpz_out_str(keys, 10, a0) == 0)
    printf("Not able to write a0\n");
  fprintf(keys, "\n\n");

  //write d to a file
  fprintf(keys, "d: ");
  fprintf(keys, "Size = %d\n", mpz_sizeinbase(d, 2));
  if (mpz_out_str(keys, 10, d) == 0)
    printf("Not able to write d\n");
  fprintf(keys, "\n\n");

  //write s1 to a file
  fprintf(keys, "s1: ");
  fprintf(keys, "Size = %d\n", mpz_sizeinbase(s1, 2));
  if (mpz_out_str(keys, 10, s1) == 0)
    printf("Not able to write s1\n");
  fprintf(keys, "\n\n");

  //write v1 to a file
  fprintf(keys, "v1: ");
  fprintf(keys, "Size = %d\n", mpz_sizeinbase(v1, 2));
  if (mpz_out_str(keys, 10, v1) == 0)
    printf("Not able to write v1\n");
  fprintf(keys, "\n\n");
  
  //write s2 to a file
  fprintf(keys, "s2: ");
  fprintf(keys, "Size = %d\n", mpz_sizeinbase(s2, 2));
  if (mpz_out_str(keys, 10, s2) == 0)
    printf("Not able to write s2\n");
  fprintf(keys, "\n\n");

  //write v2 to a file
  fprintf(keys, "v2: ");
  fprintf(keys, "Size = %d\n", mpz_sizeinbase(v2, 2));
  if (mpz_out_str(keys, 10, v2) == 0)
    printf("Not able to write v2\n");
  fprintf(keys, "\n\n");

  //write v to a file
  fprintf(keys, "v: ");
  fprintf(keys, "Size = %d\n", mpz_sizeinbase(v, 2));
  if (mpz_out_str(keys, 10, v) == 0)
    printf("Not able to write v\n");
  fprintf(keys, "\n\n");

  //write v to a file
  fprintf(keys, "n: ");
  fprintf(keys, "Size = %d\n", mpz_sizeinbase(n, 2));
  if (mpz_out_str(keys, 10, n) == 0)
    printf("Not able to write n\n");
  fprintf(keys, "\n\n");


  // release memory allocated to big numbers
  mpz_clear(r);
  mpz_clear(temp);
  mpz_clear(p1);
  mpz_clear(q1);
  mpz_clear(p);
  mpz_clear(q); 
  mpz_clear(m);
  mpz_clear(n);
  mpz_clear(nn);
  mpz_clear(nm);
  mpz_clear(v);
  mpz_clear(d);
  mpz_clear(s1);
  mpz_clear(v1);
  mpz_clear(s2);
  mpz_clear(v2);
  mpz_clear(a0);
}

/*
 * This function produce two primes:
 * 
 * @param p1 - is a prime with size size - 1
 * @param p - is a prime such that p = 2*p1 + 1
 */
void gen_safe_primes(mpz_t p1, mpz_t p, int size){

  int done = 0;
  mpz_t temp;
  gmp_randstate_t state;

  mpz_init(temp);

 
  do {
    //initializing a random state
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));
    
    //generate the prime with size = size - 1
    mpz_rrandomb(temp, state, size - 1);
    mpz_nextprime(p1, temp);

    if(mpz_sizeinbase(p1, 2) != (size - 1))
      continue;

    //set temp = 2*p1
    mpz_mul_ui(temp, p1, 2);

    //set p = 2*p1 + 1
    mpz_add_ui(p, temp, 1);

    //Now check is p is a prime
    if (mpz_probab_prime_p(p, 50) < 1)
      continue;
   
    done = 1;
    
  }while(!done);
  
  mpz_clear(temp);
}
