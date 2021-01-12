#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main()
{
	double random_value;
	FILE *fp;
	char *buf = NULL;
	int err = 0;

	srand ( time ( NULL));

	random_value = (double)rand()/RAND_MAX*2.0-1.0;//float in range -1 to 1

	printf ( "%f\n", random_value);

	random_value = 4.3*10e-6;

	printf ( "%f\n", random_value);

	fp = fopen("data.dat", "r");
	if ( fp == NULL )
	{
		err = -1;
		goto clean_up;
	}

	buf = (char *)malloc(1024);
	int i = 0;
	while ( fgets(buf, 1024, fp) != NULL )
	{
		double val = atof(buf);
		printf("%d>> \t%lf\n", i, val);
		i++;
	}

clean_up:
	
	printf("Before freeing, buf:%p\n", buf);
	free(buf);
	printf("After freeing, buf:%p\n", buf);

	return 0;
}
