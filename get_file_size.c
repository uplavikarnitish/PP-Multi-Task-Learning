#include<stdio.h>
#include<errno.h>

int main(int argc, char *argv[])
{

	FILE *fp = NULL;
	int err = 0;
	if ( argc !=2 )
	{
		fprintf(stderr, "ERROR in input arguments!!!\nUSAGE - For finding out size of file in bytes:\n");
		fprintf(stderr, "%s <file_name>\n", argv[0]);
	}

	if ( (fp = fopen(argv[1], "rb")) != NULL)
	{
		long file_sz = 0;
		if ( (err = fseek(fp, 0, SEEK_END)) != 0)
		{
			fprintf(stderr, "%s:%d:: ERROR:%d seeking the file pointer! errno:%u\n", __func__, __LINE__, err, errno);
			goto cleanup;
		}
		if ( (file_sz = ftell(fp)) == -1)
		{
			fprintf(stderr, "%s:%d:: ERROR:%d telling the file pointer! errno:%u\n", __func__, __LINE__, err, errno);
			goto cleanup;
		}
		printf("File size: %ld for file %s\n", file_sz, argv[1]);


	}

cleanup:
	if ( fp )
	{
		fclose(fp);
	}
	return 0;
}
