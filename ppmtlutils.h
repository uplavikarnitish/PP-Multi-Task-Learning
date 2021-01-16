#define DEB_LASSO_FNAME "db_lasso.dat"
#define SC_R_DEB_LASSO_FNAME "sc_db_lasso.dat"
#define ENCR_SC_R_DEB_LASSO_FNAME "encr_sc_db_lasso.dat"
#define ENCR_DEB_LASSO_FRM_CL_FNAME "encr_db_l_cl.dat"
#define ENCR_DEB_LASSO_NORM2 "encr_db_norm2.dat"
#define ENCR_DEC_BITS_FNAME "encr_dec_bits.dat"
#define DELIMITER ","
#define SCALEUP_BY 1000
#define S1_HOSTNAME "127.0.0.1"
#define S2_HOSTNAME "127.0.0.1"
#define C_TO_S1_PORT_NO 9081
#define S1_TO_S2_PORT_NO 9082



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
