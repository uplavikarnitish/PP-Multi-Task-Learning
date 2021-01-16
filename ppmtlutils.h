#define DEB_LASSO_FNAME "db_lasso.dat"
#define SC_R_DEB_LASSO_FNAME "sc_db_lasso.dat"
#define ENCR_SC_R_DEB_LASSO_FNAME "encr_sc_db_lasso.dat"
#define ENCR_DEB_LASSO_FRM_CL_FNAME "encr_db_l_cl.dat"
#define ENCR_DEB_LASSO_NORM2 "encr_db_norm2.dat"
#define ENCR_DEC_BITS_FNAME "encr_dec_bits.dat"
#define SUPPORT_THRESHOLD_S1_FNAME "threshold_sq.dat"
#define V_FNAME "v.dat"
#define E_SUPP_FNAME "e_supp.dat"
#define DELIMITER ","
#define SCALEUP_BY 1000
#define SUPPORT_DOM SCALEUP_BY*50
#define S1_HOSTNAME "127.0.0.1"
#define S2_HOSTNAME "127.0.0.1"
#define C_TO_S1_PORT_NO 9081
#define S1_TO_S2_PORT_NO 9082

typedef struct _sbd_sc_file_names_param
{
	char *working_dir;
	char *encr_norm2_file_name; //stores name of i/p file with list of E(norm2)
	char *sup_threshold_file_name; //stores name of i/p file with list of $\Lambda^{2}$
	char *op_encr_dec_bits_file_name; //stores name of o/p file in which norm2 bits would be decomposed and encrypted
	char *v_file_name; //stores name of o/p file in which support threshold bits would be decomposed
	char *e_supp_file_name; //stores name of o/p file in which encr.s of supports based on thresholds derived using sc_optimized() are stored


}sbd_sc_file_names_param;

