#define OK 0
#define HTTP_INTERNAL_SERVER_ERROR -1

int
store_gss_creds(const char *princ_name,
                gss_cred_id_t delegated_cred,
		char **pccname);
