/*
 * Copyright (c) 2007 Mikael Magnusson
 * Based on mod_spnego version 0.6
 */

/*
 * Copyright (c) 2004 - 2006 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 *
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 *
 * 3. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <ei.h>
#include <unistd.h>
#include <gssapi.h>
#include <malloc.h>
#include <memory.h>
#include <alloca.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>


#ifdef HAVE_KRB5
#include <gssapi_krb5.h>
#include <krb5.h>
#endif

#include "krb5_deleg.h"
#include "port_util.h"

#define HTTP_UNAUTHORIZED -1

void
gss_print_errors (int min_stat);

void
gss_err(int exitval, int status, const char *fmt, ...);

static void
k5_save(const char *princ_name, gss_cred_id_t cred, char **pccname)
{
    store_gss_creds(princ_name, cred, pccname);
}

struct mech_specific {
    char *oid;
    size_t oid_len;
    void (*save_cred)(const char *princ_name, gss_cred_id_t, char **pccname);
} mechs[] = {
    { "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02", 9, k5_save },
    { NULL }
};

static const struct mech_specific *
find_mech(gss_OID oid)
{
    int i;

    for (i = 0; mechs[i].oid != NULL; i++) {
	if (oid->length != mechs[i].oid_len)
	    continue;
	if (memcmp(oid->elements, mechs[i].oid, mechs[i].oid_len) != 0)
	    continue;
	return &mechs[i];
    }
    return NULL;
}

static int 
authenticate_user(gss_buffer_desc *in,
		  gss_buffer_desc *out,
		  gss_buffer_desc *name,
		  char **pccname)
{
    OM_uint32 maj_stat, min_stat;
    gss_name_t src_name = GSS_C_NO_NAME;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_OID oid = GSS_C_NO_OID;
    int ret;
    gss_cred_id_t delegated_cred_handle = NULL;

    *pccname = NULL;
    maj_stat = gss_accept_sec_context(&min_stat,
				      &ctx,
				      GSS_C_NO_CREDENTIAL,
				      in,
				      GSS_C_NO_CHANNEL_BINDINGS,
				      &src_name,
				      &oid,
				      out,
				      NULL,
				      NULL,
				      &delegated_cred_handle);

    /* XXX */
    if ((maj_stat & GSS_S_CONTINUE_NEEDED) || maj_stat != GSS_S_COMPLETE) {
	fprintf(stderr, "gss_accept_sec_context:");
	gss_print_errors(min_stat);
	ret = HTTP_UNAUTHORIZED;
	goto out;
    }
				      
    if (name) {
	/* Use display name */
	maj_stat = gss_display_name(&min_stat, src_name, name, NULL);
	if (maj_stat != GSS_S_COMPLETE) {
	    ret = HTTP_UNAUTHORIZED;
	    goto out;
	}
    
/* 	gss_release_buffer(&min_stat, &name); */
    }

    ret = OK;

    if (delegated_cred_handle) {
	const struct mech_specific *m;

	m = find_mech(oid);
	if (m && m->save_cred)
	    (*m->save_cred)(name->value, delegated_cred_handle, pccname);
    } else {
	fprintf(stderr, "Not delegated\n");
    }

 out:
    if (src_name != GSS_C_NO_NAME)
	gss_release_name(&min_stat, &src_name);
    if (ctx != GSS_C_NO_CONTEXT)
	gss_delete_sec_context(&min_stat, &ctx, GSS_C_NO_BUFFER);

    return ret;
}

/* From Heimdal */

void
gss_print_errors (int min_stat)
{
    OM_uint32 new_stat;
    OM_uint32 msg_ctx = 0;
    gss_buffer_desc status_string;
    OM_uint32 ret;

    do {
        ret = gss_display_status (&new_stat,
                                  min_stat,
                                  GSS_C_MECH_CODE,
                                  GSS_C_NO_OID,
                                  &msg_ctx,
                                  &status_string);
        fprintf (stderr, "%s\n", (char *)status_string.value);
        gss_release_buffer (&new_stat, &status_string);
    } while (!GSS_ERROR(ret) && msg_ctx != 0);
}

void
gss_verr(int exitval, int status, const char *fmt, va_list ap)
{
/*     vwarnx (fmt, ap); */
    gss_print_errors (status);
    exit (exitval);
}

void
gss_err(int exitval, int status, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    gss_verr (exitval, status, fmt, args);
    va_end(args);
}


void test(int argc, char *argv[])
{
    OM_uint32 maj_stat, min_stat;
    const char *hostname;
    const char *service = "HTTP";
    gss_buffer_desc name_token;
    gss_buffer_desc input_token;
    gss_buffer_desc output_token;
    gss_buffer_desc name;
    gss_name_t server;
    gss_ctx_id_t context_hdl = GSS_C_NO_CONTEXT;
    const gss_OID mech_oid = gss_mech_krb5;
    char *ccname = NULL;

    memset(&name_token, 0, sizeof(name_token));
    memset(&input_token, 0, sizeof(input_token));
    memset(&output_token, 0, sizeof(output_token));
    memset(&name, 0, sizeof(name));

    if (argc != 2)
	return;

    hostname = argv[1];

    name_token.length = asprintf ((char **)&name_token.value,
                                  "%s@%s", service, hostname);

    maj_stat = gss_import_name (&min_stat,
                                &name_token,
                                GSS_C_NT_HOSTBASED_SERVICE,
                                &server);

    if (GSS_ERROR(maj_stat))
        gss_err (1, min_stat,
                 "Error importing name `%s@%s':\n", service, hostname);

    maj_stat =
	gss_init_sec_context(&min_stat,
			     GSS_C_NO_CREDENTIAL,
			     &context_hdl,
			     server,
			     mech_oid,
/* 			     GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_DELEG_FLAG, */
			     GSS_C_DELEG_FLAG,
			     0,
/* 			     &input_chan_bindings, */
			     GSS_C_NO_CHANNEL_BINDINGS,
/* 			     &input_token, */
			     NULL, 
			     NULL,
			     &output_token,
			     NULL,
			     NULL);
    if (GSS_ERROR(maj_stat))
	gss_err (1, min_stat, "gss_init_sec_context");

/*     fwrite(output_token.value, output_token.length, 1, stdout); */

 
    if (authenticate_user(&output_token, &input_token, &name, &ccname) == OK) {
	fprintf(stderr, "User authenticated\n");
    }
}

static int negotiate(char *buf, int index, ei_x_buff *presult)
{
    ei_x_buff result = *presult;

    do {
	    /* {negotiate, Base64} */

	    int type = 0;
	    int len = 0;
	    long llen;
	    gss_buffer_desc in;
	    gss_buffer_desc out;
	    gss_buffer_desc name;
	    int res;
	    char *ccname = NULL;

	    if (ei_get_type(buf, &index, &type, &len)) return 5;

	    if (type != ERL_BINARY_EXT) return 6;

	    in.length = len;
	    in.value = alloca(len);

	    llen = len;

	    if (ei_decode_binary(buf, &index, in.value, &llen)) return 6;

	    in.length = llen;

	    memset(&out, 0, sizeof(out));
	    memset(&name, 0, sizeof(name));

	    res = authenticate_user(&in, &out, &name, &ccname);

	    /* TODO release out and name */

	    if (res == OK) {
	        const char *ret_ccname = ccname;
		if (!ret_ccname)
		    ret_ccname = "";

		if (ei_x_encode_atom(&result, "ok") ||
		    ei_x_encode_tuple_header(&result, 3) ||
		    ei_x_encode_string_len(&result, name.value, name.length) ||
		    ei_x_encode_string(&result, ret_ccname) ||
		    ei_x_encode_binary(&result, out.value, out.length)
		    ) return 8;

		if (ccname) {
		    free(ccname);
		    ccname = NULL;
		}
	    } else {
		if (ei_x_encode_atom(&result, "error") || ei_x_encode_atom(&result, "unauthorized"))
		    return 9;
	    }
    } while(0);

error:
    *presult = result;
    return 0;
}


#define BUF_SIZE 128 

/*-----------------------------------------------------------------
 * MAIN
 *----------------------------------------------------------------*/
int main(int argc, char *argv[])
{
    byte*     buf;
    int       size = BUF_SIZE;
    char      command[MAXATOMLEN];
    int       index, version, arity;
    ei_x_buff result;
    int fd;
    int i;

    if (argc > 1) {
	test(argc, argv);
	return 0;
    }

    fprintf(stderr, "gssapi started\r\n");

    if ((buf = malloc(size)) == NULL)
	return -1;
    
    while (read_cmd(buf, &size) > 0) {
	/* Reset the index, so that ei functions can decode terms from the 
	 * beginning of the buffer */
	index = 0;

	/* Ensure that we are receiving the binary term by reading and 
	 * stripping the version byte */
	if (ei_decode_version(buf, &index, &version)) return 1;
    
	/* Our marshalling spec is that we are expecting a tuple {Command, Arg1, Arg2} */
	if (ei_decode_tuple_header(buf, &index, &arity)) return 2;
    
	if (arity != 2) return 3;
    
	if (ei_decode_atom(buf, &index, command)) return 4;
    
	/* Prepare the output buffer that will hold {ok, Result} or {error, Reason} */
	if (ei_x_new_with_version(&result) || ei_x_encode_tuple_header(&result, 2)) return 5;
    
	if (!strcmp("negotiate", command)) {
	    negotiate(buf, index, &result);
	} else {
	    if (ei_x_encode_atom(&result, "error") || ei_x_encode_atom(&result, "unsupported_command")) 
		return 99;
	}

	write_cmd(&result);

	ei_x_free(&result);

	size = BUF_SIZE;
    }

    fprintf(stderr, "No more command, exiting\n");

    return 0;
}
