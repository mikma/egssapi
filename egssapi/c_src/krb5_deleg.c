/* 
 * krb5_deleg.c
 * Copyright (c) 2007 Mikael Magnusson
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
 * 3. Neither the name of the copyright owner nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission. 
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
/* Based on modauthkerb */
/*
 * Daniel Kouril <kouril@users.sourceforge.net>
 *
 * Source and Documentation can be found at:
 * http://modauthkerb.sourceforge.net/
 *
 * Based on work by
 *   James E. Robinson, III <james@ncstate.net>
 *   Daniel Henninger <daniel@ncsu.edu>
 *   Ludek Sulak <xsulak@fi.muni.cz>
 */

/*
 * Copyright (c) 2004-2006 Masarykova universita
 * (Masaryk University, Brno, Czech Republic)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the University nor the names of its contributors may
 *    be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#ifdef KRB5
#include <krb5.h>
#ifdef HEIMDAL
#  include <gssapi.h>
#else
#  include <gssapi/gssapi.h>
#  include <gssapi/gssapi_generic.h>
#  include <gssapi/gssapi_krb5.h>
#  define GSS_C_NT_USER_NAME gss_nt_user_name
#  define GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#  define GSS_KRB5_NT_PRINCIPAL_NAME gss_nt_krb5_name
#  define krb5_get_err_text(context,code) error_message(code)
#endif
#endif

#include "krb5_deleg.h"

static int
create_krb5_ccache(krb5_context kcontext,
		   krb5_principal princ,
		   krb5_ccache *ccache,
		   char **pccname)
{
   char *ccname;
   int fd;
   krb5_error_code problem;
   int ret;
   krb5_ccache tmp_ccache = NULL;

   *pccname = NULL;
   asprintf(&ccname, "FILE:%s/krb5cc_deleg_XXXXXX", P_tmpdir);
   fd = mkstemp(ccname + strlen("FILE:"));
   if (fd < 0) {
       /* FIXME */
/*        log_rerror(APLOG_MARK, APLOG_ERR, 0, r, */
/*                  "mkstemp() failed: %s", strerror(errno)); */
       ret = HTTP_INTERNAL_SERVER_ERROR;
       goto end;
   }
   close(fd);

   problem = krb5_cc_resolve(kcontext, ccname, &tmp_ccache);
   if (problem) {
       /* FIXME */
/*       log_rerror(APLOG_MARK, APLOG_ERR, 0, r, */
/*                  "krb5_cc_resolve() failed: %s", */
/*                  krb5_get_err_text(kcontext, problem)); */
      ret = HTTP_INTERNAL_SERVER_ERROR;
      unlink(ccname);
      goto end;
   }

   problem = krb5_cc_initialize(kcontext, tmp_ccache, princ);
   if (problem) {
       /* FIXME */
/*       log_rerror(APLOG_MARK, APLOG_ERR, 0, r, */
/* 		 "Cannot initialize krb5 ccache %s: krb5_cc_initialize() failed: %s", */
/* 		 ccname, krb5_get_err_text(kcontext, problem)); */
      ret = HTTP_INTERNAL_SERVER_ERROR;
      goto end;
   }

   /* FIXME */
/*    apr_table_setn(r->subprocess_env, "KRB5CCNAME", ccname); */
/*    apr_pool_cleanup_register(r->pool, ccname, krb5_cache_cleanup, */
/* 	 		     apr_pool_cleanup_null); */

   *ccache = tmp_ccache;
   tmp_ccache = NULL;
   *pccname = strdup(ccname);

   ret = OK;

end:
   if (tmp_ccache)
      krb5_cc_destroy(kcontext, tmp_ccache);

   return ret;
}


int
store_gss_creds(const char *princ_name,
                gss_cred_id_t delegated_cred,
		char **pccname)
{
   OM_uint32 maj_stat, min_stat;
   krb5_principal princ = NULL;
   krb5_ccache ccache = NULL;
   krb5_error_code problem;
   krb5_context context;
   int ret = HTTP_INTERNAL_SERVER_ERROR;

   problem = krb5_init_context(&context);
   if (problem) {
       /* FIXME */
/*       log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Cannot initialize krb5 context"); */
      return HTTP_INTERNAL_SERVER_ERROR;
   }

   problem = krb5_parse_name(context, princ_name, &princ);
   if (problem) {
       /* FIXME */
/*       log_rerror(APLOG_MARK, APLOG_ERR, 0, r,  */
/* 	 "Cannot parse delegated username (%s)", krb5_get_err_text(context, problem)); */
      goto end;
   }

   problem = create_krb5_ccache(context, princ, &ccache, pccname);
   if (problem) {
       /* FIXME */
/*       log_rerror(APLOG_MARK, APLOG_ERR, 0, r, */
/* 	 "Cannot create krb5 ccache (%s)", krb5_get_err_text(context, problem)); */
      goto end;
   }

   maj_stat = gss_krb5_copy_ccache(&min_stat, delegated_cred, ccache);
   if (GSS_ERROR(maj_stat)) {
       /* FIXME */
/*       log_rerror(APLOG_MARK, APLOG_ERR, 0, r, */
/* 	 "Cannot store delegated credential (%s)",  */
/* 	 get_gss_error(r->pool, maj_stat, min_stat, "gss_krb5_copy_ccache")); */
      goto end;
   }

   krb5_cc_close(context, ccache);
   ccache = NULL;
   ret = 0;

end:
   if (princ)
      krb5_free_principal(context, princ);
   if (ccache)
      krb5_cc_destroy(context, ccache);
   krb5_free_context(context);
   return ret;
}
