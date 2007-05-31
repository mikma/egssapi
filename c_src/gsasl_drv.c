/*
  gsasl_drv.c
  Copyright (C) 2007  Mikael Magnusson <mikma@users.sourceforge.net>

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
*/

#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <memory.h>
#include <alloca.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>

#include <gsasl.h>
#include <ei.h>
#include "port_util.h"

#define MAX_SESSIONS 128
#define MECH "GSSAPI"
/* #define MECH "ANONYMOUS" */
#define BUF_SIZE 512 

#define ENCODE_ERROR(err)				\
    {							\
	if (ei_x_encode_atom(&result, "error") ||	\
	    ei_x_encode_atom(&result, err))		\
	    return 18;					\
	write_cmd(&result);				\
	ei_x_free(&result);				\
	goto error;					\
    }

#define ENCODE_ERROR_NO(err, no)			\
    {							\
	if (ei_x_encode_atom(&result, "error") ||	\
	    ei_x_encode_tuple_header(&result, 2) ||	\
	    ei_x_encode_atom(&result, err) ||		\
	    ei_x_encode_long(&result, no))		\
	    return 18;					\
	write_cmd(&result);				\
	ei_x_free(&result);				\
	goto error;					\
    }

#define OK(x) { if (x != GSASL_OK) { fprintf(stderr, "Error: %s\r\n", gsasl_strerror(x)); ENCODE_ERROR_NO("gsasl_error", x); }}

struct session {
    char *service;
    char *hostname;
};

Gsasl *g_ctx;
char *g_service;
char *g_hostname;

Gsasl_session *g_sessions[MAX_SESSIONS];

enum sasl_mode {
    MODE_CLIENT = 1,
    MODE_SERVER = 2
};

typedef int (*port_func)(char *buf, int index, ei_x_buff *presult);

struct func_info {
    const char *name;
    port_func func;
};

struct property_info {
    const char *name;
    Gsasl_property prop;
};

struct property_info g_properties[] = 
{
    { "authid", GSASL_AUTHID },
    { "authzid", GSASL_AUTHZID },
    { "password", GSASL_PASSWORD },
    { "gssapi_display_name", GSASL_GSSAPI_DISPLAY_NAME },
};

struct error_info {
    const char *name;
    Gsasl_rc error;
};

struct error_info g_errors[] =
{
    { "authentication_error", GSASL_AUTHENTICATION_ERROR }
};

int session_find_free()
{
    int i;
    for (i = 0; i < MAX_SESSIONS; i++) {
	if (!g_sessions[i])
	    return i;
    }

    return -1;
}

struct session *session_alloc()
{
    struct session *sess = malloc(sizeof(struct session));

    memset(sess, 0, sizeof(*sess));

    return sess;
}

void session_free(struct session *sess)
{
    if (sess->service)
	free(sess->service);

    if (sess->hostname)
	free(sess->hostname);

    free(sess);
}

static int callback_function(Gsasl *ctx, Gsasl_session *sctx,
			     Gsasl_property prop)
{
    switch(prop) {
    case GSASL_AUTHID:
	return GSASL_NO_AUTHID;
    case GSASL_SERVICE:
	gsasl_property_set(sctx, GSASL_SERVICE, g_service);
	return GSASL_OK;
    case GSASL_HOSTNAME:
	gsasl_property_set(sctx, GSASL_HOSTNAME, g_hostname);
	return GSASL_OK;
    case GSASL_VALIDATE_GSSAPI:
	return GSASL_OK;
/* 	return GSASL_AUTHENTICATION_ERROR; */
    default:
	fprintf(stderr, "Unhandled callback_function %d\n", prop);
	return GSASL_AUTHENTICATION_ERROR;
/* 	return GSASL_OK; */
    }
}

static Gsasl_property property_from_string(const char *name)
{
    int i;
    int max = sizeof(g_properties) / sizeof(g_properties[0]);

    for (i = 0; i < max; i++) {
	if (!strcmp(name, g_properties[i].name))
	    return g_properties[i].prop;
    }

    return -1;
}

static const char *string_from_rc(Gsasl_rc error)
{
    int i;
    int max = sizeof(g_errors) / sizeof(g_errors[0]);

    for (i = 0; i < max; i++) {
	if (error == g_errors[i].error)
	    return g_errors[i].name;
    }

    return "undefined";
}

static int start(char *buf, int index, ei_x_buff *presult)
{
    ei_x_buff result = *presult;
    /* {new, {Mode, Service, Host_name}} */

    do {
	int idx;
	int arity;
	char mode_str[MAXATOMLEN];
	enum sasl_mode mode;

	if (ei_decode_tuple_header(buf, &index, &arity)) return 6;

	if (arity != 3) return 7;

	if (ei_decode_atom(buf, &index, mode_str)) return 8;
	/* Used in callback_function called by gsasl_server_start */
	
	DECODE_STRING(&g_service);
	DECODE_STRING(&g_hostname);

	if (!strcmp(mode_str, "client")) {
	    mode = MODE_CLIENT;
	} else if (!strcmp(mode_str, "server")) {
	    mode = MODE_SERVER;
	} else {
	    ENCODE_ERROR("invalid_mode");
	}

	idx = session_find_free();
	if (idx < 0) ENCODE_ERROR("no_mem");

	if (mode == MODE_SERVER) {
	    OK(gsasl_server_start(g_ctx, MECH, &g_sessions[idx]));
	} else {
	    OK(gsasl_client_start(g_ctx, MECH, &g_sessions[idx]));
	}

	gsasl_property_set(g_sessions[idx], GSASL_SERVICE, g_service);
	gsasl_property_set(g_sessions[idx], GSASL_HOSTNAME, g_hostname);

	free(g_service);
	free(g_hostname);
	g_service = NULL;
	g_hostname = NULL;

	if (ei_x_encode_atom(&result, "ok") ||
	    ei_x_encode_long(&result, idx)) return 9;
    }while(0);

error:
    *presult = result;
    return 0;
}

static int step(char *buf, int index, ei_x_buff *presult)
{
    ei_x_buff result = *presult;
    /* {step, {Idx, Data}} */

    do {
	char *input;
	size_t input_len;
	char *output = NULL;
	int len;
	long llen;
	size_t output_len = 0;
	int res;
	int type;
	long idx;
	Gsasl_session *sess;
	int arity;

	if (ei_decode_tuple_header(buf, &index, &arity)) return 20;
    
	if (arity != 2) return 21;

	if (ei_decode_long(buf, &index, &idx)) return 22;

	if (idx < 0 || idx >= MAX_SESSIONS || !g_sessions[idx]) ENCODE_ERROR("bad_instance");

	sess = g_sessions[idx];

	if (ei_get_type(buf, &index, &type, &len)) return 24;

	if (type != ERL_BINARY_EXT) return 25;

	input_len = len;
	input = malloc(input_len);

	llen = len;

	if (ei_decode_binary(buf, &index, input, &llen)) return 26;

	res = gsasl_step(sess, input, input_len,
			 &output, &output_len);

	free(input);

	if (res == GSASL_OK || res == GSASL_NEEDS_MORE) {
	    if (res == GSASL_OK) {
		if (ei_x_encode_atom(&result, "ok"))
		    return 27;
	    } else {
		if (ei_x_encode_atom(&result, "needsmore"))
		    return 28;
	    }

	    if (ei_x_encode_binary(&result, output, output_len))
		return 29;
	} else {
	    fprintf(stderr, "Error: %s\n", gsasl_strerror(res));
	    ENCODE_ERROR_NO("gsasl", res);
	}
    }while(0);

error:
    *presult = result;
    return 0;
}

static int property_get(char *buf, int index, ei_x_buff *presult)
{
    ei_x_buff result = *presult;
    /* {property_get, {Ref, Property_name}} */

    do {
	int arity;
	long idx;
	Gsasl_session *sess;
	char propname[MAXATOMLEN];
	const char *propvalue;
	Gsasl_property prop;

	if (ei_decode_tuple_header(buf, &index, &arity)) return 6;

	if (arity != 2) return 7;

	if (ei_decode_long(buf, &index, &idx)) return 30;

	if (idx < 0 || idx >= MAX_SESSIONS || !g_sessions[idx]) ENCODE_ERROR("bad_instance");

	sess = g_sessions[idx];

	/* Used in callback_function called by gsasl_server_start */
	if (ei_decode_atom(buf, &index, propname)) return 4;

	prop = property_from_string(propname);
	if (prop < 0) ENCODE_ERROR("bad_property");

	propvalue = gsasl_property_get(sess, prop);
	if (propvalue) {
	    if (ei_x_encode_atom(&result, "ok") ||
		ei_x_encode_string(&result, propvalue)) return 9;
	} else {
	    if (ei_x_encode_atom(&result, "error") ||
		ei_x_encode_atom(&result, "not_found")) return 9;
	}
    }while(0);

error:
    *presult = result;
    return 0;
}

static int property_set(char *buf, int index, ei_x_buff *presult)
{
    ei_x_buff result = *presult;
    /* {property_set, {Ref, name, value}} */

    do {
	int arity;
	long idx;
	Gsasl_session *sess;
	char propname[MAXATOMLEN];
	char *propvalue;
	Gsasl_property prop;

	if (ei_decode_tuple_header(buf, &index, &arity)) return 6;

	if (arity != 3) return 7;

	if (ei_decode_long(buf, &index, &idx)) return 30;

	if (idx < 0 || idx >= MAX_SESSIONS || !g_sessions[idx]) ENCODE_ERROR("bad_instance");

	sess = g_sessions[idx];

	/* Used in callback_function called by gsasl_server_start */
	if (ei_decode_atom(buf, &index, propname)) return 4;

	prop = property_from_string(propname);
	if (prop < 0) ENCODE_ERROR("bad_property");

	DECODE_STRING(&propvalue);
	gsasl_property_set(sess, prop, propvalue);

	free(propvalue);
	propvalue = NULL;

	if (ei_x_encode_atom(&result, "ok") ||
	    ei_x_encode_atom(&result, "set")) return 9;

    }while(0);

error:
    *presult = result;
    return 0;
}

static int finish(char *buf, int index, ei_x_buff *presult)
{
    ei_x_buff result = *presult;
    /* {finish, Ref} */

    do {
	long idx;
	Gsasl_session *sess;

	if (ei_decode_long(buf, &index, &idx)) return 30;

	if (idx < 0 || idx >= MAX_SESSIONS || !g_sessions[idx]) ENCODE_ERROR("bad_instance");

	sess = g_sessions[idx];
	gsasl_finish(sess);
	g_sessions[idx] = NULL;

	if (ei_x_encode_atom(&result, "ok") ||
	    ei_x_encode_atom(&result, "finished")) return 32;
    }while(0);

error:
    *presult = result;
    return 0;
}

static int debug(char *buf, int index, ei_x_buff *presult)
{
    ei_x_buff result = *presult;
    /* {debug, {Idx, Data}} */

    do {
	char *input;
	size_t input_len;
	int len;
	long llen;
	int type;
	long idx;
	int arity;

	if (ei_decode_tuple_header(buf, &index, &arity)) return 40;
    
	if (arity != 2) return 41;

	if (ei_decode_long(buf, &index, &idx)) return 42;

	if (ei_get_type(buf, &index, &type, &len)) return 43;

	if (type != ERL_BINARY_EXT) return 44;

	input_len = len;
	input = malloc(input_len);

	llen = len;

	if (ei_decode_binary(buf, &index, input, &llen)) return 45;
	fprintf(stderr, "Decode binary %d %ld\n", len, llen);

	free(input);

	if (ei_x_encode_atom(&result, "ok") ||
	    ei_x_encode_atom(&result, "dummy"))
	    return 46;
    }while(0);

error:
    *presult = result;
    return 0;
}


struct func_info g_entries[] = {
    { "start", start },
    { "step", step },
    { "property_get", property_get },
    { "property_set", property_set },
    { "finish", finish },
    { "debug", debug }
};

port_func lookup_func(const char *name)
{
    int i;
    int size = sizeof(g_entries)/sizeof(g_entries[0]);

    for (i = 0; i < size; i++) {
	if (strcmp(name, g_entries[i].name) == 0) {
	    return g_entries[i].func;
	}
    }

    return NULL;
}

/*-----------------------------------------------------------------
 * MAIN
 *----------------------------------------------------------------*/
int main(int argc, char *argv[])
{
    byte *buf;
    int size = BUF_SIZE;

    if ((buf = malloc(size)) == NULL)
	return -1;

    g_ctx = NULL;
    if (gsasl_init(&g_ctx) != GSASL_OK)
	return 1;

    gsasl_callback_set(g_ctx, callback_function);

    while ( (buf = read_cmd(buf, &size)) ) {
	int res = 0;
	int index = 0;
	int version, arity;
	char command[MAXATOMLEN];
	port_func func;
	ei_x_buff result;

	/* Ensure that we are receiving the binary term by reading and 
	 * stripping the version byte */
	if (ei_decode_version(buf, &index, &version)) return 1;
    
	/* Our marshalling spec is that we are expecting a tuple {Command, Arg1, Arg2} */
	if (ei_decode_tuple_header(buf, &index, &arity)) return 2;
    
	if (arity != 2) return 3;
    
	if (ei_decode_atom(buf, &index, command)) return 4;
    
	/* Prepare the output buffer that will hold {ok, Result} or {error, Reason} */
	if (ei_x_new_with_version(&result) || ei_x_encode_tuple_header(&result, 2)) return 5;

	func = lookup_func(command);

	if (func) {
	    res = func(buf, index, &result);
	} else {
	    if (ei_x_encode_atom(&result, "error") || ei_x_encode_atom(&result, "unsupported_command")) 
		return 47;
	}

	if (res)
	    return res;

	write_cmd(&result);
	ei_x_free(&result);

	size = BUF_SIZE;
    }

    fprintf(stderr, "No more command, exiting\r\n");

    return 0;
}

