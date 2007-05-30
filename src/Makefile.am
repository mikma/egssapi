# Empty
VPATH = ../c_src

AM_CFLAGS = -Wall -g -DHAVE_KRB5
AM_CPPFLAGS = -I/usr/include/gssapi `pkg-config --cflags libgsasl`

privdir = $(ERLANG_INSTALL_LIB_DIR)/gssapi-0.0/priv
priv_PROGRAMS = gssapi_drv gsasl_drv

gssapi_drv_LDFLAGS = `krb5-config --libs krb5 gssapi`
gssapi_drv_LDADD = -lei
gssapi_drv_SOURCES = gssapi_drv.c krb5_deleg.c krb5_deleg.h	\
port_util.c port_util.h

gsasl_drv_LDFLAGS = `pkg-config --libs libgsasl`
gsasl_drv_LDADD = -lei
gsasl_drv_SOURCES = gsasl_drv.c port_util.h port_util.c
