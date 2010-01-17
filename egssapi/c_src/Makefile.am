AM_CFLAGS = -Wall -g -DHAVE_KRB5
AM_CPPFLAGS = $(K5CFLAGS) $(EI_CFLAGS)

privdir = $(ERLANG_INSTALL_LIB_DIR)/egssapi-$(VERSION)/priv
priv_PROGRAMS = gssapi_drv

gssapi_drv_LDFLAGS = $(K5LIBS) $(EI_LDFLAGS)
gssapi_drv_LDADD = $(EI_LIBS)
gssapi_drv_SOURCES = gssapi_drv.c krb5_deleg.c krb5_deleg.h	\
port_util.c port_util.h config.h
