include $(top_srcdir)/app.mk

VPATH = ../src

OPT_APP = gssapi

gssapi_VSN = 0.1

gssapi_SRCS = \
	../src/spnego.erl \
	../src/gsasl.erl \
	../src/eldap_expr.erl \
	SPNEGOASNOneSpec.erl \
	../src/gssapi.erl \
	../src/gssapi_app.erl \
	../src/gssapi_sup.erl

# gssapi_HDRS =

AM_ERLCFLAGS = -I$(top_builddir)/include -I$(srcdir)    \
-I$(ERLANG_LIB_DIR_xmerl)/include
AM_ERL_FLAGS =

CLEANFILES += SPNEGOASNOneSpec.asn1db SPNEGOASNOneSpec.erl	\
SPNEGOASNOneSpec.hrl

SPNEGOASNOneSpec.erl: SPNEGOASNOneSpec.asn1
	$(ERLC) +der $?
