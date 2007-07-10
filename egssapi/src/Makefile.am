include $(top_srcdir)/app.mk

OPT_APP = gssapi

gssapi_VSN = 0.1

gssapi_SRCS = \
	spnego.erl \
	SPNEGOASNOneSpec.erl \
	gssapi.erl

# gssapi_HDRS =

AM_ERLCFLAGS = -I$(top_builddir)/include -I$(srcdir)    \
-I$(ERLANG_LIB_DIR_xmerl)/include
AM_ERL_FLAGS =

CLEANFILES += SPNEGOASNOneSpec.asn1db SPNEGOASNOneSpec.erl	\
SPNEGOASNOneSpec.hrl

SPNEGOASNOneSpec.erl: SPNEGOASNOneSpec.asn1
	$(ERLC) +der $?
