include $(top_srcdir)/app.mk

OTP_APP = egssapi

egssapi_VSN = $(VERSION)

egssapi_SRCS = \
	spnego.erl \
	SPNEGOASNOneSpec.erl \
	egssapi.erl

# egssapi_HDRS =

AM_ERLCFLAGS = -I$(srcdir) +debug_info
AM_ERL_FLAGS =

CLEANFILES += SPNEGOASNOneSpec.asn1db SPNEGOASNOneSpec.erl	\
SPNEGOASNOneSpec.hrl

SPNEGOASNOneSpec.erl: SPNEGOASNOneSpec.asn1
	$(ERLC) +der $?
