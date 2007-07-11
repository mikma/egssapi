libsubdir = $(ERLANG_INSTALL_LIB_DIR)/$(OTP_APP)-$($(OPT_APP)_VSN)
bindir = $(libsubdir)/bin
ebindir = $(libsubdir)/ebin
incdir = $(libsubdir)/include

ebin_DATA = $(OTP_RELEASES:=.boot) $(OPT_RELEASES:=.rel)	\
$(OTP_RELEASES:=.script)
EXTRA_DIST = $(OTP_RELEASES:=.rel.in)
CLEANFILES = $(OTP_RELEASES:=.boot) $(OPT_RELEASES:=.rel)	\
$(OTP_RELEASES:=.script)

include $(top_srcdir)/rules.mk
