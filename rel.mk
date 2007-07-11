libsubdir = $(ERLANG_INSTALL_LIB_DIR)/$(OPT_APP)-$($(OPT_APP)_VSN)
bindir = $(libsubdir)/bin
ebindir = $(libsubdir)/ebin
incdir = $(libsubdir)/include

ebin_DATA = $(OPT_RELEASES:=.boot) $(OPT_RELEASES:=.rel)	\
$(OPT_RELEASES:=.script)
EXTRA_DIST = $(OPT_RELEASES:=.rel.in)
CLEANFILES = $(OPT_RELEASES:=.boot) $(OPT_RELEASES:=.rel)	\
$(OPT_RELEASES:=.script)

include $(top_srcdir)/rules.mk
