SUBDIRS = src c_src

ACLOCAL_AMFLAGS = -I m4

all-local:
	test -e ebin || ln -s src ebin
	test -e priv || ln -s c_src priv

clean-local:
	-test -L ebin && $(RM) ebin
	-test -L priv && $(RM) priv
