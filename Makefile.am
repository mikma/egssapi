SUBDIRS = egssapi

AM_ERL_FLAGS = -pa egssapi/ebin

run-yaws:
	ksu root -e /bin/su yaws -c '/usr/bin/yaws -I debian_yaws -D -heart -name yaws -i'

check:
	$(MAKE) check-gssapi
	$(MAKE) check-spnego

check-spnego:
	$(ERL) $(AM_ERL_FLAGS) $(ERL_FLAGS) -s spnego test -s init stop

check-gssapi:
	$(ERL) $(AM_ERL_FLAGS) $(ERL_FLAGS) -s gssapi test -s init stop
