SUBDIRS = egssapi

AM_ERL_FLAGS = -pa egssapi/ebin

run:
	$(ERL) $(AM_ERL_FLAGS) $(ERLFLAGS) -s spnego test4
#	$(ERL) $(AM_ERL_FLAGS) $(ERLFLAGS) -s spnego test2

run-yaws:
	ksu root -e /bin/su yaws -c '/usr/bin/yaws -I debian_yaws -D -heart -name yaws -i'

check:
	$(ERL) $(AM_ERL_FLAGS) $(ERL_FLAGS) -s gssapi test -s init stop
