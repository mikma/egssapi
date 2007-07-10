SUBDIRS = 

AM_ERL_FLAGS = -pa `pwd`/../egssapi/ebin -pa ~/tmp/cvs/jungerl/lib/eldap/ebin

run:
	$(ERL) $(AM_ERL_FLAGS) $(ERLFLAGS) -s spnego test4
#	$(ERL) $(AM_ERL_FLAGS) $(ERLFLAGS) -s spnego test2

run-yaws:
	ksu root -e /bin/su yaws -c '/usr/bin/yaws -I debian_yaws -D -heart -name yaws -i'

test-gsasl:
	$(ERL) $(AM_ERL_FLAGS) $(ERLFLAGS) -sname gsasl -run gsasl test xmpp skinner.hem.za.org /home/mikael/src/erlang/ejabberd/xmpp.keytab -s init stop

test-gssapi:
	$(ERL) $(AM_ERL_FLAGS) $(ERL_FLAGS) -s gssapi test -s init stop

test-eldap:
	$(ERL) $(AM_ERL_FLAGS) $(ERLFLAGS) -s eldap_expr test -s init stop
