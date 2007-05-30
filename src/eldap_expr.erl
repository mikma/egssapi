%%% Based on eldap_test.erl

-module(eldap_expr).

-export([test/0,
	 test/1]).

test() ->
    test("").

test(Ccname) ->
%%     Pid = gsasl:start("", Ccname),
    Host = "mulder.hem.za.org",
    {ok, Handle} = topen_bind(Host),
    io:format("open ~p~n", [Handle]),
    Base_dn = "dc=hem, dc=za, dc=org",
    Filter = eldap:equalityMatch("uid","mikael"),
    X=(catch eldap:search(Handle, [{base, Base_dn},
			      {filter, Filter},
			      {scope,eldap:wholeSubtree()}])),
    io:format("~p~n",[X]),
    eldap:close(Handle).
%%     gsasl:stop(Pid).

topen_bind(Host) -> 
%%     topen_bind(Host, debug(t)).
    topen_bind(Host, debug(f)).

topen_bind(Host, Dbg) -> 
    Options = [],
    do_open_bind(Host, Dbg, Options).

do_open_bind(Host, LogFun, Options) ->
    Opts = [{log,LogFun}],
    {ok,Handle} = eldap:open([Host], Opts),
    {eldap:sasl_bind(Handle, Options),
     Handle}.

debug(t) -> fun(L,S,A) -> io:format("--- " ++ S, A) end;
debug(1) -> fun(L,S,A) when L =< 1 -> io:format("--- " ++ S, A) end;
debug(2) -> fun(L,S,A) when L =< 2 -> io:format("--- " ++ S, A) end;
debug(f) -> false.
