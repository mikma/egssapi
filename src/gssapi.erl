%%%-------------------------------------------------------------------
%%% File    : test.erl
%%% Author  : Mikael Magnusson <mikael@skinner.hem.za.org>
%%% Description : 
%%%
%%% Created : 17 May 2007 by Mikael Magnusson <mikael@skinner.hem.za.org>
%%%-------------------------------------------------------------------
-module(gssapi).

-behaviour(gen_server).

%% API
-export([
	 start/0,
	 stop/0,
	 accept_sec_context/1,
	 init_sec_context/3
	]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

% Internal exports
-export([start_link/1,
	 call_port/1,
	 test/0]).

-define(GSSAPI_DRV, "gssapi_drv").
-define(SERVER, ?MODULE).
-define(APP, egssapi).

-record(state, {
	  port,
	  waiting = []
	 }).

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% Function: start_link() -> {ok,Pid} | ignore | {error,Error}
%% Description: Starts the server
%%--------------------------------------------------------------------
start() ->
%%    KeyTab = filename:join(code:priv_dir(gssapi), "http.keytab"),
    KeyTab = "/etc/yaws/http.keytab",
    start_link(KeyTab).

%% start(KeyTab) ->
%%     supervisor:start_child(gssapi_sup, {gssapi, {gssapi, start_link, [KeyTab]}, permanent, 2000, worker, [gssapi]}).

start_link(KeyTab) ->
    Prog = filename:join(code:priv_dir(?APP), ?GSSAPI_DRV),
    start_link(KeyTab, Prog).
%%     start("/home/mikael/src/erlang/yaws/gssapi_drv").

start_link(KeyTab, ExtPrg) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [KeyTab, ExtPrg], []).

stop() ->
    gen_server:cast(?SERVER, stop).

accept_sec_context(Base64) when is_list(Base64) ->
    Data = base64:decode(Base64),
    accept_sec_context(Data);
accept_sec_context(Data) when is_binary(Data) ->
    Result = call_port({accept_sec_context, Data}),
%%     io:format("accept_sec_context Result ~p~n", [Result]),

    case Result of
	{ok, {User, Ccname, Resp}} ->
	    {ok, {User, Ccname, base64:encode(Resp)}};
	{error, Reason} ->
	    {error, Reason}
    end.

init_sec_context(Service, Hostname, Data) when is_list(Service),
					       is_list(Hostname),
					       is_binary(Data) ->
    call_port({init_sec_context, {Service, Hostname, Data}}).

%%====================================================================
%% gen_server callbacks
%%====================================================================

%%--------------------------------------------------------------------
%% Function: init(Args) -> {ok, State} |
%%                         {ok, State, Timeout} |
%%                         ignore               |
%%                         {stop, Reason}
%% Description: Initiates the server
%%--------------------------------------------------------------------
init([KeyTab, ExtPrg]) ->
    process_flag(trap_exit, true),
    Env = {env, [{"KRB5_KTNAME", KeyTab}]},
    Port = open_port({spawn, ExtPrg}, [{packet, 2}, binary, exit_status, Env]),
    {ok, #state{port=Port}}.

%%--------------------------------------------------------------------
%% Function: %% handle_call(Request, From, State) -> {reply, Reply, State} |
%%                                      {reply, Reply, State, Timeout} |
%%                                      {noreply, State} |
%%                                      {noreply, State, Timeout} |
%%                                      {stop, Reason, Reply, State} |
%%                                      {stop, Reason, State}
%% Description: Handling call messages
%%--------------------------------------------------------------------
handle_call({call, Msg}, From, State) ->
    %%         io:format("Calling port with ~p~n", [Msg]),
    Port = State#state.port,
    erlang:port_command(Port, term_to_binary(Msg)),

    Waiting = State#state.waiting ++ [From],
    {noreply, State#state{waiting=Waiting}};

handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%%--------------------------------------------------------------------
%% Function: handle_cast(Msg, State) -> {noreply, State} |
%%                                      {noreply, State, Timeout} |
%%                                      {stop, Reason, State}
%% Description: Handling cast messages
%%--------------------------------------------------------------------
handle_cast(stop, State) ->
    erlang:port_close(State#state.port),
    {stop, normal, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% Function: handle_info(Info, State) -> {noreply, State} |
%%                                       {noreply, State, Timeout} |
%%                                       {stop, Reason, State}
%% Description: Handling all non call/cast messages
%%--------------------------------------------------------------------
handle_info({Port, {data, Data}}, State = #state{port=Port}) ->
    Term = binary_to_term(Data),
    [From | Rest] = State#state.waiting,
    %% 		io:format("Result ~p~n", [Term]),
    gen_server:reply(From, Term),
    {noreply, State#state{waiting=Rest}};

handle_info({Port, {exit_status, Status}}, State = #state{port=Port}) when Status > 128 ->
    io:format("Port terminated with signal: ~p~n", [Status-128]),
    {stop, {port_terminated, Status}, State};

handle_info({Port, {exit_status, Status}}, State = #state{port=Port}) ->
    io:format("Port terminated with status: ~p~n", [Status]),
    {stop, {port_terminated, Status}, State};

handle_info({'EXIT', Port, Reason}, State = #state{port=Port}) ->
    {stop, Reason, State};

handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% Function: terminate(Reason, State) -> void()
%% Description: This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any necessary
%% cleaning up. When it returns, the gen_server terminates with Reason.
%% The return value is ignored.
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% Func: code_change(OldVsn, State, Extra) -> {ok, NewState}
%% Description: Convert process state when code is changed
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------

call_port(Msg) ->
%%     io:format("Call port ~p~n", [Msg]),
    Result = gen_server:call(?MODULE, {call, Msg}),
%%     io:format("Result ~p~n", [Result]),
    Result.

test() ->
    start_link("/home/mikael/src/erlang/yaws/http.keytab"),
%%     init_sec_context("HTTP", "skinner.hem.za.org",list_to_binary(lists:duplicate(1096, 17))),
    {ok, Data2}=init_sec_context("HTTP", "skinner.hem.za.org",<<>>),
%%     accept_sec_context(Data),
    {ok, {User, Ccname, Out}} = accept_sec_context(Data2),
    io:format("User authenticated: ~s~n", [User]),
    ok.
