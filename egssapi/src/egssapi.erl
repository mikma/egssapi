%%%-------------------------------------------------------------------
%%% File    : egssapi.erl
%%% Author  : Mikael Magnusson <mikael@skinner.hem.za.org>
%%% Description : 
%%%
%%% Created : 17 May 2007 by Mikael Magnusson <mikael@skinner.hem.za.org>
%%%-------------------------------------------------------------------
%%%
%%% Copyright (c) 2007 Mikael Magnusson
%%% All rights reserved. 
%%%
%%% Redistribution and use in source and binary forms, with or without 
%%% modification, are permitted provided that the following conditions 
%%% are met: 
%%%
%%% 1. Redistributions of source code must retain the above copyright 
%%%    notice, this list of conditions and the following disclaimer. 
%%%
%%% 2. Redistributions in binary form must reproduce the above copyright 
%%%    notice, this list of conditions and the following disclaimer in the 
%%%    documentation and/or other materials provided with the distribution. 
%%%
%%% 3. Neither the name of the copyright owner nor the names of its
%%%    contributors may be used to endorse or promote products derived from
%%%    this software without specific prior written permission. 
%%%
%%% THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
%%% ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
%%% IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
%%% ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
%%% FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
%%% DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
%%% OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
%%% HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
%%% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
%%% OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
%%% SUCH DAMAGE. 
%%%
-module(egssapi).

-behaviour(gen_server).

%% API
-export([
	 start_link/0,
	 start_link/1,
	 start_link/2,
	 start_link/3,
	 stop/1,
	 accept_sec_context/2,
	 init_sec_context/4,
	 wrap/3,
	 unwrap/2,
	 delete_sec_context/1
	]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

% Internal exports
-export([call_port/2,
	 test/0]).

-include_lib("kernel/include/inet.hrl").

-define(GSSAPI_DRV, "gssapi_drv").
-define(SERVER, ?MODULE).
-define(APP, egssapi).

%%-define(ENABLE_DEBUG, yes).

-ifdef(ENABLE_DEBUG).
-define(INFO, io:format).
-define(DEBUG, io:format).
%% -define(WARNING, io:format).
%% -define(ERROR, io:format).
-else.
-define(INFO, ignore).
-define(DEBUG, ignore).
%% -define(WARNING, ignore).
%% -define(ERROR, ignore).
-endif.

-define(WARNING, io:format).
-define(ERROR, io:format).

-record(context, {
	  server_ref,				% pid()|atom()
	  index=-1				% integer()
	  }).

-record(state, {
	  port,
	  waiting = []
	 }).

%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% Function: start_link([Server_name], [KeyTab, [Ccname]])
%%           Server_name = {local, Name} | {global, Name}
%%           Name = atom()
%%           KeyTab = string(), Keytab filename
%%           Ccname = string(), Credential cache filename
%% Returns:  {ok,Pid} | ignore | {error,Error}
%% Description: Starts the GSSAPI port server
%%--------------------------------------------------------------------
start_link() ->
    start_link("").

start_link(KeyTab) ->
    start_link(KeyTab, "").

start_link(KeyTab, Ccname) when is_list(KeyTab),
				is_list(Ccname) ->
    gen_server:start_link(?MODULE, [KeyTab, Ccname], []);
start_link(Server_name, KeyTab) ->
    start_link(Server_name, KeyTab, "").

start_link(Server_name, KeyTab, Ccname) ->
    gen_server:start_link(Server_name, ?MODULE, [KeyTab, Ccname], []).

%%--------------------------------------------------------------------
%% Function: stop(Server_ref)
%%           Server_ref = pid() | atom()
%% Returns:  ok
%% Description: Stop the GSSAPI port server
%%--------------------------------------------------------------------
stop(Server_ref) ->
    gen_server:cast(Server_ref, stop).


%%--------------------------------------------------------------------
%% Function: accept_sec_context(Server_ref|Context, Data) 
%%           Server_ref = pid() | atom(), pid or registered server name
%%           Context = context record(), security context
%%           Data = binary(), GSSAPI data
%% Descrip.: Start gsasl port driver 
%% Returns : {ok, {Context, User, Ccname, Resp}} |
%%           {needsmore, {Context, Resp}} |
%%           {error, Error}
%%           Context = context record(), security context
%%           User = list(), authenticated principal
%%           Ccname = list(), credential cache env
%%           Resp = binary(), GSSAPI response
%%--------------------------------------------------------------------
accept_sec_context(Context, Data) when is_binary(Data) ->
    Idx = lookup_index(Context),
    Result = call_port(Context, {accept_sec_context, {Idx, Data}}),
%%     io:format("accept_sec_context Result ~p~n", [Result]),

    case Result of
	{ok, {Idx2, User, Ccname, Resp}} ->
	    {ok, {set_index(Context, Idx2), User, Ccname, Resp}};
	{needsmore, {Idx2, Resp}} ->
	    {needsmore, {set_index(Context, Idx2), Resp}};
	{error, Reason} ->
	    {error, Reason}
    end.

%%--------------------------------------------------------------------
%% Function: init_sec_context(Server_ref|Context, Service, Hostname, Data)
%%           Server_ref = pid() | atom(), pid or registered server name
%%           Context = context record(), security context
%%           Service = list(), service name (ex. "HTTP")
%%           Hostname = list(), hostname
%%           Data = binary(), GSSAPI data
%% Descrip.: 
%% Returns : {ok, {Context, Resp}} | {needsmore, {Context, Resp}} |
%%           {error, Error}
%%           Context = context record(), security context
%%           Resp = binary(), GSSAPI response
%%           Error = number(), GSSAPI error code
%%--------------------------------------------------------------------
init_sec_context(Context, Service, Hostname, Data) when is_list(Service),
							is_list(Hostname),
							is_binary(Data) ->
    Idx = lookup_index(Context),
    case call_port(Context, {init_sec_context, {Idx, Service, Hostname, Data}}) of
	{Status, {Idx2, Resp}} ->
	    {Status, {set_index(Context, Idx2), Resp}};
	{error, Reason} ->
	    {error, Reason}
    end.

%%--------------------------------------------------------------------
%% Function: wrap(Context, Conf_req_flag, Input) 
%%           Context = context record(), security context
%%           Conf_req_flag = binary(), confidentiality requested
%%           Input = binary(), data to wrap
%% Descrip.: Sign and possible encrypt data
%% Returns : {ok, {Conf_state, Output}} | {error, Error}
%%           Conf_state = boolean(), confidentiality state
%%           Output = binary(), output
%%           Error = number(), GSSAPI error code
%%--------------------------------------------------------------------
wrap(Context, Conf_req_flag, Input) when is_atom(Conf_req_flag),
					 is_binary(Input) ->
    Idx = lookup_index(Context),
    call_port(Context, {wrap, {Idx, Conf_req_flag, Input}}).

%%--------------------------------------------------------------------
%% Function: unwrap(Context, Input) 
%%           Context = context record(), security context
%%           Input = binary(), data to wrap
%% Descrip.: Verify sign and possible decrypt data
%% Returns : {ok, {Conf_state, Output}} | {error, Error}
%%           Conf_state = boolean(), confidentiality state
%%           Output = binary(), output
%%           Error = number(), GSSAPI error code
%%--------------------------------------------------------------------
unwrap(Context, Input) when is_binary(Input) ->
    Idx = lookup_index(Context),
    call_port(Context, {unwrap, {Idx, Input}}).


%%--------------------------------------------------------------------
%% Function: delete_sec_context(Context) 
%%           Context = context record(), security context
%% Descrip.: Delete security context
%% Returns : {ok, done} | {error, Error}
%%           Error = number(), GSSAPI error code
%%--------------------------------------------------------------------
delete_sec_context(Context) ->
    Idx = lookup_index(Context),
    call_port(Context, {delete_sec_context, Idx}).

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
init([KeyTab, Ccname]) ->
    ExtPrg = filename:join(code:priv_dir(?APP), ?GSSAPI_DRV),
    process_flag(trap_exit, true),
    KeyTabEnv =
	if KeyTab =/= [] ->
		[{"KRB5_KTNAME", KeyTab}];
	   true ->
		[]
	end,
    Ccname_env =
	if Ccname =/= [] ->
		[{"KRB5CCNAME", Ccname}];
	   true ->
		[]
	end,
    Env = {env, KeyTabEnv ++ Ccname_env},
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

call_port(Context, Msg) ->
    Server_ref = lookup_server(Context),
%%     io:format("Call port ~p~n", [Msg]),
    Result = gen_server:call(Server_ref, {call, Msg}),
%%     io:format("Result ~p~n", [Result]),
    Result.

lookup_server(Context) when is_record(Context, context) ->
    Context#context.server_ref;
lookup_server(Context) when is_atom(Context); is_pid(Context) ->
    Context.

lookup_index(Context) when is_record(Context, context) ->
    Context#context.index;
lookup_index(_Context) ->
    -1.

set_index(Context, Idx) when is_record(Context, context) ->
    Context#context{index=Idx};
set_index(Server_ref, Idx) when is_atom(Server_ref); is_pid(Server_ref) ->
    #context{server_ref=Server_ref, index=Idx}.

test() ->
    io:format("~p: test 1~n", [?MODULE]),
    {ok, Server}=start_link("http.keytab"),

    io:format("~p: test 2~n", [?MODULE]),
    {ok, {Ctx, Data}}=init_sec_context(Server, "HTTP", gethostname(),<<>>),

    io:format("~p: test 4~n", [?MODULE]),
    {ok, {Ctx2, User, _Ccname, _Out}} = accept_sec_context(Server, Data),

    io:format("User authenticated: ~s~n", [User]),
    io:format("Test wrap~n", []),

    io:format("~p: test 5~n", [?MODULE]),
    {ok, {false, Out3}} = wrap(Ctx, false, <<"Hello World">>),
    io:format("Wrap ~p~n", [Out3]),

    io:format("~p: test 6~n", [?MODULE]),
    {ok, {false, <<"Hello World">>=Out4}} = unwrap(Ctx2, Out3),
    io:format("Unwrap ~s~n", [Out4]),

    io:format("~p: test 6.1~n", [?MODULE]),
    {ok, {true, Out5}} = wrap(Ctx, true, <<"Hello World">>),
    io:format("Wrap ~p~n", [Out5]),

    io:format("~p: test 6.2~n", [?MODULE]),
    {ok, {true, <<"Hello World">>=Out6}} = unwrap(Ctx2, Out5),
    io:format("Unwrap ~s~n", [Out6]),

    io:format("~p: test 7~n", [?MODULE]),
    {ok, done} = delete_sec_context(Ctx),

    io:format("~p: test 8~n", [?MODULE]),
    {ok, done} = delete_sec_context(Ctx2),

    io:format("~p: test 9~n", [?MODULE]),
    {error, _} = wrap(Ctx, false, <<"Hello World">>),

    stop(Server),

    {ok, Server2}=start_link({local, gssapi_test}, "http.keytab"),
    stop(Server2),

    ok.

gethostname() ->
    {ok, Name} = inet:gethostname(),
    case inet:gethostbyname(Name) of
	{ok, Hostent} when is_record(Hostent, hostent) ->
	    Hostent#hostent.h_name;
	_ ->
	    Name
    end.
