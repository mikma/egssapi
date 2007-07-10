%%%-------------------------------------------------------------------
%%% File    : test.erl
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
-module(gssapi).

-behaviour(gen_server).

%% API
-export([
	 start_link/0,
	 start_link/1,
	 start_link/2,
	 stop/0,
	 accept_sec_context/1,
	 init_sec_context/3,
	 wrap/3,
	 unwrap/2
	]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

% Internal exports
-export([call_port/1,
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
start_link() ->
    KeyTab = "/etc/yaws/http.keytab",
    start_link(KeyTab).

start_link(KeyTab) ->
    start_link(KeyTab, "").

start_link(KeyTab, Ccname) ->
    ExtPrg = filename:join(code:priv_dir(?APP), ?GSSAPI_DRV),
    gen_server:start_link({local, ?SERVER}, ?MODULE, [KeyTab, ExtPrg, Ccname], []).

stop() ->
    gen_server:cast(?SERVER, stop).

accept_sec_context(Base64) when is_list(Base64) ->
    Data = base64:decode(Base64),
    accept_sec_context(Data);
accept_sec_context(Data) when is_binary(Data) ->
    accept_sec_context(-1, Data).

accept_sec_context(Idx, Data) when is_integer(Idx), is_binary(Data) ->
    Result = call_port({accept_sec_context, {Idx, Data}}),
%%     io:format("accept_sec_context Result ~p~n", [Result]),

    case Result of
	{ok, {Idx2, User, Ccname, Resp}} ->
	    {ok, {Idx2, User, Ccname, base64:encode(Resp)}};
	{error, Reason} ->
	    {error, Reason}
    end.

init_sec_context(Service, Hostname, Data) when is_list(Service),
					       is_list(Hostname),
					       is_binary(Data) ->
    init_sec_context(-1, Service, Hostname, Data).

init_sec_context(Idx, Service, Hostname, Data) when is_integer(Idx),
						    is_list(Service),
						    is_list(Hostname),
						    is_binary(Data) ->
    call_port({init_sec_context, {Idx, Service, Hostname, Data}}).

wrap(Idx, Conf_req_flag, Input) when is_integer(Idx),
				     is_atom(Conf_req_flag),
				     is_binary(Input) ->
    call_port({wrap, {Idx, Conf_req_flag, Input}}).

unwrap(Idx, Input) when is_integer(Idx),
			is_binary(Input) ->
    call_port({unwrap, {Idx, Input}}).

delete_sec_context(Idx) when is_integer(Idx) ->
    call_port({delete_sec_context, Idx}).

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
init([KeyTab, ExtPrg, Ccname]) ->
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

call_port(Msg) ->
%%     io:format("Call port ~p~n", [Msg]),
    Result = gen_server:call(?MODULE, {call, Msg}),
%%     io:format("Result ~p~n", [Result]),
    Result.

test() ->
    io:format("~p: test 1~n", [?MODULE]),
    start_link("/home/mikael/src/erlang/yaws/http.keytab"),

    io:format("~p: test 2~n", [?MODULE]),
    {ok, {Idx, Data}}=init_sec_context("HTTP", "skinner.hem.za.org",<<>>),

    io:format("~p: test 4~n", [?MODULE]),
    {ok, {Idx2, User, Ccname, Out}} = accept_sec_context(Data),

    io:format("User authenticated: ~s~n", [User]),
    io:format("Test wrap~n", []),

    io:format("~p: test 5~n", [?MODULE]),
    {ok, {false, Out3}} = wrap(Idx, false, <<"Hello World">>),
    io:format("Wrap ~p~n", [Out3]),

    io:format("~p: test 6~n", [?MODULE]),
    {ok, {false, <<"Hello World">>=Out4}} = unwrap(Idx2, Out3),
    io:format("Unwrap ~s~n", [Out4]),

    io:format("~p: test 7~n", [?MODULE]),
    {ok, done} = delete_sec_context(Idx),

    io:format("~p: test 8~n", [?MODULE]),
    {ok, done} = delete_sec_context(Idx2),

    io:format("~p: test 9~n", [?MODULE]),
    {error, _} = wrap(Idx, false, <<"Hello World">>),
    ok.
