%%%-------------------------------------------------------------------
%%% File    : gssapi_sup.erl
%%% Author  : Mikael Magnusson <mikael@skinner.hem.za.org>
%%% Description : 
%%%
%%% Created : 17 May 2007 by Mikael Magnusson <mikael@skinner.hem.za.org>
%%%-------------------------------------------------------------------
-module(gssapi_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%====================================================================
%% API functions
%%====================================================================
%%--------------------------------------------------------------------
%% Function: start_link() -> {ok,Pid} | ignore | {error,Error}
%% Description: Starts the supervisor
%%--------------------------------------------------------------------
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%====================================================================
%% Supervisor callbacks
%%====================================================================
%%--------------------------------------------------------------------
%% Func: init(Args) -> {ok,  {SupFlags,  [ChildSpec]}} |
%%                     ignore                          |
%%                     {error, Reason}
%% Description: Whenever a supervisor is started using 
%% supervisor:start_link/[2,3], this function is called by the new process 
%% to find out about restart strategy, maximum restart frequency and child 
%% specifications.
%%--------------------------------------------------------------------
init([]) ->
    KeyTab = "/etc/yaws/http.keytab",
    Gss = {gssapi, {gssapi, start_link, [KeyTab]}, permanent, 2000, worker, [gssapi]},
%%     AChild = {'AName',{'AModule',start_link,[]},
%% 	      permanent,2000,worker,['AModule']},
    {ok,{{one_for_all,0,1}, [Gss]}}.

%%====================================================================
%% Internal functions
%%====================================================================
