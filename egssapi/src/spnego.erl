%%%-------------------------------------------------------------------
%%% File    : spnego.erl
%%% Author  : Mikael Magnusson <mikael@skinner.hem.za.org>
%%% Description : SPNEGO wrappers around GSSAPI
%%%
%%% Created :  3 May 2007 by Mikael Magnusson <mikael@skinner.hem.za.org>
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

% Documented in RFC 4178 and RFC 2743 section 3.1
% asn1ct:compile("SPNEGOASNOne",[ber])
-module(spnego).

%% -compile([export_all]).

%% API
-export([accept_sec_context/2,
	 init_sec_context/4,
	 delete_sec_context/1]).

%% Internal exports
-export([test/0]).

-include_lib("kernel/include/inet.hrl").

-define(TAG_APP_SEQ, 16#60).
-define(TAG_OID, 16#06).

-define(OID_KRB5, {1,2,840,113554,1,2,2}).
-define(OID_SPNEGO, {1,3,6,1,5,5,2}).
%% -define(OID_MS_KRB5, {1,2,840,48018,1,2,2}).
%% -define(OID_NTLM_SSP, {1,3,6,1,4,1,311,2,2,10}).

-define('RT_BER',asn1rt_ber_bin).

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

%%====================================================================
%% API
%%====================================================================

%%--------------------------------------------------------------------
%% Function: accept_sec_context(Server_ref|Context, Data)
%%           Server_ref = pid() | atom(), egssapi pid or registered server name
%%           Context = context record(), egssapi security context
%%           Data = binary(), SPNEGO data
%% Descrip.: Accept security context
%% Returns : {ok, {Context, User, Ccname, Resp}} |
%%           {needsmore, {Context, Resp}} |
%%           {error, Error}
%%           Context = context record(), security context
%%           User = list(), authenticated principal
%%           Ccname = list(), credential cache env
%%           Resp = binary(), SPNEGO response
%%--------------------------------------------------------------------
accept_sec_context(Context, Data) ->
    {Mode, Token} = decode(Data),
    catch accept_sec_context(Context, Mode, Data, Token).

accept_sec_context(Context, krb5, Data, _Token) ->
    ?DEBUG("Krb5 accept~n", []),
    egssapi:accept_sec_context(Context, Data);    
accept_sec_context(Context, spnego, _Data, {negTokenInit, {'NegTokenInit', Types, _ReqFlags, Token, _ListMIC}}) ->
    ?DEBUG("negTokenInit~n", []),

    case lists:member(?OID_KRB5, Types) of
	false ->
	    Spnego1 = {negTokenResp, {'NegTokenResp', reject, ?OID_KRB5, [], asn1_NOVALUE}},
	    %% TODO use Resp1
	    _Resp1 = encode_spnego(Spnego1),
%% 	    {Status, {User, Ccname, Resp1}},
	    throw({error, unsupported_mech});
	true ->
	    ok
    end,

    {Status, Value} = egssapi:accept_sec_context(Context, list_to_binary(Token)),
    
    Neg_state =
	case Status of
	    ok ->
		'accept-completed';
	    needsmore ->
		'accept-incomplete';
	    error ->
		'reject'
	end,

    {Context2, User, Ccname, Resp} =
	case Status of
	    error ->
		{undefined, undefined, undefined, asn1_NOVALUE};
	    _ ->
		Value
	end,

    Spnego = {negTokenResp, {'NegTokenResp', Neg_state, ?OID_KRB5, Resp, asn1_NOVALUE}},
    {Status, {Context2, User, Ccname, encode_spnego(Spnego)}}.

%%--------------------------------------------------------------------
%% Function: init_sec_context(Server_ref|Context, Mech, Service, Hostname) |
%%           init_sec_context(Server_ref|Context, Service, Hostname, Data)
%%           Server_ref = pid() | atom(), egssapi pid or registered server name
%%           Context = context record(), egssapi security context
%%           Mech = atom(), SPNEGO mechanism (krb5 or spnego)
%%           Service = list(), service name (ex. "HTTP")
%%           Hostname = list(), hostname
%%           Data = binary(), SPNEGO data
%% Descrip.: Initialize security context
%% Returns : {ok, {Context, Resp}} | {needsmore, {Context, Resp}} |
%%           {error, Error}
%%           Context = context record(), security context
%%           Resp = binary(), SPNEGO response
%%           Error = number(), GSSAPI error code
%%--------------------------------------------------------------------
init_sec_context(Context, Mech, Service, Hostname) when is_atom(Mech) ->
    init_sec_context(Context, Mech, {Service, Hostname}, <<>>, undefined);

init_sec_context(Context, Service, Hostname, Data) ->
    {Mode, Token} = decode(Data),
    init_sec_context(Context, Mode, {Service, Hostname}, Data, Token).

init_sec_context(Context, krb5, {Service, Hostname}, Data, _Token) ->
    ?DEBUG("Krb5 init~n", []),
    egssapi:init_sec_context(Context, Service, Hostname, Data);
init_sec_context(Context, spnego, {Service, Hostname}, _Data, undefined) ->
    init_sec_context_spnego(Context, {Service, Hostname}, <<>>);
init_sec_context(Context, spnego, {Service, Hostname}, _Data, {negTokenInit, {'NegTokenInit', _Types, _ReqFlags, Token, _ListMIC}}) ->
    init_sec_context_spnego(Context, {Service, Hostname}, list_to_binary(Token)).

init_sec_context_spnego(Context, {Service, Hostname}, Token) ->
    ?DEBUG("negTokenInit~n", []),
    case egssapi:init_sec_context(Context, Service, Hostname, Token) of
	{error, Reason} ->
	    {error, Reason};
	{Status, {Context2, Init}} ->
	    Spnego = {negTokenInit, {'NegTokenInit', [?OID_KRB5], asn1_NOVALUE, Init, asn1_NOVALUE}},
	    {Status, {Context2, encode_spnego(Spnego)}}
    end.


%%--------------------------------------------------------------------
%% Function: delete_sec_context(Context) 
%%           Context = context record(), security context
%% Descrip.: Delete security context
%% Returns : {ok, done} | {error, Error}
%%           Error = number(), GSSAPI error code
%%--------------------------------------------------------------------
delete_sec_context(Context) ->
    egssapi:delete_sec_context(Context).

%%====================================================================
%% Internal functions
%%====================================================================
decode(Data) when is_binary(Data) ->
    {Oid, Blob} = decode_gssapi(Data),
    decode_token(Oid, Blob).

decode_token(?OID_KRB5, Blob) when is_binary(Blob) ->
    ?DEBUG("Krb5~n", []),
    {krb5, Blob};
decode_token(?OID_SPNEGO, Blob) when is_binary(Blob) ->
    ?DEBUG("SPNEGO~n", []),
    decode_spnego(Blob).

decode_spnego(Blob) when is_binary(Blob) ->
    {ok, NegotiationToken} = 'SPNEGOASNOneSpec':decode('NegotiationToken', Blob),
    {spnego, NegotiationToken}.

encode_spnego(Spnego) when is_tuple(Spnego) ->
    {ok, Spnego_data} = 'SPNEGOASNOneSpec':encode('NegotiationToken', Spnego),
    encode_gssapi(?OID_SPNEGO, list_to_binary(Spnego_data)).

decode_gssapi(Data) when is_binary(Data) ->
    <<?TAG_APP_SEQ, Rest/binary>> = Data,
    {Length, _, Rest2} = decode_length(Rest),
    ?DEBUG("Length ~p~n", [Length]),
    {Oid, Blob} = decode_oid(Rest2),
    ?DEBUG("decode~n", []),

    ?DEBUG("OID ~p~n", [Oid]),
    {Oid, Blob}.

encode_gssapi(Oid, Token) when is_tuple(Oid),
			       is_binary(Token)->
    Oid_bin = encode_oid(Oid),
    Length_bin = encode_length(size(Token)+size(Oid_bin)),
    <<?TAG_APP_SEQ, Length_bin/binary, Oid_bin/binary, Token/binary>>.

decode_length(Data) when is_binary(Data) ->
    <<B, Rest/binary>> = Data,
    if B < 128 ->
	    {B, 1, Rest};
       B >= 128 ->
	    Size_len = B - 128,
	    Bits = Size_len*8,
	    <<Len:Bits/big, Rest2/binary>> = Rest,
	    {Len, 1 + Size_len, Rest2}
    end.

encode_length(Data) when is_binary(Data) ->
    encode_length(size(Data));
encode_length(Len) when is_number(Len) ->
    if Len < 128 ->
	    << Len >>;
       Len >= 128 ->
	    Size_len = calc_octets(Len),
	    Bits = Size_len*8,
	    << (Size_len+128), Len:Bits/big >>
		end.


calc_octets(Len) when is_number(Len), Len > -1 ->
    calc_octets(Len, 0).

calc_octets(0, Octets) ->
    Octets;
    
calc_octets(Len, Octets) ->
    calc_octets(Len bsr 8, Octets + 1).
    

decode_oid(Data) when is_binary(Data) ->
    {Oid_dec, Blob, _} = ?RT_BER:decode_object_identifier(Data, [], []),
    {Oid_dec, Blob}.

encode_oid(Oid) when is_tuple(Oid) ->
    {Oid_list, _} = ?RT_BER:encode_object_identifier(Oid, []),
    list_to_binary(Oid_list).


ignore(_,_) ->
    ok.


%%====================================================================
%% Test functions
%%====================================================================
test() ->
    3 = calc_octets(65536),
    <<0>> = encode_length(<<>>),
    <<5>> = encode_length(<<1,2,3,4,5>>),
    <<131,1,0,0>> = encode_length(list_to_binary(lists:duplicate(65536, 1))),
    Data = <<1,2,3,4>>,
    {?OID_KRB5, Data} = decode_gssapi(encode_gssapi(?OID_KRB5, Data)),

    {ok, Server} = egssapi:start_link("http.keytab"),
    {ok, {Context2, Token2}}=init_sec_context(Server, krb5, "HTTP", gethostname()),
%%     io:format("krb5: ~p~n", [Token2]),
    {ok, done} = delete_sec_context(Context2),

    {ok,{Context4, _User2, _Ccname2, _Resp2}}=accept_sec_context(Server, Token2),
    {ok, done} = delete_sec_context(Context4),


    {ok, {Context1, Token1}}=init_sec_context(Server, spnego, "HTTP", gethostname()),
    {ok, done} = delete_sec_context(Context1),

%%     io:format("spnego: ~p~n", [Token1]),
    {ok, {Context3, _User1, _Ccname1, _Resp1}}=accept_sec_context(Server, Token1),
    {ok, done} = delete_sec_context(Context3),

    ok = egssapi:stop(Server),
    ok.

gethostname() ->
    {ok, Name} = inet:gethostname(),
    case inet:gethostbyname(Name) of
	{ok, Hostent} when is_record(Hostent, hostent) ->
	    Hostent#hostent.h_name;
	_ ->
	    Name
    end.

