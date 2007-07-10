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

-compile([export_all]).

%% API
-export([accept_sec_context/1,
	 init_sec_context/3]).

%% Internal exports
-export([]).

-define(TAG_APP_SEQ, 16#60).
-define(TAG_OID, 16#06).

-define(OID_KRB5, {1,2,840,113554,1,2,2}).
-define(OID_SPNEGO, {1,3,6,1,5,5,2}).
%% -define(OID_MS_KRB5, {1,2,840,48018,1,2,2}).
%% -define(OID_NTLM_SSP, {1,3,6,1,4,1,311,2,2,10}).

-define('RT_BER',asn1rt_ber_bin).

%%====================================================================
%% API
%%====================================================================

%%--------------------------------------------------------------------
%% Function: accept_sec_context(Data)
%%           Data = list() | binary(), SPNEGO data, base64 or binary
%% Descrip.: Start gsasl port driver 
%% Returns : {ok, {User, Ccname, Resp}} | {needsmore, Resp} |
%%           {error, Error}
%%           User = list(), authenticated principal
%%           Ccname = list(), credential cache env
%%           Resp = binary(), SPNEGO response
%%--------------------------------------------------------------------
accept_sec_context(Data) when is_list(Data) ->
    accept_sec_context(base64:decode(Data));
accept_sec_context(Data) ->
    {Mode, Token} = decode(Data),
    catch accept_sec_context(Mode, Data, Token).

accept_sec_context(krb5, Data, _Token) ->
    io:format("Krb5 accept~n", []),
    gssapi:accept_sec_context(Data);    
accept_sec_context(spnego, _Data, {negTokenInit, {'NegTokenInit', Types, _ReqFlags, Token, _ListMIC}}) ->
    io:format("negTokenInit~n", []),

    case lists:member(?OID_KRB5, Types) of
	false ->
	    Spnego1 = {negTokenResp, {'NegTokenResp', reject, ?OID_KRB5, [], asn1_NOVALUE}},
	    Resp1 = encode_spnego(Spnego1),
%% 	    {Status, {User, Ccname, Resp1}},
	    throw({error, unsupported_mech});
	true ->
	    ok
    end,

    {Status, {User,Ccname,Resp}} = gssapi:accept_sec_context(list_to_binary(Token)),
    
    Neg_state =
	case Status of
	    ok ->
		'accept-completed';
	    needsmore ->
		'accept-incomplete';
	    error ->
		'reject'
	end,

    Spnego = {negTokenResp, {'NegTokenResp', Neg_state, ?OID_KRB5, Resp, asn1_NOVALUE}},
    {Status, {User, Ccname, encode_spnego(Spnego)}}.

%%--------------------------------------------------------------------
%% Function: init_sec_context(Mech, Service, Hostname)
%%           Mech = atom(), SPNEGO mechanism (krb5 or spnego)
%%           Service = list(), service name (ex. "HTTP")
%%           Hostname = list(), hostname
%% Descrip.: 
%% Returns : {ok, Resp} | {needsmore, Resp} |
%%           {error, Error}
%%           Resp = binary(), SPNEGO response
%%           Error = number(), GSSAPI error code
%%--------------------------------------------------------------------
init_sec_context(Mech, Service, Hostname) when is_atom(Mech) ->
    init_sec_context(Mech, {Service, Hostname}, <<>>, undefined);

init_sec_context(Service, Hostname, Data) when is_list(Data) ->
    init_sec_context(Service, Hostname, base64:decode(Data));
init_sec_context(Service, Hostname, Data) ->
    {Mode, Token} = decode(Data),
    init_sec_context(Mode, {Service, Hostname}, Data, Token).

init_sec_context(krb5, {Service, Hostname}, Data, _Token) ->
    io:format("Krb5 init~n", []),
    gssapi:init_sec_context(Service, Hostname, Data);
init_sec_context(spnego, {Service, Hostname}, _Data, undefined) ->
    init_sec_context_spnego({Service, Hostname}, <<>>);
init_sec_context(spnego, {Service, Hostname}, _Data, {negTokenInit, {'NegTokenInit', _Types, _ReqFlags, Token, _ListMIC}}) ->
    init_sec_context_spnego({Service, Hostname}, list_to_binary(Token)).

init_sec_context_spnego({Service, Hostname}, Token) ->
    io:format("negTokenInit~n", []),
    case gssapi:init_sec_context(Service, Hostname, Token) of
	{error, Reason} ->
	    {error, Reason};
	{Status, Init} ->
	    Spnego = {negTokenInit, {'NegTokenInit', [?OID_KRB5], asn1_NOVALUE, Init, asn1_NOVALUE}},
	    {Status, encode_spnego(Spnego)}
    end.


%%====================================================================
%% Internal functions
%%====================================================================
decode(Data) when is_binary(Data) ->
    {Oid, Blob} = decode_gssapi(Data),
    decode_token(Oid, Blob).

decode_token(?OID_KRB5, Blob) when is_binary(Blob) ->
    io:format("Krb5~n", []),
    {krb5, Blob};
decode_token(?OID_SPNEGO, Blob) when is_binary(Blob) ->
    io:format("SPNEGO~n", []),
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
    io:format("Length ~p~n", [Length]),
    {Oid, Blob} = decode_oid(Rest2),
    io:format("decode~n", []),

    io:format("OID ~p~n", [Oid]),
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


%%====================================================================
%% Test functions
%%====================================================================
test4() ->
    gssapi:start(),
    {ok, Spnego} = spnego:init_sec_context(spnego, "HTTP", "skinner.hem.za.org"),    
    spnego:decode(Spnego),
    ok.

test3() ->
    gssapi:start(),
%%     {ok, Spnego} = spnego:init_sec_context(krb5, "HTTP", "skinner.hem.za.org"),    
    {ok, Spnego} = spnego:init_sec_context(spnego, "HTTP", "skinner.hem.za.org"),    
%%     http:request(get, {"http://192.168.0.2/~mikael/kerberos", [{"Authorization", "Negotiate " ++ base64:encode_to_string(Spnego)}]},[],[]).
    http:request(get, {"http://192.168.0.2/yaws", [{"Authorization", "Negotiate " ++ base64:encode_to_string(Spnego)}]},[],[]).


test2() ->
%%     3 = calc_octets(65536),
%%     <<0>> = encode_length(<<>>),
%%     <<5>> = encode_length(<<1,2,3,4,5>>),
%%     <<131,1,0,0>> = spnego:encode_length(list_to_binary(lists:duplicate(65536, 1))),
%%     Data = <<1,2,3,4>>,
%%     {?OID_KRB5, Data} = decode_gssapi(encode_gssapi(?OID_KRB5, Data)),

    gssapi:start_link("/home/mikael/src/erlang/yaws/http.keytab"),
    {ok, Token2}=init_sec_context(krb5, "HTTP", "skinner.hem.za.org"),
%%     io:format("krb5: ~p~n", [Token2]),
    {ok,_}=accept_sec_context(Token2),
    {ok, Token1}=init_sec_context(spnego, "HTTP", "skinner.hem.za.org"),
%%     io:format("spnego: ~p~n", [Token1]),
    {ok,_}=accept_sec_context(Token1),
    ok.
   

test() ->
    Data3 = get_data(3),
    accept_sec_context(Data3),
    throw(ok),

    Data0 = get_data(0),
    accept_sec_context(Data0),
    Data1 = get_data(1),
    accept_sec_context(Data1),
    Data2 = get_data(2),
    accept_sec_context(Data2),
    {ok, Data3} = file:read_file("spnego_resp.dat"),
%%     decode_spnego(accept, Data3, undefined),
    ok.

get_data(0) ->
    {ok, Data1} = file:read_file("spnego.dat"),
    Data1;
get_data(1) ->
%% Kerberos
    base64:decode("YIICHQYJKoZIhvcSAQICAQBuggIMMIICCKADAgEFoQMCAQ6iBwMFAAAAAACjggEkYYIBIDCCARygAwIBBaEMGwpIRU0uWkEuT1JHoiUwI6ADAgEDoRwwGhsESFRUUBsSc2tpbm5lci5oZW0uemEub3Jno4HfMIHcoAMCARChAwIBBKKBzwSBzBAFkpH4fnCbAxcRIkQ+weDCt7iFFOB47cdoyzyG7fVelqbXbl5Kd4aqG9MdRqp4ZhvirM8RPu/ODhqrK1W6zIA8y/MlSLayk7YW6nExwAzU87vumeoJLGPu7dg7Wj82vEezJUESaVS+vkuwnoRxj/k7fpdUI+S1M9KQczScPEAO9utjPGjfk8tBVBwjgEwnBE5OoiRHzrNHyb/IXBBR6R3x/CAENH+1ziccDANIcW6mzCX6Ag1iwop7OQZXGDYYyjoHcRuhoVS3M1qqU6SByjCBx6ADAgEQooG/BIG8KbVyWFWZVE3vk7flQCxa2LbpPcrDklvjpDohYJoY0bB7zKim+tvb8I7sVdDFXL0J5HGP/X91rZt4h6wMwIdLQTlLQD7V76TWEgE8ZppG8nzjKcASWz7NwIfsq7BbL7L8hqJRjq89Yl8v+LqiEIU9bkFWJw0IiLtY47KCNqePbwVhAcz8at+JQPGaFtIbOUBKGO+gtXwivxeeRCG5mFd3FVBX14Emq4cZsZ7wgRn1FYnEBthaBcLwV0Owq2I=");
get_data(2) ->
    base64:decode("YIICHQYJKoZIhvcSAQICAQBuggIMMIICCKADAgEFoQMCAQ6iBwMFAAAAAACjggEkYYIBIDCCARygAwIBBaEMGwpIRU0uWkEuT1JHoiUwI6ADAgEDoRwwGhsESFRUUBsSc2tpbm5lci5oZW0uemEub3Jno4HfMIHcoAMCARChAwIBBKKBzwSBzBAFkpH4fnCbAxcRIkQ+weDCt7iFFOB47cdoyzyG7fVelqbXbl5Kd4aqG9MdRqp4ZhvirM8RPu/ODhqrK1W6zIA8y/MlSLayk7YW6nExwAzU87vumeoJLGPu7dg7Wj82vEezJUESaVS+vkuwnoRxj/k7fpdUI+S1M9KQczScPEAO9utjPGjfk8tBVBwjgEwnBE5OoiRHzrNHyb/IXBBR6R3x/CAENH+1ziccDANIcW6mzCX6Ag1iwop7OQZXGDYYyjoHcRuhoVS3M1qqU6SByjCBx6ADAgEQooG/BIG8bR0n6kp1+GIDRZ8fXia09QxDDqLvSgUzC4Xmiv0OECMTaeHVlxC7Cu5G/V/za4RJNpp2Q2dSZ767i4OYAiuQkls9nkG7200c/3Hx05IG5b86CgZntGVUjzwS/zz20OTWDy7hz2y4c61Xf6l5GNt8wz+cIsZg+zheWu6YMGuRKM3M8wWlC3z51mc+f7MDRPg71OFqRtTYXmOpM3bs4wJkaxFuXZGE86leD4mWIiP0iYOPbnm+WSZ42BRJXlI=");
get_data(3) ->
    base64:decode("YIIB6AYJKoZIhvcSAQICAQBuggHXMIIB06ADAgEFoQMCAQ6iBwMFAAAAAACjggETYYIBDzCCAQugAwIBBaEMGwpIRU0uWkEuT1JHoiQwIqADAgECoRswGRsDc2lwGxJza2lubmVyLmhlbS56YS5vcmejgc8wgcygAwIBEKEDAgECooG/BIG8MP9EVY6XdQJvbF7z1nN5K8ZAsJmSMXajTTpCyHb3RpXLr8s/mviYhrayuvGf0iS4ZASC7kvbNq+T3lVE4UgLriZqCY2rBhpp66u6Va31HDFlULy7CMO+SstoCkYnPTSwweI9sCxqHfRBwxINfTD4j1yTgW8NZ7XwwHcKGMZTnvVqUPjrya8VhpFVAyXJqi5eGRZlY5fIMcB/mkaWKllNHrXsNv718E2m3T0lVJWVIH7mT8hN3otRgrudmNOkgaYwgaOgAwIBAaKBmwSBmK4qSZTcP50xQj7fo8R6wSAaPhTWXt3SHv1TShQLBkcGen41hUI4Ln1jQTTUg3Ia1CLe+zPBD//gkgZnKbw88nsUeZBCT7KT514UoYcMyS5ZFToa0S6X3MQjf7tmlkRGMFlwRwbv+X9Vao96xNIGGVKtdGm9ycwFd8TNuPgxD0Hy1yQrJSk0j91b7DDjP2W6MUlBgMuj/v2x").
