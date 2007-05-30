%%%-------------------------------------------------------------------
%%% File    : spnego.erl
%%% Author  : Mikael Magnusson <mikael@skinner.hem.za.org>
%%% Description : 
%%%
%%% Created :  3 May 2007 by Mikael Magnusson <mikael@skinner.hem.za.org>
%%%-------------------------------------------------------------------

% TODO return SPNEGO responses
% Documented in RFC 2743 section 3.1
% asn1ct:compile("SPNEGOASNOne",[ber])
-module(spnego).

-export([decode/1, test/0]).

-define(TAG_APP_SEQ, 16#60).
-define(TAG_OID, 16#06).

-define(OID_KRB5, {1,2,840,113554,1,2,2}).
-define(OID_SPNEGO, {1,3,6,1,5,5,2}).
%% -define(OID_MS_KRB5, {1,2,840,48018,1,2,2}).
%% -define(OID_NTLM_SSP, {1,3,6,1,4,1,311,2,2,10}).

-define('RT_BER',asn1rt_ber_bin).

decode(Data) when is_list(Data) ->
    decode(base64:decode(Data));
decode(Data) ->
    <<Debug:32/binary, _/binary>> = Data,
    io:format("Debug ~p~n", [Debug]),

    <<?TAG_APP_SEQ, Rest/binary>> = Data,
    {Length, _, Rest2} = get_length(Rest),
    io:format("Length ~p~n", [Length]),
    {Oid, Blob} = get_oid(Rest2, Length),
    io:format("decode~n", []),

    io:format("OID ~p~n", [Oid]),
    decode_token(Oid, Blob, Data).
    

decode_token(?OID_KRB5, Blob, Data) ->
    io:format("Krb5~n", []),
    gssapi:negotiate(Data);
decode_token(?OID_SPNEGO, Blob, _Data) ->
    io:format("SPNEGO~n", []),
    decode_spnego(Blob).

decode_spnego(Blob) ->
    {ok, NegotiationToken} = 'SPNEGOASNOneSpec':decode('NegotiationToken', Blob),
    handle_spnego(NegotiationToken).

handle_spnego({negTokenInit, {'NegTokenInit', _Types, _ReqFlags, Token, _ListMIC}}) ->
    io:format("negTokenInit~n", []),
    gssapi:negotiate(list_to_binary(Token));
handle_spnego({negTokenResp, {'NegTokenResp', NegState, _Type, Token, _ListMIC}}) ->
    io:format("negTokenResp:~n", []),
    handle_spnego_resp(NegState, Token).

handle_spnego_resp('accept-completed', Token) ->
    Token.

get_length(Data) ->
    <<B, Rest/binary>> = Data,
    if B < 128 ->
	    {B, 1, Rest};
       B >= 128 ->
	    Size_len = B - 128,
	    Bits = Size_len*8,
	    <<Len:Bits/big, Rest2/binary>> = Rest,
	    {Len, 1 + Size_len, Rest2}
    end.


get_oid(Data, Length) ->
    <<?TAG_OID, Rest1/binary>> = Data,
    case length(binary_to_list(Rest1)) of
	Length ->
	    ok;
	Length2 ->
	    io:format("Length no match ~p ~p~n", [Length, Length2])
    end,
    {Oid_len, Size_len, Rest2} = get_length(Rest1),
    io:format("Length ~p ~p~n", [Oid_len, Size_len]),
    Oid_len2 = Oid_len + Size_len + 1,
    <<Oid:Oid_len2/binary, Blob/binary>> = Data,

    io:format("Raw OID ~p~n", [Oid]),
    {Oid_dec, <<>>, _} = ?RT_BER:decode_object_identifier(Oid, [], []),

    {Oid_dec, Blob}.


test() ->
    Data3 = get_data(3),
    decode(Data3),
    throw(ok),

    Data0 = get_data(0),
    decode(Data0),
    Data1 = get_data(1),
    decode(Data1),
    Data2 = get_data(2),
    decode(Data2),
    {ok, Data3} = file:read_file("spnego_resp.dat"),
    decode_spnego(Data3),
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
