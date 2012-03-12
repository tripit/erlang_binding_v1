%
% Copyright 2008-2012 Concur Technologies, Inc.
%
% Licensed under the Apache License, Version 2.0 (the "License"); you may
% not use this file except in compliance with the License. You may obtain
% a copy of the License at
%
%     http://www.apache.org/licenses/LICENSE-2.0
%
% Unless required by applicable law or agreed to in writing, software
% distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
% WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
% License for the specific language governing permissions and limitations
% under the License.

-module(tripit).
-behaviour(gen_server).

% Public API
-export([start_link/1, start_link/2]).
-export([credential/1, get_request_token/1, get_access_token/1]).
-export([get_trip/2, get_trip/3, get_air/2, get_lodging/2, get_car/2, get_profile/2, get_rail/2]).
-export([get_transport/2, get_cruise/2, get_restaurant/2, get_activity/2, get_note/2, get_map/2, get_directions/2]).
-export([get_points_program/2]).
-export([delete_trip/2, delete_air/2, delete_lodging/2, delete_car/2, delete_rail/2]).
-export([delete_transport/2, delete_cruise/2, delete_restaurant/2, delete_activity/2, delete_note/2]).
-export([delete_map/2, delete_directions/2]).
-export([replace_trip/3, replace_air/3, replace_lodging/3, replace_car/3, replace_rail/3]).
-export([replace_transport/3, replace_cruise/3, replace_restaurant/3, replace_activity/3, replace_note/3]).
-export([replace_map/3, replace_directions/3]).
-export([list_trip/1, list_trip/2, list_object/1, list_object/2, list_points_program/1, create/2]).
-export([crs_load_reservations/2, crs_load_reservations/3, crs_delete_reservations/2]).
-export([oauth_credential/2, oauth_credential/3, oauth_credential/4, webauth_credential/2]).

% gen_server
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(API_VERSION, "v1").
-define(OAUTH_SIGNATURE_METHOD, "HMAC-SHA1").
-define(OAUTH_VERSION, "1.0").

-record(state, {
    credential,
    api_url
    }).

start_link(Credential) -> start_link(Credential, "https://api.tripit.com").
start_link(Credential, ApiUrl) ->
    crypto:start(),
    ssl:start(),
    ssl:seed(crypto:rand_bytes(512)),
    inets:start(),
    gen_server:start_link(?MODULE, [Credential, ApiUrl], []).

init([Credential, ApiUrl]) ->
    {ok, #state{credential=Credential, api_url=ApiUrl}}.

credential(Self) ->
    gen_server:call(Self, {credential}).

get_request_token(Self) ->
    gen_server:call(Self, {get_request_token}).
    
get_access_token(Self) ->
    gen_server:call(Self, {get_access_token}).

get_trip(Self, Id) -> get_trip(Self, Id, []).
get_trip(Self, Id, Filter) ->
    request(Self, "get", "trip", [{id, Id}|Filter]).

get_air(Self, Id) ->
    request(Self, "get", "air", [{id, Id}]).
    
get_lodging(Self, Id) ->
    request(Self, "get", "lodging", [{id, Id}]).

get_car(Self, Id) ->
    request(Self, "get", "car", [{id, Id}]).

get_profile(Self, Id) ->
    request(Self, "get", "profile", [{id, Id}]).

get_rail(Self, Id) ->
    request(Self, "get", "rail", [{id, Id}]).

get_transport(Self, Id) ->
    request(Self, "get", "transport", [{id, Id}]).
    
get_cruise(Self, Id) ->
    request(Self, "get", "cruise", [{id, Id}]).

get_restaurant(Self, Id) ->
    request(Self, "get", "restaurant", [{id, Id}]).

get_activity(Self, Id) ->
    request(Self, "get", "activity", [{id, Id}]).

get_note(Self, Id) ->
    request(Self, "get", "air", [{id, Id}]).

get_map(Self, Id) ->
    request(Self, "get", "air", [{id, Id}]).

get_directions(Self, Id) ->
    request(Self, "get", "air", [{id, Id}]).

get_points_program(Self, Id) ->
    request(Self, "get", "points_program", [{id, Id}]).

delete_trip(Self, Id) ->
    request(Self, "delete", "trip", [{id, Id}]).

delete_air(Self, Id) ->
    request(Self, "delete", "air", [{id, Id}]).

delete_lodging(Self, Id) ->
    request(Self, "delete", "lodging", [{id, Id}]).
    
delete_car(Self, Id) ->
    request(Self, "delete", "car", [{id, Id}]).

delete_rail(Self, Id) ->
    request(Self, "delete", "rail", [{id, Id}]).

delete_transport(Self, Id) ->
    request(Self, "delete", "transport", [{id, Id}]).

delete_cruise(Self, Id) ->
    request(Self, "delete", "cruise", [{id, Id}]).

delete_restaurant(Self, Id) ->
    request(Self, "delete", "restaurant", [{id, Id}]).

delete_activity(Self, Id) ->
    request(Self, "delete", "activity", [{id, Id}]).

delete_note(Self, Id) ->
    request(Self, "delete", "note", [{id, Id}]).

delete_map(Self, Id) ->
    request(Self, "delete", "map", [{id, Id}]).

delete_directions(Self, Id) ->
    request(Self, "delete", "directions", [{id, Id}]).

replace_trip(Self, Id, Xml) ->
    request(Self, "replace", "trip", [{id, Id}, {xml, Xml}]).

replace_air(Self, Id, Xml) ->
    request(Self, "replace", "air", [{id, Id}, {xml, Xml}]).

replace_lodging(Self, Id, Xml) ->
    request(Self, "replace", "lodging", [{id, Id}, {xml, Xml}]).
    
replace_car(Self, Id, Xml) ->
    request(Self, "replace", "car", [{id, Id}, {xml, Xml}]).

replace_rail(Self, Id, Xml) ->
    request(Self, "replace", "rail", [{id, Id}, {xml, Xml}]).

replace_transport(Self, Id, Xml) ->
    request(Self, "replace", "transport", [{id, Id}, {xml, Xml}]).

replace_cruise(Self, Id, Xml) ->
    request(Self, "replace", "cruise", [{id, Id}, {xml, Xml}]).

replace_restaurant(Self, Id, Xml) ->
    request(Self, "replace", "restaurant", [{id, Id}, {xml, Xml}]).

replace_activity(Self, Id, Xml) ->
    request(Self, "replace", "activity", [{id, Id}, {xml, Xml}]).

replace_note(Self, Id, Xml) ->
    request(Self, "replace", "note", [{id, Id}, {xml, Xml}]).

replace_map(Self, Id, Xml) ->
    request(Self, "replace", "map", [{id, Id}, {xml, Xml}]).

replace_directions(Self, Id, Xml) ->
    request(Self, "replace", "directions", [{id, Id}, {xml, Xml}]).

list_trip(Self) -> list_trip(Self, []).
list_trip(Self, Filter) ->
    request(Self, "list", "trip", Filter).
    
list_object(Self) -> list_object(Self, []).
list_object(Self, Filter) ->
    request(Self, "list", "object", Filter).

list_points_program(Self) ->
    request(Self, "list", "points_program", []).
    
create(Self, Xml) ->
    request(Self, "create", undefined, undefined, [{xml, Xml}]).
    
crs_load_reservations(Self, Xml) ->
    crs_load_reservations(Self, Xml, undefined).

crs_load_reservations(Self, Xml, CompanyKey) ->
    Args0 = [{xml, Xml}],
    Args = case CompanyKey of
        undefined -> Args0;
        _ -> [{company_key, CompanyKey}|Args0]
    end,
    request(Self, "crsLoadReservations", undefined, undefined, Args).
    
crs_delete_reservations(Self, RecordLocator) ->
    request(Self, "crsDeleteReservations", undefined, [{record_locator, RecordLocator}], undefined).

request(Self, Verb, Entity, Params) -> request(Self, Verb, Entity, Params, undefined).
request(Self, Verb, Entity, Params, PostArgs) ->
    gen_server:call(Self, {request, Verb, Entity, Params, PostArgs}).

do_request(State, Verb) -> do_request(State, undefined, Verb, undefined, undefined, undefined).
do_request(
    #state{
        credential=Credential,
        api_url=ApiUrl
    },
    From, Verb, Entity, Params, PostArgs)
    ->
    BaseUrl = if
        Verb == "/oauth/request_token" -> ApiUrl ++ Verb;
        Verb == "/oauth/access_token" -> ApiUrl ++ Verb;
        Entity == undefined -> ApiUrl ++ "/" ++ ?API_VERSION ++ "/" ++ Verb;
        true -> ApiUrl ++ "/" ++ ?API_VERSION ++ "/" ++ Verb ++ "/" ++ Entity
    end,
    {Method, Request, Args} = if
        Params /= undefined ->
            {
                get, % method
                {
                    BaseUrl ++ "?" ++ urlencode_args(Params), % URL
                    [] % Headers
                },
                Params
            };
        PostArgs /= undefined ->
            {
                post, % method
                {
                    BaseUrl, % URL
                    [], % Headers
                    "application/x-www-form-urlencoded", % Content-Type (TODO),
                    urlencode_args(PostArgs) % Body
                },
                PostArgs
            };
        true ->
            {get, {BaseUrl, []}, undefined}
    end,
    
    AuthenticatedRequest = Credential({authorize, Method, ApiUrl, BaseUrl, Request, Args}),
    
    Reply = case http:request(Method, AuthenticatedRequest, [], []) of
        {ok, {{_Version, 200, _Phrase}, _Headers, ResultBody}} -> {ok, ResultBody};
        {ok, {{_Version, Code, Phrase}, _Headers, ResultBody}} -> {error, Code, Phrase, ResultBody};
        {error, Reason} -> {error, Reason}
    end,
    
    if
        From /= undefined -> gen_server:reply(From, Reply);
        true -> Reply
    end.

get_token(State, Credential, Type) ->
    ParamDict = parse_query_string(do_request(State, "/oauth/" ++ Type ++ "_token")),
    Token = dict:fetch("oauth_token", ParamDict),
    Secret = dict:fetch("oauth_token_secret", ParamDict),
    oauth_credential(Credential(consumer_key), Credential(consumer_secret), Token, Secret).

handle_call(Request, From, State = #state{credential=Credential}) ->
    case Request of
        {credential} ->
            {reply, {ok, Credential}, State};
        
        {get_request_token} ->
            Credential2 = get_token(State, Credential, "request"),
            {reply, {ok, Credential2}, State#state{credential=Credential2}};
        
        {get_access_token} ->
            Credential2 = get_token(State, Credential, "access"),
            {reply, {ok, Credential2}, State#state{credential=Credential2}};
        
        {request, Verb, Entity, Params, PostArgs} ->
            spawn_link(fun() ->
                do_request(State, From, Verb, Entity, Params, PostArgs)
            end),
            {noreply, State}
    end.
    
handle_cast(_Request, State = #state{}) ->
    {noreply, State}.
    
handle_info(_Request, State = #state{}) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVer, State, _Extra) ->
    {ok, State}.

urldecode(String) -> urldecode(String, "").
urldecode("", Acc) -> lists:reverse(Acc);
urldecode([$%, Hi, Lo|Tail], Acc) ->
    urldecode(Tail, [erlang:list_to_integer([Hi, Lo], 16)|Acc]);
urldecode([C|Tail], Acc) when is_integer(C) ->
    urldecode(Tail, [C|Acc]);
urldecode([List|Tail], Acc) when is_list(List) ->
    urldecode(Tail, [urldecode(List)|Acc]).

urlencode(Int) when is_integer(Int) -> urlencode(integer_to_list(Int));
urlencode(Bin) when is_binary(Bin) -> urlencode(binary_to_list(Bin));
urlencode(Atom) when is_atom(Atom) -> urlencode(atom_to_list(Atom));
urlencode(String) when is_list(String) -> lists:flatten(lists:reverse(urlencode(String, []))).
urlencode([], Acc) -> Acc;
urlencode([C|Rest], Acc) when C >= $a, C =< $z -> urlencode(Rest, [C|Acc]);
urlencode([C|Rest], Acc) when C >= $A, C =< $Z -> urlencode(Rest, [C|Acc]);
urlencode([C|Rest], Acc) when C >= $0, C =< $9 -> urlencode(Rest, [C|Acc]);
urlencode([C|Rest], Acc) when C =:= $_ -> urlencode(Rest, [C|Acc]);
urlencode([C|Rest], Acc) when C =:= $. -> urlencode(Rest, [C|Acc]);
urlencode([C|Rest], Acc) when C =:= $- -> urlencode(Rest, [C|Acc]);
urlencode([C|Rest], Acc) when C =:= $~ -> urlencode(Rest, [C|Acc]);
urlencode([C|Rest], Acc) ->
    urlencode(Rest, [io_lib:format("%~2.16.0B", [C]) | Acc]).

urlencode_args(Args) ->
    string:join(
        lists:map(
            fun({Key, Value}) -> urlencode(Key) ++ [$=|urlencode(Value)] end,
            Args
        ),
    "&").

json_encode_string(Bin) when is_binary(Bin) -> json_encode_string(binary_to_list(Bin));
json_encode_string(Int) when is_integer(Int) -> json_encode_string(integer_to_list(Int));
json_encode_string(Atom) when is_atom(Atom) -> json_encode_string(atom_to_list(Atom));
json_encode_string(String) -> json_encode_string(String, "").
json_encode_string("", Acc) -> lists:reverse(Acc);
json_encode_string([$"|Rest], Acc) -> json_encode_string(Rest, [$", $\\|Acc]);
json_encode_string([$\\|Rest], Acc) -> json_encode_string(Rest, [$\\, $\\|Acc]);
json_encode_string([$\b|Rest], Acc) -> json_encode_string(Rest, [$b, $\\|Acc]);
json_encode_string([$\f|Rest], Acc) -> json_encode_string(Rest, [$f, $\\|Acc]);
json_encode_string([$\n|Rest], Acc) -> json_encode_string(Rest, [$n, $\\|Acc]);
json_encode_string([$\r|Rest], Acc) -> json_encode_string(Rest, [$r, $\\|Acc]);
json_encode_string([$\t|Rest], Acc) -> json_encode_string(Rest, [$t, $\\|Acc]);
json_encode_string([C|Rest], Acc) -> json_encode_string(Rest, [C|Acc]).

split_on_equals(String) -> split_on_equals(String, []).
split_on_equals([], Acc) ->
    {lists:reverse(Acc), ""};
split_on_equals([$=|Rest], Acc) ->
    {lists:reverse(Acc), Rest};
split_on_equals([Char|Rest], Acc) ->
    split_on_equals(Rest, [Char|Acc]).

parse_query_string(String) ->
    dict:from_list(lists:map(fun split_on_equals/1, string:tokens(String, "&"))).

% Credentials

webauth_credential(Username, Password) ->
    AuthHeader = "Basic " ++ binary_to_list(base64:encode(Username ++ [$:|Password])),
    fun
        ({authorize, _Method, _Realm, _BaseUrl, Request, _Args}) ->
            request_add_header(Request, "Authorization", AuthHeader)
    end.

oauth_credential(ConsumerKey, ConsumerSecret) ->
    oauth_credential(ConsumerKey, ConsumerSecret, "", "").
oauth_credential(ConsumerKey, ConsumerSecret, Token, TokenSecret) ->
    fun
        (consumer_key) -> ConsumerKey;
        (consumer_secret) -> ConsumerSecret;
        (token) -> Token;
        (token_secret) -> TokenSecret;
        ({get_session_parameters, Url, Action}) ->
            get_session_parameters(Url, Action, ConsumerKey, ConsumerSecret, Token, TokenSecret);
        ({validate_signature, Url}) ->
            validate_signature(Url, ConsumerSecret, TokenSecret);
        
        ({authorize, Method, Realm, BaseUrl, Request, Args}) ->
            request_add_header(Request, "Authorization",
                generate_authorization_header(Method, Realm, BaseUrl, Args,
                    ConsumerKey, ConsumerSecret, Token, TokenSecret))
    end.

% 2-legged authentication
oauth_credential(ConsumerKey, ConsumerSecret, RequestorId) ->
    fun
        (consumer_key) -> ConsumerKey;
        (consumer_secret) -> ConsumerSecret;
        (requestor_id) -> RequestorId;
        ({get_session_parameters, Url, Action}) ->
            get_session_parameters(Url, Action, ConsumerKey, ConsumerSecret, "", "");
        ({validate_signature, Url}) ->
            validate_signature(Url, ConsumerSecret, "");
        
        ({authorize, Method, Realm, BaseUrl, Request, Args}) ->
            request_add_header(Request, "Authorization",
                generate_authorization_header(Method, Realm, BaseUrl,
                    [{xoauth_requestor_id, RequestorId}|Args],
                    ConsumerKey, ConsumerSecret, "", ""))
    end.

get_session_parameters(Url, Action, ConsumerKey, ConsumerSecret, Token, TokenSecret) ->
    Params1 = generate_oauth_parameters(get, Action, [{"redirect_url", Url}], ConsumerKey, ConsumerSecret, Token, TokenSecret),
    Params2 = dict:to_list(dict:merge(
        fun(_, _, V) -> V end,
        dict:from_list(Params1),
        dict:from_list([
            {redirect_url, Url},
            {action, Action}
        ]))),
    lists:flatten(["{", string:join(lists:map(fun({K, V}) ->
        ["\"", json_encode_string(K), "\": \"", json_encode_string(V), "\""]
    end, Params2), ","), "}"]).

generate_authorization_header(Method, Realm, BaseUrl, Args,
    ConsumerKey, ConsumerSecret, Token, TokenSecret)
    ->
    "OAuth realm=\"" ++ Realm ++ "\"," ++
        string:join(
            lists:map(
                fun({Key, Value}) ->
                    urlencode(Key) ++ [$=, $"|urlencode(Value)] ++ "\""
                end,
                generate_oauth_parameters(Method, BaseUrl, Args,
                    ConsumerKey, ConsumerSecret, Token, TokenSecret)
            ),
        ",").

generate_oauth_parameters(RawMethod, BaseUrl, Args,
    ConsumerKey, ConsumerSecret, Token, TokenSecret)
    ->
    Method = string:to_upper(atom_to_list(RawMethod)),
    
    OAuthParameters1 = [
        {oauth_consumer_key, ConsumerKey},
        {oauth_nonce, generate_nonce()},
        {oauth_timestamp, generate_timestamp()},
        {oauth_signature_method, ?OAUTH_SIGNATURE_METHOD},
        {oauth_version, ?OAUTH_VERSION}
    ],
    
    OAuthParameters2 = if
        Token /= "" -> [{oauth_token, Token}|OAuthParameters1];
        true -> OAuthParameters1
    end,
    
    OAuthParameters = if
        TokenSecret /= "" -> [{oauth_token_secret, TokenSecret}|OAuthParameters2];
        true -> OAuthParameters2
    end,
    
    OAuthParametersForBaseString = dict:to_list(
        dict:merge(fun(_, _, V) -> V end,
            dict:from_list(OAuthParameters),
            dict:from_list(Args))),
    
    Signature = generate_signature(Method, BaseUrl, OAuthParametersForBaseString, ConsumerSecret, TokenSecret), 
    
    [{oauth_signature, Signature}|OAuthParameters].

generate_signature(Method, UrlBase, Args, ConsumerSecret, TokenSecret) ->
    base64:encode(crypto:sha_mac(ConsumerSecret ++ [$&|TokenSecret],
        generate_signature_base_string(Method, UrlBase, Args))).

generate_signature_base_string(Method, UrlBase, Args) ->
    ParameterString = urlencode(string:join(
        lists:map(
            fun ({Key, Value}) ->
                urlencode(Key) ++ [$=|urlencode(Value)]
            end,
            lists:keysort(1, lists:keydelete("oauth_signature", 1, Args))
        ), "&"
    )),
    Method ++ [$&|urlencode(UrlBase)] ++ [$&|ParameterString].

validate_signature(Url, ConsumerSecret, TokenSecret) ->
    [UrlBase, ParamString] = string:tokens(Url, "?"),
    Args = lists:map(fun(S) ->
        [Name, Value] = string:tokens(S, "="),
        {urldecode(Name), urldecode(Value)}
    end, string:tokens(ParamString, "&")),
    
    case lists:keyfind("oauth_signature", 1, Args) of
        false -> no_signature;
        {"oauth_signature", Signature} ->
            case binary_to_list(generate_signature("GET", UrlBase, Args, ConsumerSecret, TokenSecret)) of
                Signature -> true;
                _ -> incorrect_signature
            end
    end.

generate_nonce() ->
    integer_to_list(crypto:rand_uniform(0, 1000000000000000000000000000000)).

generate_timestamp() ->
    calendar:datetime_to_gregorian_seconds( calendar:now_to_universal_time(now()) ) -
        calendar:datetime_to_gregorian_seconds( {{1970,1,1},{0,0,0}} ).
    
request_add_header({Url, Headers, ContentType, Body}, Name, Value) ->
    {Url, [{Name, Value}|Headers], ContentType, Body};
request_add_header({Url, Headers}, Name, Value) ->
    {Url, [{Name, Value}|Headers]}.