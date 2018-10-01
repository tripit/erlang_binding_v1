%
% Copyright 2008-2018 Concur Technologies, Inc.
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

-module(examples).
-export([webauth_example/3, oauth_example/5, crs_load_example/4, crs_delete_example/4]).

webauth_example(Url, User, Password) ->
    C = tripit:webauth_credential(User, Password),
    {ok, T} = tripit:start_link(C, Url),
    {ok, Result} = tripit:list_trip(T),
    Result.

oauth_example(Url, Key, Secret, Token, TokenSecret) ->
    C = tripit:oauth_credential(Key, Secret, Token, TokenSecret),
    {ok, T} = tripit:start_link(C, Url),
    {ok, Result} = tripit:list_trip(T),
    Result.
    
crs_load_example(Url, Key, Secret, Email) ->
    C = tripit:oauth_credential(Key, Secret, Email),
    {ok, T} = tripit:start_link(C, Url),
    {ok, Result} = tripit:crs_load_reservations(T, "<CrsRequest><AirObject><record_locator>ABC123</record_locator><notes>NOTES</notes><Segment><start_airport_code>YVR</start_airport_code><end_airport_code>SFO</end_airport_code></Segment></AirObject></CrsRequest>"),
    Result.
    
crs_delete_example(Url, Key, Secret, Email) ->
    C = tripit:oauth_credential(Key, Secret, Email),
    {ok, T} = tripit:start_link(C, Url),
    {ok, Result} = tripit:crs_delete_reservations(T, "ABC123"),
    Result.
