-module(archive_download_ffi).
-export([await_up/3, normalise_await_up/2, open/4, before_close/1]).

before_close(Connection) -> network_ffi:before_close(Connection).

open(Host, Port, Options, Deadline) ->
    case network_ffi:open(fun() ->
        case prepare_options(Host, Port, Options) of
            {error, _} = Error -> Error;
            {ok, GunOptions} ->
                case gun:open(host_for_gun(Host), Port,
                    network_ffi:gun_options(GunOptions)) of
                    {ok, _} = Opened -> Opened;
                    {error, Reason} -> {error, open_error(Reason)}
                end
        end
    end, Deadline) of
        {ok, _} = Result -> Result;
        {error, timeout} -> {error, timeout};
        {error, Reason} -> {error, {network_failure, Reason}}
    end.

host_for_gun(Host) ->
    Text = unicode:characters_to_list(Host),
    case inet:parse_address(string:trim(Text, both, "[]")) of
        {ok, Address} -> Address;
        {error, _} -> Text
    end.

prepare_options(Host, Port, Options) ->
    try {ok, gluegun_ffi:prepare_connect_options(Host, Port, Options)}
    catch
        error:{options, Reason} -> {error, {invalid_options, gleam@string:inspect(Reason)}};
        error:{invalid_options, Reason} -> {error, {invalid_options, gleam@string:inspect(Reason)}};
        Class:Reason -> {error, {erlang_error, gleam@string:inspect({Class, Reason})}}
    end.

open_error(timeout) -> timeout;
open_error({options, Reason}) -> {invalid_options, gleam@string:inspect(Reason)};
open_error({down, Reason}) -> {connection_down, gleam@string:inspect(Reason)};
open_error({Tag, Reason}) when Tag =:= invalid_options; Tag =:= connection_down;
        Tag =:= connection_error; Tag =:= stream_error; Tag =:= invalid_message;
        Tag =:= decode_error; Tag =:= erlang_error ->
    {Tag, gleam@string:inspect(Reason)};
open_error(Reason) -> {connection_error, gleam@string:inspect(Reason)}.

%% Gluegun renders Gun reasons as diagnostic strings. Keep the DNS reason
%% structured until the archive adapter has classified the selected family.
await_up(Connection, {milliseconds, Timeout}, Family) ->
    try gun:await_up(Connection, Timeout) of
        Result -> normalise_await_up(Result, Family)
    catch
        Class:Reason ->
            {error, {network_failure, {erlang_error,
                gleam@string:inspect({Class, Reason})}}}
    end.

normalise_await_up({error, {down, {shutdown, nxdomain}}}, ipv6) ->
    {error, no_ipv6_address};
normalise_await_up({error, timeout}, _Family) ->
    {error, timeout};
normalise_await_up({error, {down, Reason}}, _Family) ->
    case httpc_adaptive_ffi:normalise_error({stream_error, Reason}) of
        {connection_failure, Kind, Detail} ->
            {error, {connection_failure, Kind, Detail}};
        {tls_failure, Detail} ->
            {error, {tls_failure, Detail}};
        _ ->
            {error, {network_failure, {connection_down, gleam@string:inspect(Reason)}}}
    end;
normalise_await_up({ok, Protocol}, _Family) ->
    case gluegun_ffi:protocol_result(Protocol) of
        {ok, _} = Result -> Result;
        {error, Reason} -> {error, {network_failure, Reason}}
    end.
