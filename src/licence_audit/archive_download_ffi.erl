-module(archive_download_ffi).
-export([await_up/3, normalise_await_up/2]).

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
    {error, {network_failure, {connection_down, gleam@string:inspect(Reason)}}};
normalise_await_up({ok, Protocol}, _Family) ->
    case gluegun_ffi:protocol_result(Protocol) of
        {ok, _} = Result -> Result;
        {error, Reason} -> {error, {network_failure, Reason}}
    end.
