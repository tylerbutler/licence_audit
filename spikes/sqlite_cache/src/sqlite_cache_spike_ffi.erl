-module(sqlite_cache_spike_ffi).
-export([arguments/0, monotonic_milliseconds/0, sleep/0]).

arguments() ->
    Plain = lists:map(fun unicode:characters_to_binary/1, init:get_plain_arguments()),
    case init:get_argument(escript) of
        {ok, _} -> tl(Plain);
        _ -> Plain
    end.

monotonic_milliseconds() ->
    erlang:monotonic_time(millisecond).

sleep() ->
    timer:sleep(30000),
    nil.
