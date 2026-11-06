-module(cache_dir_ffi).
-export([ensure_sqlite_loaded/0, with_connection/2]).

%% Check the on-load result before calling a NIF that may not be available.
ensure_sqlite_loaded() ->
    case code:ensure_loaded(esqlite3_nif) of
        {module, esqlite3_nif} -> {ok, nil};
        {error, Reason} ->
            Detail = unicode:characters_to_binary(io_lib:format("~p", [Reason])),
            {error, <<"SQLite native library unavailable: ", Detail/binary>>}
    end.

%% Gleam cannot catch driver exceptions or close a connection while unwinding.
with_connection(Connection, Action) ->
    Outcome = try Action(Connection)
    catch
        error:{case_clause, '$busy'} ->
            {error, <<"SQLite error 5: database is busy">>};
        Class:Reason:Stack ->
            _ = sqlight:close(Connection),
            erlang:raise(Class, Reason, Stack)
    end,
    {Outcome, sqlight:close(Connection)}.
