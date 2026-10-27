-module(cache_dir_ffi).
-export([with_connection/2]).

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
