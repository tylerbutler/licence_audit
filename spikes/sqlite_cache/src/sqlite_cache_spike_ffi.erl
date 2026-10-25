-module(sqlite_cache_spike_ffi).
-export([arguments/0, monotonic_milliseconds/0, sleep/0, open/1, query/3]).

open(Path) ->
    case binary:match(Path, <<0>>) of
        nomatch ->
            %% The NIF copies Latin-1 list elements to SQLite's UTF-8 filename buffer.
            case esqlite3:open(binary_to_list(Path)) of
                {ok, Connection} -> {ok, Connection};
                {error, invalid_filename} ->
                    {error, {sqlight_error, generic_error,
                        <<"Invalid SQLite filename (esqlite limit: 511 UTF-8 bytes)">>, -1}};
                {error, Code} ->
                    {error, {sqlight_error, sqlight:error_code_from_int(Code),
                        <<"Unable to open SQLite database">>, -1}}
            end;
        {_, _} ->
            {error, {sqlight_error, generic_error,
                <<"SQLite filenames cannot contain NUL bytes">>, -1}}
    end.

query(Sql, Connection, Arguments) ->
    case esqlite3:prepare(Connection, Sql) of
        {ok, Statement} ->
            Outcome = case esqlite3:bind(Statement, Arguments) of
                ok -> fetch_rows(Connection, Statement, []);
                {error, Code} -> sqlite_error(Connection, Code)
            end,
            %% Reset releases statement locks; its error can repeat the failed step.
            case {Outcome, esqlite3:reset(Statement)} of
                {{ok, _}, {error, ResetCode}} -> sqlite_error(Connection, ResetCode);
                _ -> Outcome
            end;
        {error, Code} ->
            sqlite_error(Connection, Code)
    end.

fetch_rows(Connection, Statement, Rows) ->
    case esqlite3:step(Statement) of
        Row when is_list(Row) ->
            fetch_rows(Connection, Statement, [list_to_tuple(Row) | Rows]);
        '$done' ->
            {ok, lists:reverse(Rows)};
        '$busy' ->
            sqlite_error(Connection, 5);
        {error, Code} ->
            sqlite_error(Connection, Code)
    end.

sqlite_error(Connection, Code) ->
    #{errmsg := Message, error_offset := Offset} = esqlite3:error_info(Connection),
    {error, {sqlight_error, sqlight:error_code_from_int(Code), Message, Offset}}.

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
