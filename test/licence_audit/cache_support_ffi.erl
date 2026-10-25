-module(cache_support_ffi).
-export([corrupt_entry/2, with_writer/2, assert_busy/1, create_legacy/1, assert_concurrent_cleanup/1]).

corrupt_entry(Path, Key) ->
    {ok, Connection} = esqlite3:open(binary_to_list(filename:absname(Path))),
    try
        [] = esqlite3:q(Connection,
            <<"INSERT INTO cache_entries(key, value) VALUES (?, x'FF')
               ON CONFLICT(key) DO UPDATE SET value = excluded.value">>, [Key])
    after
        ok = esqlite3:close(Connection)
    end,
    false = filelib:is_regular(<<Path/binary, "-wal">>),
    false = filelib:is_regular(<<Path/binary, "-shm">>),
    {ok, nil}.

with_writer(Path, Action) ->
    {ok, Connection} = esqlite3:open(binary_to_list(filename:absname(Path))),
    try
        ok = esqlite3:exec(Connection, <<"BEGIN IMMEDIATE">>),
        Action()
    after
        ok = esqlite3:exec(Connection, <<"ROLLBACK">>),
        ok = esqlite3:close(Connection)
    end.

assert_busy(Action) ->
    try Action() of
        _ -> erlang:error(expected_sqlight_busy_exception)
    catch
        error:{case_clause, '$busy'} -> nil
    end.

create_legacy(Path) ->
    {ok, Table} = dets:open_file(cache_test_legacy, [{file, binary_to_list(Path)}]),
    try
        ok = dets:insert(Table, {<<"key">>, <<"legacy">>}),
        nil
    after
        ok = dets:close(Table)
    end.

assert_concurrent_cleanup(Prefix) ->
    Workers = [spawn_monitor(fun() ->
        Path = <<Prefix/binary, "-", (integer_to_binary(Index))/binary>>,
        lists:foreach(fun(Suffix) -> file:delete(<<Path/binary, Suffix/binary>>) end,
            [<<>>, <<"-wal">>, <<"-shm">>]),
        {ok, Store} = licence_audit@cache_dir:open_table({some, Path}, <<"unused">>, <<"test">>),
        try
            lists:foreach(fun(Version) ->
                Value = integer_to_binary(Version),
                {ok, nil} = licence_audit@cache_dir:insert_at(Store,
                    <<"key">>, Value, {some, Version}),
                false = filelib:is_regular(<<Path/binary, "-wal">>),
                {ok, {entry, Value, {some, Version}}} =
                    licence_audit@cache_dir:lookup_entry(Store, <<"key">>),
                false = filelib:is_regular(<<Path/binary, "-wal">>),
                false = filelib:is_regular(<<Path/binary, "-shm">>)
            end, lists:seq(1, 30))
        after
            file:delete(Path)
        end
    end) || Index <- lists:seq(1, 16)],
    lists:foreach(fun({Worker, Monitor}) ->
        receive
            {'DOWN', Monitor, process, Worker, normal} -> ok;
            {'DOWN', Monitor, process, Worker, Reason} -> erlang:error(Reason)
        after 4000 -> erlang:error(cache_cleanup_timeout)
        end
    end, Workers),
    nil.
