-module(sqlite_cache_spike_ffi_tests).
-include_lib("eunit/include/eunit.hrl").

invalid_filename_test() ->
    ?assertMatch(
        {error, {sqlight_error, generic_error, _, -1}},
        sqlite_cache_spike_ffi:open(<<":memory:", 0, "suffix">>)
    ),
    ?assertMatch(
        {error, {sqlight_error, generic_error, _, -1}},
        sqlite_cache_spike_ffi:open(binary:copy(<<"x">>, 512))
    ).

query_errors_test() ->
    {ok, Connection} = sqlite_cache_spike_ffi:open(<<":memory:">>),
    try
        ?assertMatch(
            {error, {sqlight_error, generic_error, _, _}},
            sqlite_cache_spike_ffi:query(<<"SELECT FROM">>, Connection, [])
        ),
        ?assertMatch(
            {error, {sqlight_error, range, _, _}},
            sqlite_cache_spike_ffi:query(<<"SELECT ?">>, Connection, [1, 2])
        ),
        ?assertEqual(
            {ok, [{42}]},
            sqlite_cache_spike_ffi:query(<<"SELECT ?">>, Connection, [42])
        ),
        ?assertEqual(
            {ok, [{1}, {2}]},
            sqlite_cache_spike_ffi:query(
                <<"SELECT 1 UNION ALL SELECT 2 ORDER BY 1">>, Connection, []
            )
        )
    after
        ?assertEqual({ok, nil}, sqlight_ffi:close(Connection))
    end.

filename_byte_limit_test() ->
    with_database(fun(Path) ->
        Parent = filename:join([
            filename:dirname(binary_to_list(Path)),
            lists:duplicate(200, $a),
            lists:duplicate(200, $b)
        ]),
        ok = filelib:ensure_dir(filename:join(Parent, "unused")),
        Prefix = unicode:characters_to_binary(Parent),
        Filename = binary:copy(<<"c">>, 503 - byte_size(Prefix)),
        Accepted = <<Prefix/binary, "/", Filename/binary>>,
        Rejected = <<Accepted/binary, "c">>,
        Overlong = <<Accepted/binary, "cccccccc">>,
        ?assertEqual(504, byte_size(Accepted)),
        ?assertEqual(505, byte_size(Rejected)),
        ?assertEqual(512, byte_size(Overlong)),
        with_connection(Accepted, fun(Connection) ->
            ok = esqlite3:exec(Connection,
                <<"PRAGMA journal_mode=WAL; CREATE TABLE entries(value TEXT);
                   INSERT INTO entries VALUES ('cached')">>)
        end),
        ?assert(filelib:is_regular(binary_to_list(Accepted))),
        ?assertMatch(
            {error, {sqlight_error, cantopen, _, -1}},
            sqlite_cache_spike_ffi:open(Rejected)
        ),
        ?assertMatch(
            {error, {sqlight_error, generic_error, _, -1}},
            sqlite_cache_spike_ffi:open(Overlong)
        ),
        ?assertNot(filelib:is_regular(binary_to_list(Rejected)))
    end).

read_only_database_test() ->
    with_database(fun(Path) ->
        with_connection(Path, fun(Writer) ->
            ok = esqlite3:exec(Writer,
                <<"PRAGMA journal_mode=WAL; CREATE TABLE entries (value TEXT);
                   INSERT INTO entries VALUES ('cached')">>)
        end),
        with_connection(<<"file:", Path/binary, "?mode=ro">>, fun(Reader) ->
            ?assertEqual(
                {ok, [{<<"cached">>}]},
                sqlite_cache_spike_ffi:query(<<"SELECT value FROM entries">>, Reader, [])
            ),
            ?assertMatch(
                {error, {sqlight_error, readonly, _, _}},
                sqlite_cache_spike_ffi:query(
                    <<"INSERT INTO entries VALUES (?)">>, Reader, [<<"new">>]
                )
            ),
            ?assertEqual(
                {ok, [{<<"cached">>}]},
                sqlite_cache_spike_ffi:query(<<"SELECT value FROM entries">>, Reader, [])
            )
        end)
    end).

legacy_dets_is_not_overwritten_test() ->
    with_database(fun(Path) ->
        {ok, Table} = dets:open_file(sqlite_spike_legacy, [{file, binary_to_list(Path)}]),
        try
            ok = dets:insert(Table, {<<"key">>, <<"legacy">>})
        after
            ok = dets:close(Table)
        end,
        {ok, Before} = file:read_file(Path),
        with_connection(Path, fun(Connection) ->
            ?assertMatch(
                {error, {sqlight_error, notadb, _, _}},
                sqlite_cache_spike_ffi:query(<<"PRAGMA journal_mode=WAL">>, Connection, [])
            )
        end),
        ?assertEqual({ok, Before}, file:read_file(Path))
    end).

full_database_test() ->
    with_connection(<<":memory:">>, fun(Connection) ->
        ok = esqlite3:exec(Connection,
            <<"PRAGMA page_size=512; PRAGMA max_page_count=2;
               CREATE TABLE entries(value TEXT)">>),
        Sql = <<"INSERT INTO entries VALUES (?)">>,
        ?assertMatch(
            {error, {sqlight_error, full, _, _}},
            sqlite_cache_spike_ffi:query(Sql, Connection, [binary:copy(<<"x">>, 1024)])
        ),
        ?assertEqual(
            {ok, []},
            sqlite_cache_spike_ffi:query(Sql, Connection, [<<"safe">>])
        ),
        ?assertEqual(
            {ok, [{<<"safe">>}]},
            sqlite_cache_spike_ffi:query(<<"SELECT value FROM entries">>, Connection, [])
        )
    end).

closed_database_snapshot_test() ->
    with_database(fun(Path) ->
        Copy = <<Path/binary, ".copy">>,
        with_connection(Path, fun(Writer) ->
            ok = esqlite3:exec(Writer,
                <<"PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;
                   CREATE TABLE entries (value TEXT);
                   INSERT INTO entries VALUES ('committed')">>),
            ?assert(filelib:is_regular(binary_to_list(<<Path/binary, "-wal">>))),
            {ok, _} = file:copy(Path, Copy),
            with_connection(Copy, fun(Reader) ->
                ?assertMatch(
                    {error, {sqlight_error, generic_error, _, _}},
                    sqlite_cache_spike_ffi:query(
                        <<"SELECT value FROM entries">>, Reader, []
                    )
                )
            end)
        end),
        ?assertNot(filelib:is_regular(binary_to_list(<<Path/binary, "-wal">>))),
        {ok, _} = file:copy(Path, Copy),
        with_connection(Copy, fun(Reader) ->
            ?assertEqual(
                {ok, [{<<"committed">>}]},
                sqlite_cache_spike_ffi:query(<<"SELECT value FROM entries">>, Reader, [])
            )
        end)
    end).

busy_queries_test() ->
    with_database(fun(Path) ->
        with_connection(Path, fun(Writer) ->
            ok = esqlite3:exec(Writer,
                <<"CREATE TABLE entries (key TEXT PRIMARY KEY, value TEXT)">>),
            with_connection(Path, fun(Reader) ->
                %% Cache the schema before the exclusive lock so reads reach step/1.
                ?assertEqual(
                    {ok, []},
                    sqlite_cache_spike_ffi:query(<<"SELECT * FROM entries">>, Reader, [])
                ),
                ok = esqlite3:exec(Writer, <<"BEGIN EXCLUSIVE">>),
                assert_busy(<<"SELECT * FROM entries">>, Reader, []),
                assert_busy(<<"PRAGMA journal_mode=WAL">>, Reader, []),
                ok = esqlite3:exec(Writer, <<"ROLLBACK">>),
                ok = esqlite3:exec(Writer, <<"PRAGMA journal_mode=WAL">>),
                ok = esqlite3:exec(Writer, <<"BEGIN IMMEDIATE">>),
                Sql = <<"INSERT INTO entries VALUES (?, ?)">>,
                assert_busy(Sql, Reader, [<<"blocked">>, <<"value">>]),
                ?assertEqual(
                    {ok, []},
                    sqlite_cache_spike_ffi:query(<<"SELECT * FROM entries">>, Reader, [])
                ),
                ok = esqlite3:exec(Writer, <<"ROLLBACK">>),
                ?assertEqual(
                    {ok, []},
                    sqlite_cache_spike_ffi:query(Sql, Reader, [<<"safe">>, <<"value">>])
                ),
                ?assertMatch(
                    {error, {sqlight_error, constraint_primarykey, _, _}},
                    sqlite_cache_spike_ffi:query(Sql, Reader, [<<"safe">>, <<"duplicate">>])
                ),
                ?assertEqual(
                    {ok, [{<<"safe">>, <<"value">>}]},
                    sqlite_cache_spike_ffi:query(<<"SELECT * FROM entries">>, Reader, [])
                )
            end)
        end)
    end).

with_database(Action) ->
    Directory = filename:join(
        os:getenv("TMPDIR", "/tmp"),
        "sqlite-spike-" ++ os:getpid() ++ "-" ++
            integer_to_list(erlang:unique_integer([positive, monotonic]))
    ),
    ok = file:make_dir(Directory),
    Path = unicode:characters_to_binary(filename:join(Directory, "cache.sqlite3")),
    try
        Action(Path)
    after
        ok = file:del_dir_r(Directory)
    end.

assert_busy(Sql, Connection, Arguments) ->
    Started = erlang:monotonic_time(millisecond),
    ?assertMatch(
        {error, {sqlight_error, busy, _, _}},
        sqlite_cache_spike_ffi:query(Sql, Connection, Arguments)
    ),
    ?assert(erlang:monotonic_time(millisecond) - Started < 1000).

with_connection(Path, Action) ->
    {ok, Connection} = sqlite_cache_spike_ffi:open(Path),
    try
        ok = esqlite3:exec(Connection, <<"PRAGMA busy_timeout=0">>),
        Action(Connection)
    after
        ?assertEqual({ok, nil}, sqlight_ffi:close(Connection))
    end.
