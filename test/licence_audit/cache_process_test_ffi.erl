-module(cache_process_test_ffi).
-export([concurrent_writes/5, worker/0]).

%% Gleam processes share one VM. Separate erl runtimes exercise SQLite's
%% cross-process locking and synchronize writes without relying on sleeps.
concurrent_writes(CachePath, FirstKey, FirstValue, SecondKey, SecondValue) ->
    case os:find_executable("erl") of
        false ->
            {error, <<"erl executable not found">>};
        Erl ->
            run_workers(
                Erl,
                CachePath,
                [{FirstKey, FirstValue}, {SecondKey, SecondValue}]
            )
    end.

run_workers(Erl, Root, Entries) ->
    {ok, Listener} = gen_tcp:listen(0, [
        binary,
        {active, false},
        {ip, {127, 0, 0, 1}},
        {packet, 4},
        {reuseaddr, true}
    ]),
    {ok, {{127, 0, 0, 1}, Port}} = inet:sockname(Listener),
    Ports = [start_worker(Erl, Root, Key, Value, Port) || {Key, Value} <- Entries],
    Result =
        case accept_ready_workers(Listener, 2, []) of
            {ok, Sockets} ->
                lists:foreach(
                    fun(Socket) -> ok = gen_tcp:send(Socket, term_to_binary(go)) end,
                    Sockets
                ),
                case receive_results(Sockets) of
                    {ok, nil} -> wait_workers(Ports);
                    {error, _} = Error -> Error
                end;
            {error, Reason} ->
                {error, describe(<<"accept worker">>, Reason)}
        end,
    gen_tcp:close(Listener),
    lists:foreach(fun close_port/1, Ports),
    Result.

wait_workers([]) ->
    {ok, nil};
wait_workers([Port | Rest]) ->
    receive
        {Port, {exit_status, 0}} -> wait_workers(Rest);
        {Port, {exit_status, Status}} ->
            {error, describe(<<"worker exit">>, Status)}
    after 10000 ->
        {error, <<"Timed out waiting for cache worker exit">>}
    end.

start_worker(Erl, Root, Key, Value, Port) ->
    Ebin = filename:dirname(code:which(licence_audit@cache_dir)),
    LibDirs = filelib:wildcard(filename:join(filename:dirname(filename:dirname(filename:dirname(code:which(gleam@result)))), "*/ebin")),
    TestEbin = filename:dirname(code:which(?MODULE)),
    open_port(
        {spawn_executable, Erl},
        [
            exit_status,
            hide,
            {args, [
                "-noshell",
                "-pa",
                Ebin,
                "-pa"
            ] ++ LibDirs ++ [
                "-pa",
                TestEbin,
                "-eval",
                "cache_process_test_ffi:worker()."
            ]},
            {env, [
                {"CACHE_TEST_ROOT", binary_to_list(Root)},
                {"CACHE_TEST_KEY", binary_to_list(Key)},
                {"CACHE_TEST_VALUE", binary_to_list(Value)},
                {"CACHE_TEST_PORT", integer_to_list(Port)}
            ]}
        ]
    ).

accept_ready_workers(_Listener, 0, Sockets) ->
    {ok, Sockets};
accept_ready_workers(Listener, Remaining, Sockets) ->
    case gen_tcp:accept(Listener, 10000) of
        {ok, Socket} ->
            case gen_tcp:recv(Socket, 0, 10000) of
                {ok, Encoded} ->
                    case binary_to_term(Encoded, [safe]) of
                        {ready, _Key} ->
                            accept_ready_workers(
                                Listener,
                                Remaining - 1,
                                [Socket | Sockets]
                            );
                        Other ->
                            {error, {unexpected_ready, Other}}
                    end;
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

receive_results([]) ->
    {ok, nil};
receive_results([Socket | Rest]) ->
    case gen_tcp:recv(Socket, 0, 10000) of
        {ok, Encoded} ->
            gen_tcp:close(Socket),
            case binary_to_term(Encoded, [safe]) of
                {ok, nil} -> receive_results(Rest);
                {error, Error} -> {error, Error};
                Other -> {error, describe(<<"unexpected worker result">>, Other)}
            end;
        {error, Reason} ->
            {error, describe(<<"receive worker result">>, Reason)}
    end.

worker() ->
    Root = env_binary("CACHE_TEST_ROOT"),
    Key = env_binary("CACHE_TEST_KEY"),
    Value = env_binary("CACHE_TEST_VALUE"),
    Port = list_to_integer(os:getenv("CACHE_TEST_PORT")),
    {ok, Socket} = gen_tcp:connect(
        {127, 0, 0, 1},
        Port,
        [binary, {active, false}, {packet, 4}],
        10000
    ),
    ok = gen_tcp:send(Socket, term_to_binary({ready, Key})),
    {ok, Go} = gen_tcp:recv(Socket, 0, 10000),
    go = binary_to_term(Go, [safe]),
    {ok, Store} = when_available(fun() ->
        licence_audit@cache_dir:open_table({some, Root}, <<"unused">>, <<"test">>)
    end, 100),
    Result =
        case when_available(fun() ->
            licence_audit@cache_dir:insert(Store, Key, Value)
        end, 100) of
            {ok, nil} -> {ok, nil};
            {error, Error} ->
                {error, licence_audit@cache_dir:describe_error(Error)}
        end,
    ok = gen_tcp:send(Socket, term_to_binary(Result)),
    gen_tcp:close(Socket),
    halt().

%% Retry returned contention errors only in this test to verify persisted writes.
when_available(Action, Retries) ->
    Outcome = Action(),
    case Outcome of
        {error, Error} when Retries > 0 ->
            Message = licence_audit@cache_dir:describe_error(Error),
            case binary:match(Message, <<"SQLite error 5:">>) of
                nomatch -> {error, Error};
                _ ->
                    timer:sleep(10),
                    when_available(Action, Retries - 1)
            end;
        Result -> Result
    end.

env_binary(Name) ->
    unicode:characters_to_binary(os:getenv(Name)).

close_port(Port) ->
    try erlang:port_close(Port) of
        true -> ok
    catch
        error:badarg -> ok
    end.

describe(Operation, Reason) ->
    ReasonText = unicode:characters_to_binary(io_lib:format("~tp", [Reason])),
    <<Operation/binary, ": ", ReasonText/binary>>.
