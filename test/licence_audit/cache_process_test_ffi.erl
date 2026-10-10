-module(cache_process_test_ffi).
-export([concurrent_writes/5, corrupt_entry/2, worker/0]).

concurrent_writes(CachePath, FirstKey, FirstValue, SecondKey, SecondValue) ->
    case os:find_executable("erl") of
        false ->
            {error, <<"erl executable not found">>};
        Erl ->
            run_workers(
                Erl,
                <<CachePath/binary, ".entries">>,
                [{FirstKey, FirstValue}, {SecondKey, SecondValue}]
            )
    end.

corrupt_entry(CachePath, Key) ->
    Root = <<CachePath/binary, ".entries">>,
    Digest = crypto:hash(sha256, Key),
    Filename = <<(binary:encode_hex(Digest, lowercase))/binary, ".cache">>,
    case file:write_file(filename:join(Root, Filename), <<255>>) of
        ok -> {ok, nil};
        {error, _Reason} -> {error, nil}
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
                receive_results(Sockets);
            {error, Reason} ->
                {error, describe(<<"accept worker">>, Reason)}
        end,
    gen_tcp:close(Listener),
    lists:foreach(fun close_port/1, Ports),
    Result.

start_worker(Erl, Root, Key, Value, Port) ->
    Ebin = filename:dirname(code:which(cache_dir_ffi)),
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
    Result = cache_dir_ffi:write(cache_dir_ffi:new_store(Root), Key, Value),
    ok = gen_tcp:send(Socket, term_to_binary(Result)),
    gen_tcp:close(Socket),
    halt().

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
