-module(network_test_ffi).
-export([with_state/1, work/3, blocked/2, count/2, increment/2,
    workers_stopped/1, record_worker/2, kill_caller/2,
    with_peer/2, assert_drained/1, interrupt_http/2,
    probe_owner_recovery/0, cancelled_open_replies/0, queued_open_deadline/0,
    preparation_failure/0,
    lose_guardian/0, unconfirmed_open/0,
    with_project/2,
    now_ms/0, elapsed_ms/0, sleep/1]).

with_state(Action) ->
    State = ets:new(?MODULE, [set, public]),
    ets:insert(State, [{active, 0}, {maximum, 0}, {admitted, 0},
        {calls, 0}, {closed, 0}]),
    try Action(State)
    after
        Pids = [Pid || {{process, _}, Pid} <- ets:tab2list(State)],
        Watches = [{Pid, erlang:monitor(process, Pid)} || Pid <- Pids],
        lists:foreach(fun(Pid) -> exit(Pid, kill) end, Pids),
        lists:foreach(fun({Pid, Watch}) ->
            receive {'DOWN', Watch, process, Pid, _} -> ok
            after 1000 -> error(test_process_not_stopped)
            end
        end, Watches),
        ets:delete(State)
    end.

count(State, <<"maximum">>) -> count(State, maximum);
count(State, <<"calls">>) -> count(State, calls);
count(State, Key) ->
    case ets:lookup(State, Key) of [] -> 0; [{Key, Value}] -> Value end.

increment(State, Key) -> ets:update_counter(State, Key, 1, {Key, 0}).
now_ms() -> erlang:system_time(millisecond).
elapsed_ms() -> erlang:monotonic_time(millisecond).
sleep(Milliseconds) -> timer:sleep(Milliseconds), nil.

lose_guardian() ->
    Guardian = erlang:get({network_ffi, guardian}),
    Monitor = erlang:monitor(process, Guardian),
    exit(Guardian, kill),
    receive {'DOWN', Monitor, process, Guardian, killed} -> nil end.

unconfirmed_open() ->
    {error, timeout} = network_ffi:open(fun() ->
        network_ffi:gun_options(#{transport => tcp}),
        receive never -> {error, never} end
    end, elapsed_ms() + 80),
    nil.

with_project(Archive, Action) ->
    Root = filename:join(["build", "tmp",
        "bounded-command-" ++ integer_to_list(erlang:unique_integer([positive]))]),
    Manifest = filename:join(Root, "manifest.toml"),
    Config = filename:join(Root, "gleam.toml"),
    ok = filelib:ensure_dir(Manifest),
    Checksum = binary:encode_hex(crypto:hash(sha256, Archive)),
    Packages = [io_lib:format(
        " { name = \"package~B\", version = \"1.0.0\", source = \"hex\", "
        "outer_checksum = \"~s\", requirements = [] },\n", [Index, Checksum])
        || Index <- lists:seq(0, 7)],
    ok = file:write_file(Manifest, ["packages = [\n", Packages, "]\n"]),
    ok = file:write_file(Config,
        <<"name = \"bounded_fixture\"\nversion = \"1.0.0\"\n">>),
    try Action(unicode:characters_to_binary(Root))
    after
        ok = file:delete(Manifest),
        ok = file:delete(Config),
        ok = file:del_dir(Root)
    end.

probe_owner_recovery() ->
    network_ffi:with_command(fun() ->
        State = network_ffi:context(),
        Caller = self(),
        {Owner, Monitor} = spawn_monitor(fun() ->
            erlang:put({network_ffi, context}, State),
            network_ffi:shared_probe(<<"interrupted.invalid">>, fun() ->
                Caller ! probe_locked,
                receive never -> {ok, ipv6} end
            end)
        end),
        try
            receive probe_locked -> ok
            after 1000 -> error(probe_not_started)
            end,
            exit(Owner, kill),
            receive {'DOWN', Monitor, process, Owner, killed} -> ok
            after 1000 -> error(probe_owner_not_stopped)
            end,
            {ok, ipv6} = network_ffi:shared_probe(<<"other.invalid">>,
                fun() -> {ok, ipv6} end),
            {error, {request_failed, _}} =
                network_ffi:shared_probe(<<"interrupted.invalid">>,
                    fun() -> error(interrupted_probe_repeated) end),
            nil
        after
            exit(Owner, kill),
            erlang:demonitor(Monitor, [flush])
        end
    end).

cancelled_open_replies() ->
    network_ffi:with_command(fun() ->
        {error, timeout} = network_ffi:open(fun() ->
            timer:sleep(120),
            {error, late_open_reply}
        end, elapsed_ms() + 30),
        timer:sleep(150),
        {messages, Messages} = process_info(self(), messages),
        [] = [Message || Message = {Reference, {error, late_open_reply}} <- Messages,
            is_reference(Reference)],
        nil
    end).

queued_open_deadline() ->
    network_ffi:with_command(fun() ->
        Caller = self(),
        {Resumer, Monitor} = spawn_monitor(fun() ->
            receive {suspend, Helper} ->
                true = erlang:suspend_process(Caller),
                Helper ! suspended,
                timer:sleep(150),
                erlang:resume_process(Caller)
            after 1000 -> error(caller_not_suspended)
            end
        end),
        try
            {error, timeout} = network_ffi:open(fun() ->
                Resumer ! {suspend, self()},
                receive suspended -> ok end,
                {error, queued_open_reply}
            end, elapsed_ms() + 100),
            receive {'DOWN', Monitor, process, Resumer, normal} -> nil
            after 1000 -> error(caller_resumer_not_stopped)
            end
        after
            exit(Resumer, kill),
            erlang:demonitor(Monitor, [flush])
        end
    end).

preparation_failure() ->
    network_ffi:with_command(fun() ->
        {error, Failure} = network_ffi:open(fun() ->
            httpc_adaptive_ffi:prepare_tls(<<"hex.invalid">>,
                fun() -> error(test_ca_load_failure) end)
        end, elapsed_ms() + 1000),
        {request_failed, _} = httpc_adaptive_ffi:normalise_error(Failure),
        {error, followup} = network_ffi:open(fun() ->
            {error, followup}
        end, elapsed_ms() + 1000),
        nil
    end).

record_worker(State, Index) ->
    ets:insert(State, {{process, {worker, Index}}, self()}),
    nil.

admit(State, Index) ->
    record_worker(State, Index),
    Active = increment(State, active),
    record_maximum(State, Active),
    Admitted = increment(State, admitted),
    case Admitted of
        4 ->
            lists:foreach(fun({{process, {worker, _}}, Pid}) -> Pid ! admitted;
                (_) -> ok end, ets:tab2list(State));
        _ -> ok
    end,
    case Admitted =< 4 of
        true -> receive admitted -> ok after 1000 -> error(admission_timeout) end;
        false -> ok
    end.

record_maximum(State, Value) ->
    Previous = count(State, maximum),
    case Value > Previous of
        false -> ok;
        true ->
            case ets:select_replace(State, [
                {{maximum, Previous}, [], [{{maximum, Value}}]}
            ]) of
                1 -> ok;
                0 -> record_maximum(State, Value)
            end
    end.

work(State, Index, Crash) ->
    admit(State, Index),
    try
        timer:sleep((4 - Index rem 4) * 15),
        case Crash of true -> error(test_worker_crash); false -> Index end
    after ets:update_counter(State, active, -1)
    end.

blocked(State, Index) ->
    admit(State, Index),
    receive never -> Index end.

workers_stopped(State) ->
    lists:all(fun({{process, {worker, _}}, Pid}) -> not is_process_alive(Pid);
        (_) -> true end, ets:tab2list(State)).

kill_caller(State, Run) ->
    {Caller, Monitor} = spawn_monitor(fun() ->
        httpc_adaptive_ffi:select_ipv4(),
        Run()
    end),
    ets:insert(State, {{process, caller}, Caller}),
    try
        wait(fun() -> count(State, admitted) =:= 4 orelse
            count(State, calls) =:= 4 end, 2000),
        exit(Caller, kill),
        receive {'DOWN', Monitor, process, Caller, killed} -> ok
        after 1000 -> error(caller_not_stopped)
        end,
        wait(fun() -> workers_stopped(State) end, 1000),
        wait(fun() -> owned_stopped(State) end, 1500),
        case ets:lookup(State, before) of
            [] -> ok;
            [{before, Before}] ->
                wait(fun() -> connection_pids() -- Before =:= []
                    andalso tls_processes() -- ets:lookup_element(State, before_tls, 2) =:= []
                end, 1500)
        end,
        nil
    after erlang:demonitor(Monitor, [flush])
    end.

with_peer(Tls, Action) ->
    {ok, _} = application:ensure_all_started(gun),
    with_state(fun(State) ->
        {ok, Listener} = gen_tcp:listen(0,
            [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
        {ok, Port} = inet:port(Listener),
        Before = connection_pids(),
        ets:insert(State, {before, Before}),
        ets:insert(State, {before_tls, tls_processes()}),
        Acceptor = spawn(fun() -> accept(State, Listener, Tls) end),
        ets:insert(State, {{process, acceptor}, Acceptor}),
        Scheme = case Tls of true -> <<"https">>; false -> <<"http">> end,
        httpc_adaptive_ffi:select_ipv4(),
        try
            Action(State, <<Scheme/binary, "://127.0.0.1:",
                (integer_to_binary(Port))/binary, "/">>)
        after gen_tcp:close(Listener), httpc_adaptive_test_ffi:reset()
        end
    end).

accept(State, Listener, Tls) ->
    case gen_tcp:accept(Listener, 1000) of
        {ok, Socket} ->
            Handler = spawn(fun() ->
                receive {socket, Socket} -> serve(State, Socket, Tls) end
            end),
            ets:insert(State, {{process, {server, Handler}}, Handler}),
            ok = gen_tcp:controlling_process(Socket, Handler),
            Handler ! {socket, Socket},
            accept(State, Listener, Tls);
        {error, timeout} -> accept(State, Listener, Tls);
        {error, closed} -> ok
    end.

serve(State, Socket, Tls) ->
    try
        case gen_tcp:recv(Socket, 0, 2000) of
            {ok, _} ->
                increment(State, calls),
                record_network_processes(State),
                case Tls of
                    true -> ok;
                    false ->
                        ok = gen_tcp:send(Socket,
                            <<"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\na">>)
                end,
                read_until_closed(Socket),
                increment(State, closed);
            {error, closed} -> ok
        end
    after gen_tcp:close(Socket)
    end.

read_until_closed(Socket) ->
    case gen_tcp:recv(Socket, 0, 3000) of
        {ok, _TlsRecord} -> read_until_closed(Socket);
        {error, closed} -> ok;
        {error, econnreset} -> ok;
        Other -> error({peer_not_closed, Other})
    end.

record_network_processes(State) ->
    lists:foreach(fun(Pid) ->
        case process_info(Pid, current_function) of
            {current_function, {network_ffi, _, _}} ->
                ets:insert(State, {{owned, Pid}, true});
            _ -> ok
        end
    end, processes()).

assert_drained(State) ->
    [] = connection_pids() -- ets:lookup_element(State, before, 2),
    [] = tls_processes() -- ets:lookup_element(State, before_tls, 2),
    true = owned_stopped(State),
    true = workers_stopped(State),
    Calls = count(State, calls),
    wait(fun() -> count(State, closed) =:= Calls end, 1500),
    timer:sleep(100),
    Calls = count(State, calls),
    nil.

owned_stopped(State) ->
    lists:all(fun({{owned, Pid}, true}) -> not is_process_alive(Pid);
        (_) -> true end, ets:tab2list(State)).

interrupt_http(State, Kind) ->
    Interrupter = spawn(fun() ->
        wait(fun() -> count(State, calls) >= 4 end, 2000),
        Target = case Kind of
            worker -> ets:lookup_element(State, {process, {worker, 2}}, 2);
            helper ->
                [Helper | _] = [Pid || Pid <- processes(),
                    process_info(Pid, current_function) =:=
                        {current_function, {network_ffi, forward_lifecycle, 5}}],
                Helper;
            sender ->
                [Connection | _] =
                    connection_pids() -- ets:lookup_element(State, before, 2),
                Connection
        end,
        ets:insert(State, {{owned, Target}, true}),
        exit(Target, kill),
        ets:insert(State, {interrupted, true})
    end),
    ets:insert(State, {{process, interrupter}, Interrupter}),
    nil.

connection_pids() ->
    [Pid || {_, Pid, _, _} <- supervisor:which_children(gun_conns_sup),
        is_pid(Pid), is_process_alive(Pid)].

tls_processes() ->
    [Pid || Pid <- processes(), is_tls_process(Pid)].

is_tls_process(Pid) ->
    case process_info(Pid, dictionary) of
        {dictionary, Dictionary} ->
            case proplists:get_value('$initial_call', Dictionary) of
                {ssl_gen_statem, _, _} -> true;
                {tls_sender, _, _} -> true;
                {tls_connection, _, _} -> true;
                {tls_connection_1_3, _, _} -> true;
                _ -> false
            end;
        undefined -> false
    end.

wait(Check, Remaining) ->
    case Check() of
        true -> ok;
        false when Remaining > 0 -> timer:sleep(5), wait(Check, Remaining - 5);
        false -> error(network_test_wait_timeout)
    end.
