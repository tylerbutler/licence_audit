-module(picker_lifecycle_test_ffi).
-export([run/0]).

run() ->
    Path = unicode:characters_to_binary(os:getenv("PICKER_POLICY_PATH")),
    Manifest = unicode:characters_to_binary(os:getenv("PICKER_MANIFEST_PATH")),
    Mode = os:getenv("PICKER_TEST_MODE"),
    {ok, Control} = gen_tcp:connect({127, 0, 0, 1},
        list_to_integer(os:getenv("PICKER_CONTROL_PORT")),
        [binary, {active, false}, {packet, 4}], 10000),
    Parent = self(),
    Observer = spawn_link(fun() -> observe(Parent, Control, Mode) end),
    {module, etch@event} = code:ensure_loaded(etch@event),
    {module, etch@terminal} = code:ensure_loaded(etch@terminal),
    erlang:trace_pattern({etch@event, init_event_server, 0},
        [{'_', [], [{return_trace}]}], [local]),
    erlang:trace_pattern({etch@terminal, exit_raw, 0}, true, [local]),
    erlang:trace(self(), true,
        [call, procs, set_on_spawn, monotonic_timestamp, {tracer, Observer}]),
    Picker = fun(Title, Labels, Allow, Deny) ->
        Result = licence_audit@picker:pick(Title, Labels, Allow, Deny),
        Delivered = erlang:trace_delivered(all),
        receive {trace_delivered, all, Delivered} -> ok end,
        Observer ! {checkpoint, self()},
        receive
            {reader, Reader} ->
                %% Do not wait for exit here: it must already be dead on return.
                false = is_process_alive(Reader)
        after 10000 ->
            error(reader_not_observed)
        end,
        false = etch@terminal:is_raw_mode(),
        {ok, Original} = file:read_file(Path),
        nomatch = binary:match(Original, <<"deny = [\"ISC\"]">>),
        case Mode of
            "accept" -> {ok, {selection, [], [<<"ISC">>]}} = Result;
            _ -> {error, cancelled} = Result
        end,
        ok = gen_tcp:send(Control, <<"before-policy">>),
        {ok, <<"continue">>} = gen_tcp:recv(Control, 0, 10000),
        Result
    end,
    {Outcome, _} = licence_audit@update:run_with_picker(
        Manifest, <<".">>,
        {update_options, none, {some, Path}, verbose, never, true, none},
        licence_audit@notice:default_clients(), Picker,
        licence_audit@progress:capturing(verbose, <<"update">>)
    ),
    case Mode of
        "accept" ->
            {update_result, 0, _} = Outcome,
            {ok, Saved} = file:read_file(Path),
            nomatch =/= binary:match(Saved, <<"deny = [\"ISC\"]">>) orelse
                error(policy_not_written);
        _ -> {update_diagnostic, 130, _} = Outcome
    end,
    erlang:trace(all, false, [call, procs, set_on_spawn]),
    erlang:trace_pattern({etch@event, init_event_server, 0}, false, [local]),
    erlang:trace_pattern({etch@terminal, exit_raw, 0}, false, [local]),
    ok = gen_tcp:send(Control, <<"done">>),
    {ok, <<"finish">>} = gen_tcp:recv(Control, 0, 10000),
    gen_tcp:close(Control),
    halt().

observe(Parent, Control, Mode) ->
    receive
        {trace_ts, Worker, return_from, {etch@event, init_event_server, 0}, Reader, _} ->
            await_read(Reader, 1000),
            ok = gen_tcp:send(Control, <<"reader-ready">>),
            {ok, <<"act">>} = gen_tcp:recv(Control, 0, 10000),
            case Mode of
                "worker_failure" -> exit(Worker, kill);
                "reader_failure" -> exit(Reader, kill);
                "read_failure" ->
                    lists:foreach(fun(_) ->
                        event_ffi:push({error, {failed_to_parse_event, <<"injected">>}})
                    end, lists:seq(1, 3));
                _ -> ok
            end,
            observe_cleanup(Parent, Reader, undefined, undefined);
        _ -> observe(Parent, Control, Mode)
    after 10000 ->
        error(reader_did_not_start)
    end.

observe_cleanup(Parent, Reader, ExitTime, RestoreTime) ->
    receive
        {trace_ts, Reader, exit, _Reason, Time} ->
            observe_cleanup(Parent, Reader, Time, RestoreTime);
        {trace_ts, Parent, call, {etch@terminal, exit_raw, []}, Time} ->
            observe_cleanup(Parent, Reader, ExitTime, Time);
        {checkpoint, Parent} ->
            true = is_integer(ExitTime),
            true = is_integer(RestoreTime),
            true = ExitTime < RestoreTime,
            Parent ! {reader, Reader};
        _ -> observe_cleanup(Parent, Reader, ExitTime, RestoreTime)
    after 10000 ->
        error(picker_did_not_return)
    end.

await_read(_Reader, 0) ->
    error(reader_did_not_block);
await_read(Reader, Attempts) ->
    case process_info(Reader, current_stacktrace) of
        {current_stacktrace, Stack} ->
            case lists:any(fun
                ({io, execute_request, 3, _}) -> true;
                (_) -> false
            end, Stack) of
                true -> ok;
                false ->
                    timer:sleep(1),
                    await_read(Reader, Attempts - 1)
            end;
        undefined -> error(reader_exited_before_input)
    end.
