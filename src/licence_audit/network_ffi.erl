-module(network_ffi).
-export([with_command/1, context/0, with_task/4, open/2,
    gun_options/1, before_close/1, tls_resources/1, tls_scope/1,
    command_owner/0, state_get/2, state_put/2, shared_probe/2,
    host_failures/1, record_host_failure/1, clear_host_failures/1,
    reset_retry_state/0, defer_host/2, host_wait/2]).

-define(CONTEXT, {?MODULE, context}).
-define(GUARDIAN, {?MODULE, guardian}).
-define(OPENER, {?MODULE, opener}).

gun_options(Options) ->
    case erlang:get(?OPENER) of
        undefined -> Options;
        {Guardian, Reference} ->
            Monitor = erlang:monitor(process, Guardian),
            Guardian ! {factory_starting, self(), Reference},
            try
                receive
                    {factory_permission, Reference, continue} -> ok;
                    {factory_permission, Reference, cancel} ->
                        erlang:error(network_open_cancelled);
                    {'DOWN', Monitor, process, Guardian, Reason} ->
                        erlang:error({http_owner_stopped, Reason})
                end
            after erlang:demonitor(Monitor, [flush])
            end,
            Owned = Options#{event_handler => {network_events_ffi,
                #{guardian => Guardian, helper => self(), reference => Reference}}},
            case maps:get(transport, Options, tcp) of
                tcp -> Owned;
                tls ->
                    Owned#{tls_opts => [
                        {cb_info, {network_events_ffi, tcp, tcp_closed, tcp_error, tcp_passive}}
                        | maps:get(tls_opts, Options, [])]}
            end
    end.

before_close(Connection) ->
    case erlang:get(?GUARDIAN) of
        undefined -> nil;
        Guardian ->
            Reference = make_ref(),
            Reply = erlang:alias(),
            Monitor = erlang:monitor(process, Guardian),
            Guardian ! {before_close, self(), Reply, Reference, Connection},
            try
                receive
                    {Reference, close_ready} -> nil;
                    {'DOWN', Monitor, process, Guardian, Reason} ->
                        erlang:error({http_drain_proof_lost, Reason})
                after 5000 -> erlang:error(http_close_cancellation_unconfirmed)
                end
            after
                erlang:unalias(Reply),
                flush_open_reply(Reference),
                erlang:demonitor(Monitor, [flush])
            end
    end.

context() -> erlang:get(?CONTEXT).

command_owner() ->
    case context() of
        undefined -> self();
        State -> ets:info(State, owner)
    end.

with_command(Action) ->
    case context() of
        undefined ->
            State = ets:new(?MODULE, [set, public]),
            lists:foreach(fun(Key) ->
                case erlang:get({httpc_adaptive_ffi, Key}) of
                    undefined -> ok;
                    Value -> ets:insert(State, {Key, Value})
                end
            end, [family, ipv6_hosts]),
            Caller = self(),
            {Guardian, Monitor} = spawn_monitor(fun() ->
                WorkerMonitor = erlang:monitor(process, Caller),
                guard(Caller, WorkerMonitor, false, #{}, #{}, #{})
            end),
            erlang:put(?CONTEXT, State),
            erlang:put(?GUARDIAN, Guardian),
            try Action()
            after
                Guardian ! stop,
                try join_command(Guardian, Monitor)
                after
                    erlang:demonitor(Monitor, [flush]),
                    erlang:erase(?GUARDIAN),
                    erlang:erase(?CONTEXT),
                    ets:delete(State)
                end
            end;
        _ -> Action()
    end.

join_command(Guardian, Monitor) ->
    receive
        {http_drained, Guardian, Connections} ->
            lists:foreach(fun gun:flush/1, Connections),
            receive
                {'DOWN', Monitor, process, Guardian, normal} -> ok;
                {'DOWN', Monitor, process, Guardian, Reason} ->
                    erlang:error({http_coverage_incomplete,
                        {command_http_drain_proof_lost, Reason}})
            after 5000 ->
                erlang:error({http_coverage_incomplete,
                    command_http_cancellation_unconfirmed})
            end;
        {'DOWN', Monitor, process, Guardian, Reason} ->
            erlang:error({http_coverage_incomplete,
                {command_http_drain_proof_lost, Reason}})
    after 5000 ->
        erlang:error({http_coverage_incomplete, command_http_cancellation_unconfirmed})
    end.

state_get(Key, Default) ->
    case context() of
        undefined ->
            case erlang:get({httpc_adaptive_ffi, Key}) of
                undefined -> Default;
                Value -> Value
            end;
        State ->
            case ets:lookup(State, Key) of
                [] -> Default;
                [{Key, Value}] -> Value
            end
    end.

state_put(Key, Value) ->
    case context() of
        undefined -> erlang:put({httpc_adaptive_ffi, Key}, Value);
        State -> ets:insert(State, {Key, Value})
    end,
    nil.

host_failures(Host) ->
    case state_get({cutoff, Host}, false) of
        true -> 3;
        false -> state_get({failures, Host}, 0)
    end.

record_host_failure(Host) ->
    case context() of
        undefined -> state_put({failures, Host}, host_failures(Host) + 1);
        State ->
            Count = ets:update_counter(State, {failures, Host}, 1,
                {{failures, Host}, 0}),
            case Count >= 3 of
                true -> ets:insert(State, {{cutoff, Host}, true});
                false -> ok
            end,
            nil
    end.

clear_host_failures(Host) ->
    %% An already-admitted success cannot reopen a host stopped by its siblings.
    case state_get({cutoff, Host}, false) of
        true -> nil;
        false ->
            case context() of
                undefined -> state_put({failures, Host}, 0);
                State ->
                    Key = {failures, Host},
                    ets:select_replace(State,
                        [{{Key, '$1'}, [{'<', '$1', 3}], [{{{const, Key}, 0}}]}]),
                    nil
            end
    end.

reset_retry_state() ->
    case context() of
        undefined ->
            lists:foreach(fun({Key, _}) ->
                case Key of
                    {httpc_adaptive_ffi, {failures, _}} -> erlang:erase(Key);
                    {httpc_adaptive_ffi, {cutoff, _}} -> erlang:erase(Key);
                    _ -> ok
                end
            end, erlang:get());
        State ->
            ets:match_delete(State, {{failures, '_'}, '_'}),
            ets:match_delete(State, {{cutoff, '_'}, '_'}),
            ets:match_delete(State, {{cooldown, '_'}, '_'})
    end,
    nil.

defer_host(Host, Deadline) ->
    case context() of
        undefined -> nil;
        State ->
            Key = {cooldown, Host},
            case ets:insert_new(State, {Key, Deadline}) of
                true -> nil;
                false -> extend_deadline(State, Key, Deadline)
            end
    end.

extend_deadline(State, Key, Deadline) ->
    [{Key, Previous}] = ets:lookup(State, Key),
    case Deadline > Previous of
        false -> nil;
        true ->
            case ets:select_replace(State,
                [{{Key, Previous}, [], [{{{const, Key}, Deadline}}]}]) of
                1 -> nil;
                0 -> extend_deadline(State, Key, Deadline)
            end
    end.

host_wait(Host, Now) -> max(0, state_get({cooldown, Host}, Now) - Now).

shared_probe(Host, Probe) ->
    case context() of
        undefined -> Probe();
        State ->
            case state_get(family, undefined) of
                ipv4 -> {ok, ipv4};
                _ -> shared_probe_locked(State, Host, Probe)
            end
    end.

shared_probe_locked(State, Host, Probe) ->
            case ets:insert_new(State, {probe_lock, {self(), Host}}) of
                true ->
                    try
                        case {state_get(family, undefined),
                                state_get({probe, Host}, undefined)} of
                            {ipv4, _} -> {ok, ipv4};
                            {_, undefined} ->
                                Result = Probe(),
                                ets:insert(State, {{probe, Host}, Result}),
                                Result;
                            {_, Result} -> Result
                        end
                    after ets:delete(State, probe_lock)
                    end;
                false ->
                    case ets:lookup(State, probe_lock) of
                        [] -> shared_probe(Host, Probe);
                        [{probe_lock, {Owner, ProbeHost}}] ->
                            Monitor = erlang:monitor(process, Owner),
                            receive
                                {'DOWN', Monitor, process, Owner, _} ->
                                    Failure = {error, {request_failed,
                                        <<"IPv6 probe worker stopped; coverage is incomplete">>}},
                                    ets:insert_new(State, {{probe, ProbeHost}, Failure}),
                                    ets:select_delete(State,
                                        [{{probe_lock, {Owner, ProbeHost}}, [], [true]}]),
                                    shared_probe(Host, Probe)
                            after 5 ->
                                erlang:demonitor(Monitor, [flush]),
                                shared_probe(Host, Probe)
                            end
                    end
            end.

with_task(Ledger, State, _Index, Action) ->
    Worker = self(),
    Guardian = spawn(fun() ->
        Monitor = erlang:monitor(process, Worker),
        guard(Worker, Monitor, false, #{}, #{}, #{})
    end),
    case weft:adopt(Ledger, Guardian, fun() -> Guardian ! stop, nil end) of
        adopted ->
            erlang:put(?CONTEXT, State),
            erlang:put(?GUARDIAN, Guardian),
            try Action()
            after Guardian ! stop, erlang:erase(?GUARDIAN),
                erlang:erase(?CONTEXT)
            end;
        refused ->
            Guardian ! stop,
            erlang:error(network_task_cancelled_before_admission)
    end.

%% Opening runs under a monitored helper. Even if the pool worker dies while
%% gun:open is returning, its guardian waits for the helper and its connection.
%% No HTTP request is released until the connection has been recorded. The
%% helper remains Gun's owner and forwards lifecycle messages without waiting
%% for DNS/TCP/TLS setup, preserving the transport's absolute request deadline.
open(Open, Deadline) ->
    case Deadline =< erlang:monotonic_time(millisecond) of
        true -> {error, timeout};
        false -> open_before_deadline(Open, Deadline)
    end.

open_before_deadline(Open, Deadline) ->
    case erlang:get(?GUARDIAN) of
        undefined -> Open();
        Guardian ->
            Reference = make_ref(),
            Reply = erlang:alias(),
            Monitor = erlang:monitor(process, Guardian),
            Guardian ! {open, self(), Reply, Reference, Open},
            Remaining = max(0, Deadline - erlang:monotonic_time(millisecond)),
            try
                receive
                    {Reference, {runtime_error, Reason}} ->
                        erlang:error(Reason);
                    {Reference, Result} ->
                        case erlang:monotonic_time(millisecond) >= Deadline of
                            true ->
                                Guardian ! {cancel_open, Reference},
                                {error, timeout};
                            false -> Result
                        end;
                    {'DOWN', Monitor, process, Guardian, Reason} ->
                        erlang:error({http_owner_stopped, Reason})
                after Remaining ->
                    Guardian ! {cancel_open, Reference},
                    {error, timeout}
                end
            after
                erlang:unalias(Reply),
                flush_open_reply(Reference),
                erlang:demonitor(Monitor, [flush])
            end
    end.

flush_open_reply(Reference) ->
    receive {Reference, _} -> flush_open_reply(Reference)
    after 0 -> ok
    end.

guard(Worker, WorkerMonitor, Stopping, Helpers, Connections, Cancelled) ->
    case Stopping andalso map_size(Helpers) =:= 0 andalso
        map_size(Connections) =:= 0 of
        true ->
            erlang:demonitor(WorkerMonitor, [flush]),
            Worker ! {http_drained, self(),
                case erlang:get(connections) of undefined -> []; Seen -> Seen end},
            case erlang:get(failure) of
                undefined -> ok;
                Reason -> exit(Reason)
            end;
        false ->
            receive
                stop ->
                    Draining = stop_connections(Connections),
                    CancelledAll = stop_helpers(Helpers, Cancelled),
                    guard(Worker, WorkerMonitor, true, Helpers, Draining, CancelledAll);
                {'DOWN', WorkerMonitor, process, Worker, _} ->
                    Draining = stop_connections(Connections),
                    CancelledAll = stop_helpers(Helpers, Cancelled),
                    guard(Worker, WorkerMonitor, true, Helpers, Draining, CancelledAll);
                {factory_starting, Helper, Reference} ->
                    case maps:find(Helper, Helpers) of
                        {ok, {Monitor, Reference, preparing}}
                                when not Stopping, not is_map_key(Reference, Cancelled) ->
                            Helper ! {factory_permission, Reference, continue},
                            guard(Worker, WorkerMonitor, Stopping,
                                Helpers#{Helper => {Monitor, Reference, opening}},
                                Connections, Cancelled);
                        _ ->
                            Helper ! {factory_permission, Reference, cancel},
                            guard(Worker, WorkerMonitor, Stopping,
                                Helpers, Connections, Cancelled)
                    end;
                {before_close, Worker, Reply, Reference, Connection} ->
                    case erlang:get({connection, Connection}) of
                        undefined -> ok;
                        ClosingReference -> erlang:put({closing, ClosingReference}, true)
                    end,
                    Tracked = track_connection_tls(Connection, Connections),
                    case awaiting_tls_capture(Connection) of
                        true ->
                            Waiters = case erlang:get({close_waiters, Connection}) of
                                undefined -> [];
                                PreviousWaiters -> PreviousWaiters
                            end,
                            erlang:put({close_waiters, Connection},
                                [{Reply, Reference} | Waiters]),
                            CancelReference = erlang:get({connection, Connection}),
                            guard(Worker, WorkerMonitor, Stopping, Helpers, Tracked,
                                Cancelled#{CancelReference => true});
                        false ->
                            Reply ! {Reference, close_ready},
                            guard(Worker, WorkerMonitor, Stopping, Helpers, Tracked, Cancelled)
                    end;
                {transport_event, Connection, Helper, Reference, Event} ->
                    Allowed = not Stopping andalso not maps:is_key(Reference, Cancelled)
                        andalso case maps:find(Helper, Helpers) of
                            {ok, {_, Reference, _}} -> true;
                            _ -> false
                        end,
                    Tracked = transport_event(Event, Reference, Connections),
                    case Allowed of
                        true -> Connection ! {transport_event_ack, Reference, continue};
                        false ->
                            case Event of
                                {tls_starting, Connection} ->
                                    erlang:erase({tls_started, Connection});
                                _ -> ok
                            end,
                            Connection ! {transport_event_ack, Reference, cancel}
                    end,
                    Draining = case Allowed of
                        true -> Tracked;
                        false -> maps:merge(Tracked,
                            stop_connections(select_connections(Reference, Tracked)))
                    end,
                    guard(Worker, WorkerMonitor, Stopping, Helpers, Draining, Cancelled);
                {open, Worker, Reply, Reference, Open} when not Stopping ->
                    Guardian = self(),
                    {Helper, Monitor} = spawn_monitor(fun() ->
                        open_connection(Guardian, Worker, Reply, Reference, Open)
                    end),
                    guard(Worker, WorkerMonitor, Stopping,
                        Helpers#{Helper => {Monitor, Reference, preparing}},
                        Connections, Cancelled);
                {open, Worker, Reply, Reference, _} ->
                    Reply ! {Reference, {runtime_error, network_task_cancelled}},
                    guard(Worker, WorkerMonitor, Stopping, Helpers, Connections, Cancelled);
                {cancel_open, Reference} ->
                    Selected = select_connections(Reference, Connections),
                    Draining = maps:merge(Connections, stop_connections(Selected)),
                    SelectedHelpers = maps:filter(fun(_, {_, OpenReference, _}) ->
                        Reference =:= OpenReference
                    end, Helpers),
                    CancelledAll = stop_helpers(SelectedHelpers,
                        Cancelled#{Reference => true}),
                    guard(Worker, WorkerMonitor, Stopping, Helpers, Draining,
                        CancelledAll);
                {opened, Helper, Reference, Connection} ->
                    Seen = case erlang:get(connections) of
                        undefined -> [];
                        Previous -> Previous
                    end,
                    case lists:member(Connection, Seen) of
                        true -> ok;
                        false -> erlang:error(http_connection_started_without_owner)
                    end,
                    Selected = select_connections(Reference, Connections),
                    Tracked = case {Stopping, maps:is_key(Reference, Cancelled)} of
                        {true, _} -> stop_connections(Connections);
                        {false, true} ->
                            maps:merge(Connections, stop_connections(Selected));
                        {false, false} -> Connections
                    end,
                    Helper ! {recorded, Connection},
                    guard(Worker, WorkerMonitor, Stopping, Helpers,
                        Tracked, Cancelled);
                {'DOWN', Monitor, _Type, Pid, Reason} ->
                    case maps:take(Pid, Helpers) of
                        {{Monitor, _, _}, Rest} when Reason =:= normal ->
                            guard(Worker, WorkerMonitor, Stopping, Rest, Connections, Cancelled);
                        {{Monitor, Reference, Phase}, Rest} ->
                            case maps:is_key(Reference, Cancelled) of
                                true ->
                                    case {Phase, erlang:get({started, Reference})} of
                                        {opening, undefined} ->
                                            erlang:put(failure,
                                                {http_open_cancellation_unconfirmed, Reference});
                                        _ -> ok
                                    end,
                                    guard(Worker, WorkerMonitor, Stopping,
                                        Rest, Connections, Cancelled);
                                false ->
                                    Draining = stop_connections(Connections),
                                    erlang:put(failure, {http_opener_crashed, Reason}),
                                    CancelledAll = stop_helpers(Rest, Cancelled),
                                    guard(Worker, WorkerMonitor, true,
                                        Rest, Draining, CancelledAll)
                            end;
                        error ->
                            case maps:find(Pid, Connections) of
                                {ok, {Monitor, _}} ->
                                    check_tls_proof(Pid),
                                    check_actor_exit(Pid, Reason, Stopping,
                                        maps:get(Pid, Connections), Cancelled),
                                    guard(Worker, WorkerMonitor, Stopping, Helpers,
                                        maps:remove(Pid, Connections), Cancelled);
                                _ ->
                                    guard(Worker, WorkerMonitor, Stopping,
                                        Helpers, Connections, Cancelled)
                            end
                    end
            end
    end.

stop_helpers(Helpers, Cancelled) ->
    maps:fold(fun(Helper, {_, Reference, _}, Acc) ->
        exit(Helper, kill),
        Acc#{Reference => true}
    end, Cancelled, Helpers).

stop_connections(Connections) ->
    Tracked = maps:fold(fun
        (_, {_, {_, _}}, Acc) -> Acc;
        (Connection, _, Acc) ->
            track_connection_tls(Connection, Acc)
    end, Connections, Connections),
    maps:fold(fun
        (Supervisor, {_, {tls_supervisor, Reference}}, Acc) ->
            case erlang:get({tls_stopping, Supervisor}) of
                true -> Acc;
                undefined ->
                    erlang:put({tls_stopping, Supervisor}, true),
                    Actors = [Pid || {Pid, {_, {resource, Owner}}} <- maps:to_list(Tracked),
                        Owner =:= Reference, is_pid(Pid)],
                    {Helper, Monitor} = spawn_monitor(fun() ->
                        shutdown_tls(Supervisor, Actors)
                    end),
                    Acc#{Helper => {Monitor, {cleanup, Reference}}}
            end;
        (_, {_, {_, _}}, Acc) -> Acc;
        (Connection, _, Acc) ->
            case awaiting_tls_capture(Connection) of
                true -> ok;
                false -> exit(Connection, shutdown)
            end,
            Acc
    end, Tracked, Tracked).

shutdown_tls(Supervisor, Actors) ->
    Monitor = erlang:monitor(process, Supervisor),
    try
        try sys:terminate(Supervisor, shutdown, 1000)
        catch
            exit:{noproc, _} -> ok;
            exit:{Stopped, {sys, terminate, _}}
                    when Stopped =:= shutdown; Stopped =:= normal -> ok
        end,
        receive {'DOWN', Monitor, process, Supervisor, _} -> ok
        after 1000 -> exit(http_tls_shutdown_unconfirmed)
        end
    catch
        Class:Reason:Stack ->
            lists:foreach(fun(Pid) -> exit(Pid, kill) end, [Supervisor | Actors]),
            erlang:raise(Class, Reason, Stack)
    after erlang:demonitor(Monitor, [flush])
    end.

select_connections(Reference, Connections) ->
    maps:filter(fun
        (_, {_, {_, OpenReference}}) -> Reference =:= OpenReference;
        (_, {_, OpenReference}) -> Reference =:= OpenReference
    end, Connections).

transport_event({starting, Connection}, Reference, Connections) ->
    erlang:put({connection, Connection}, Reference),
    erlang:put({started, Reference}, true),
    Seen = case erlang:get(connections) of undefined -> []; Previous -> Previous end,
    erlang:put(connections, lists:usort([Connection | Seen])),
    Connections#{Connection => {erlang:monitor(process, Connection), Reference}};
transport_event({socket, _, Socket}, Reference, Connections) ->
    case maps:is_key(Socket, Connections) of
        true -> Connections;
        false ->
            Connections#{Socket => {monitor_socket(Socket), {resource, Reference}}}
    end;
transport_event({tls_starting, Connection}, _, Connections) ->
    erlang:put({tls_started, Connection}, true),
    Connections;
transport_event({tls_ready, Connection, Resources}, Reference, Connections) ->
    record_tls_capture(Connection, Resources),
    release_close_waiters(Connection),
    track_tls(Resources, Reference, Connections);
transport_event({tls_finished, Connection}, _, Connections) ->
    erlang:put({tls_finished, Connection}, true),
    release_close_waiters(Connection),
    Connections.

awaiting_tls_capture(Connection) ->
    erlang:get({tls_started, Connection}) =:= true
        andalso erlang:get({tls_captured, Connection}) =/= true
        andalso erlang:get({tls_finished, Connection}) =/= true.

release_close_waiters(Connection) ->
    case erlang:erase({close_waiters, Connection}) of
        undefined -> ok;
        Waiters ->
            lists:foreach(fun({Reply, Reference}) ->
                Reply ! {Reference, close_ready}
            end, Waiters)
    end.

monitor_socket(Socket) when is_port(Socket) -> erlang:monitor(port, Socket);
monitor_socket({'$socket', _} = Socket) -> socket:monitor(Socket).

track_connection_tls(Connection, Connections) ->
    case {erlang:get({tls_captured, Connection}), maps:find(Connection, Connections)} of
        {true, _} -> Connections;
        {_, error} -> Connections;
        {_, {ok, {_, Reference}}} ->
            Resources = tls_resources(Connection),
            record_tls_capture(Connection, Resources),
            track_tls(Resources, Reference, Connections)
    end.

record_tls_capture(_, []) -> ok;
record_tls_capture(Connection, [_ | _]) ->
    erlang:put({tls_captured, Connection}, true).

check_tls_proof(Connection) ->
    case {erlang:get({tls_started, Connection}),
            erlang:get({tls_captured, Connection})} of
        {true, undefined} ->
            erlang:put(failure, {http_tls_teardown_unconfirmed, Connection});
        _ -> ok
    end.

check_actor_exit(Pid, Reason, _, {_, {cleanup, _}}, _) when Reason =/= normal ->
    erlang:put(failure, {http_tls_cleanup_failed, Pid, Reason});
check_actor_exit(Socket, _, _, {_, {resource, _}}, _) when not is_pid(Socket) -> ok;
check_actor_exit(_, normal, _, _, _) -> ok;
check_actor_exit(_, shutdown, _, _, _) -> ok;
check_actor_exit(_, {shutdown, _}, _, _, _) -> ok;
check_actor_exit(_, _, true, _, _) -> ok;
check_actor_exit(Pid, Reason, false, {_, Owner}, Cancelled) ->
    Reference = case Owner of {_, Value} -> Value; Value -> Value end,
    case maps:is_key(Reference, Cancelled) orelse
            erlang:get({closing, Reference}) =:= true of
        true -> ok;
        false -> erlang:put(failure, {http_actor_crashed, Pid, Reason})
    end.

track_tls([], _, Connections) -> Connections;
track_tls([Supervisor | Actors], Reference, Connections) ->
    Tracked = case maps:is_key(Supervisor, Connections) of
        true -> Connections;
        false ->
            Connections#{Supervisor =>
                {erlang:monitor(process, Supervisor), {tls_supervisor, Reference}}}
    end,
    lists:foldl(fun(Pid, Acc) ->
        case maps:is_key(Pid, Acc) of
            true -> Acc;
            false ->
                Acc#{Pid => {erlang:monitor(process, Pid), {resource, Reference}}}
        end
    end, Tracked, Actors).

%% OTP 28 gives each TLS connection a temporary supervisor with a significant
%% receiver and its sender. Join that scope as well as Gun, without stopping
%% shared SSL supervisors or inspecting Gun's synchronous setup state.
tls_resources(Connection) ->
    case process_info(Connection, monitored_by) of
        undefined -> [];
        {monitored_by, Monitors} ->
            lists:flatmap(fun(Pid) ->
                case proc_lib:translate_initial_call(Pid) of
                    {ssl_gen_statem, _, _} -> tls_scope(Pid);
                    _ -> []
                end
            end, Monitors)
    end.

tls_scope(Receiver) ->
    case process_info(Receiver, dictionary) of
        undefined -> erlang:error(http_tls_receiver_stopped_during_capture);
        {dictionary, Dictionary} ->
            [Supervisor | _] = proplists:get_value('$ancestors', Dictionary),
            {supervisor, tls_dyn_connection_sup, _} =
                proc_lib:translate_initial_call(Supervisor),
            Children = gen_server:call(Supervisor, which_children, 1000),
            {receiver, Receiver, worker, _} = lists:keyfind(receiver, 1, Children),
            [Supervisor | [Pid || {_, Pid, _, _} <- Children, is_pid(Pid)]]
    end.

open_connection(Guardian, Worker, Reply, Reference, Open) ->
    GuardianMonitor = erlang:monitor(process, Guardian),
    erlang:put(?OPENER, {Guardian, Reference}),
    case Open() of
        {ok, Connection} ->
            Guardian ! {opened, self(), Reference, Connection},
            receive
                {recorded, Connection} ->
                    ConnectionMonitor = erlang:monitor(process, Connection),
                    Reply ! {Reference, {ok, Connection}},
                    forward_lifecycle(Connection, ConnectionMonitor,
                        Worker, Guardian, GuardianMonitor);
                {'DOWN', GuardianMonitor, process, Guardian, _} ->
                    stop_sender(Connection)
            end;
        {error, _} = Error -> Reply ! {Reference, Error}
    end,
    erlang:demonitor(GuardianMonitor, [flush]).

forward_lifecycle(Connection, ConnectionMonitor, Worker, Guardian, GuardianMonitor) ->
    receive
        {'DOWN', ConnectionMonitor, process, Connection, _} -> ok;
        {'DOWN', GuardianMonitor, process, Guardian, _} -> stop_sender(Connection);
        {gun_up, Connection, _} = Message ->
            Worker ! Message,
            forward_lifecycle(Connection, ConnectionMonitor, Worker, Guardian, GuardianMonitor);
        {gun_down, Connection, _, _, _} = Message ->
            Worker ! Message,
            forward_lifecycle(Connection, ConnectionMonitor, Worker, Guardian, GuardianMonitor);
        {gun_error, Connection, _} = Message ->
            Worker ! Message,
            forward_lifecycle(Connection, ConnectionMonitor, Worker, Guardian, GuardianMonitor)
    end.

stop_sender(Connection) ->
    Monitor = erlang:monitor(process, Connection),
    exit(Connection, shutdown),
    receive {'DOWN', Monitor, process, Connection, _} -> ok end.
