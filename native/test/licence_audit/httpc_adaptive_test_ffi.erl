-module(httpc_adaptive_test_ffi).
-export([request_with_invalid_options/1, reset/0, with_http_response/2,
    with_script/2, scripted_request/1, now_ms/0, elapsed_ms/0, sleep/1,
    attempts/0, waits/0, record_request/1, requests/0, with_retry_response/2,
    with_backlog_response/2, with_retry_responses/2, with_recorded_response/2]).

with_script(Responses, Action) ->
    reset(),
    erlang:put({?MODULE, responses}, Responses),
    erlang:put({?MODULE, now}, 1700000000000),
    erlang:put({?MODULE, elapsed}, 0),
    erlang:put({?MODULE, attempts}, 0),
    erlang:put({?MODULE, waits}, []),
    erlang:put({?MODULE, requests}, []),
    try Action()
    after
        reset(),
        lists:foreach(fun(Key) -> erlang:erase({?MODULE, Key}) end,
            [responses, now, elapsed, attempts, waits, requests])
    end.

scripted_request(Request) ->
    [Response | Rest] = erlang:get({?MODULE, responses}),
    erlang:put({?MODULE, responses}, Rest),
    record_request(Request),
    Response.

record_request(Request) ->
    erlang:put({?MODULE, attempts}, attempts() + 1),
    erlang:put({?MODULE, requests}, [Request | erlang:get({?MODULE, requests})]),
    nil.

requests() -> lists:reverse(erlang:get({?MODULE, requests})).

with_backlog_response(Response, Client) ->
    with_retry_response({backlog, Response}, Client).

with_retry_responses(Responses, Client) ->
    with_retry_response({sequence, Responses}, Client).

with_retry_response(Response, Client) ->
    {Result, Count, _Requests} = with_recorded_responses(Response, Client),
    {Result, Count}.

with_recorded_response(Response, Client) ->
    {Result, _Count, Requests} = with_recorded_responses(Response, Client),
    {Result, Requests}.

with_recorded_responses(Response, Client) ->
    {ok, _} = application:ensure_all_started(gun),
    Before = connection_pids(),
    {ok, Listener} = gen_tcp:listen(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(Listener),
    Owner = self(),
    {Pid, Ref} = spawn_monitor(fun() -> retry_server(Listener, Response, Owner, 0) end),
    httpc_adaptive_ffi:select_ipv4(),
    try
        Result = Client(<<"http://127.0.0.1:", (integer_to_binary(Port))/binary, "/">>),
        timer:sleep(100),
        [] = connection_pids() -- Before,
        {messages, Messages} = process_info(self(), messages),
        [] = [Message || Message <- Messages, is_gun_message(Message)],
        ok = gen_tcp:close(Listener),
        receive {retry_server_count, Pid, Count} ->
            Requests = [receive {retry_raw_request, Pid, Bytes} -> Bytes end
                || _ <- lists:seq(1, Count)],
            {Result, Count, Requests}
        after 5000 -> erlang:error(retry_server_timeout)
        end
    after
        gen_tcp:close(Listener),
        receive
            {'DOWN', Ref, process, Pid, normal} -> ok;
            {'DOWN', Ref, process, Pid, Reason} -> erlang:error({retry_server_failed, Reason})
        after 5000 ->
            exit(Pid, kill),
            receive {'DOWN', Ref, process, Pid, _} -> ok end,
            erlang:error(retry_server_timeout)
        end,
        reset()
    end.

retry_server(Listener, Response, Owner, Count) ->
    case gen_tcp:accept(Listener) of
        {ok, Socket} ->
            try
                Received = receive_request(Socket, <<>>),
                Owner ! {retry_raw_request, self(), Received},
                case Response of
                    {backlog, Bytes} ->
                        erlang:suspend_process(Owner),
                        try
                            ok = gen_tcp:send(Socket, Bytes),
                            timer:sleep(100)
                        after erlang:resume_process(Owner)
                        end;
                    {sequence, Responses} ->
                        ok = gen_tcp:send(Socket, lists:nth(Count + 1, Responses));
                    Bytes -> ok = gen_tcp:send(Socket, Bytes)
                end
            after gen_tcp:close(Socket)
            end,
            retry_server(Listener, Response, Owner, Count + 1);
        {error, closed} -> Owner ! {retry_server_count, self(), Count}
    end.

receive_request(Socket, Received) ->
    Complete = case binary:split(Received, <<"\r\n\r\n">>) of
        [Headers, Body] ->
            Length = case re:run(Headers,
                <<"(?i)(?:^|\\r\\n)content-length:\\s*([0-9]+)">>,
                [{capture, [1], binary}]) of
                {match, [Value]} -> binary_to_integer(Value);
                nomatch -> 0
            end,
            byte_size(Body) >= Length;
        [_] -> false
    end,
    case Complete of
        true -> Received;
        false ->
            {ok, Bytes} = gen_tcp:recv(Socket, 0, 5000),
            receive_request(Socket, <<Received/binary, Bytes/binary>>)
    end.

connection_pids() ->
    [Pid || {_, Pid, _, _} <- supervisor:which_children(gun_conns_sup),
        is_pid(Pid), is_process_alive(Pid)].

is_gun_message(Message) when is_tuple(Message), tuple_size(Message) > 0 ->
    lists:member(element(1, Message),
        [gun_up, gun_down, gun_error, gun_response, gun_data, gun_inform,
            gun_trailers, gun_push, gun_upgrade, gun_ws]);
is_gun_message(_) -> false.

attempts() -> erlang:get({?MODULE, attempts}).
waits() -> lists:reverse(erlang:get({?MODULE, waits})).
now_ms() -> erlang:get({?MODULE, now}).
elapsed_ms() -> erlang:get({?MODULE, elapsed}).

sleep(Milliseconds) ->
    erlang:put({?MODULE, now}, now_ms() + Milliseconds),
    erlang:put({?MODULE, elapsed}, elapsed_ms() + Milliseconds),
    erlang:put({?MODULE, waits}, [Milliseconds | erlang:get({?MODULE, waits})]),
    nil.

request_with_invalid_options(HasBody) ->
    {Method, Request} = case HasBody of
        true -> {post, {"https://example.invalid", [], "text/plain", <<>>}};
        false -> {get, {"https://example.invalid", []}}
    end,
    {error, Reason} = httpc_adaptive_ffi:request(Method, Request, not_a_list, []),
    httpc_adaptive_ffi:normalise_error(Reason).

%% Injected Gleam transports bypass httpc. Use real loopback TCP for malformed
%% responses/disconnects and OTP try/after to clear sockets and transport state
%% even when a test assertion raises.
reset() ->
    erlang:erase({httpc_adaptive_ffi, family}),
    erlang:erase({httpc_adaptive_ffi, ipv6_hosts}),
    erlang:erase({httpc_adaptive_ffi, warning}),
    httpc_adaptive_ffi:reset_retry_state().

with_http_response(Response, Client) ->
    {ok, _} = application:ensure_all_started(inets),
    {ok, Listener} = gen_tcp:listen(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(Listener),
    {Pid, Ref} = spawn_monitor(fun() ->
        {ok, Socket} = gen_tcp:accept(Listener, 5000),
        {ok, _Request} = gen_tcp:recv(Socket, 0, 5000),
        case Response of
            <<>> -> ok;
            _ -> ok = gen_tcp:send(Socket, Response)
        end,
        ok = gen_tcp:close(Socket)
    end),
    httpc_adaptive_ffi:fallback_to_ipv4(<<"test">>),
    try Client(<<"http://127.0.0.1:", (integer_to_binary(Port))/binary, "/">>)
    after
        gen_tcp:close(Listener),
        receive
            {'DOWN', Ref, process, Pid, normal} -> ok;
            {'DOWN', Ref, process, Pid, Reason} -> erlang:error({server_failed, Reason})
        after 5000 ->
            exit(Pid, kill),
            receive {'DOWN', Ref, process, Pid, _} -> ok end,
            erlang:error(server_timeout)
        end,
        reset()
    end.
