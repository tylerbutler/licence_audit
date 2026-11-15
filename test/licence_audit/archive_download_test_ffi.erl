-module(archive_download_test_ffi).
-export([with_response/4, with_untrusted_tls/1]).

%% Loopback transfers observe early socket closure as well as the returned
%% error. Wait for the server, then check resources and late mailbox data.
with_response(Headers, Chunks, Delay, Check) ->
    {ok, _} = application:ensure_all_started(gun),
    Before = connection_pids(),
    {ok, Listener} = gen_tcp:listen(0,
        [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(Listener),
    Parent = self(),
    {Server, Monitor} = spawn_monitor(fun() ->
        {ok, Socket} = gen_tcp:accept(Listener, 5000),
        try
            Sent = case gen_tcp:recv(Socket, 0, 5000) of
                {ok, _} ->
                    ok = gen_tcp:send(Socket, Headers),
                    case {Headers, Chunks} of
                        {<<>>, []} -> drain_tls_until_closed(Socket);
                        _ -> send_chunks(Socket, Chunks, Delay, 0)
                    end;
                {error, closed} -> 0;
                {error, econnreset} -> 0
            end,
            Parent ! {self(), sent, Sent}
        after
            gen_tcp:close(Socket)
        end
    end),
    httpc_adaptive_ffi:fallback_to_ipv4(<<"test">>),
    try
        Result = Check(<<"http://127.0.0.1:", (integer_to_binary(Port))/binary, "/">>),
        Sent = receive
            {Server, sent, Count} -> Count;
            {'DOWN', Monitor, process, Server, Reason} ->
                erlang:error({server_failed, Reason})
        after 5000 -> erlang:error(server_timeout)
        end,
        receive
            {'DOWN', Monitor, process, Server, normal} -> ok;
            {'DOWN', Monitor, process, Server, ExitReason} ->
                erlang:error({server_failed, ExitReason})
        after 5000 -> erlang:error(server_timeout)
        end,
        timer:sleep(10),
        [] = connection_pids() -- Before,
        {messages, Messages} = process_info(self(), messages),
        [] = [Message || Message <- Messages, is_gun_message(Message)],
        {Result, Sent}
    after
        gen_tcp:close(Listener),
        exit(Server, kill),
        erlang:demonitor(Monitor, [flush]),
        httpc_adaptive_test_ffi:reset()
    end.

with_untrusted_tls(Check) ->
    {ok, _} = application:ensure_all_started(ssl),
    CertificateOptions = [{digest, sha256}, {key, {rsa, 2048, 65537}}],
    Certificate = public_key:pkix_test_data(#{root => CertificateOptions,
        intermediates => [], peer => CertificateOptions}),
    {ok, Listener} = ssl:listen(0,
        [binary, {active, false}, {ip, {127, 0, 0, 1}} | Certificate]),
    {ok, {_, Port}} = ssl:sockname(Listener),
    {Server, Monitor} = spawn_monitor(fun() ->
        {ok, Socket} = ssl:transport_accept(Listener, 5000),
        {error, _} = ssl:handshake(Socket, 5000),
        ssl:close(Socket)
    end),
    httpc_adaptive_ffi:fallback_to_ipv4(<<"test">>),
    try
        Result = Check(<<"https://127.0.0.1:", (integer_to_binary(Port))/binary, "/">>),
        receive
            {'DOWN', Monitor, process, Server, normal} -> ok;
            {'DOWN', Monitor, process, Server, Reason} ->
                erlang:error({tls_server_failed, Reason})
        after 5000 -> erlang:error(tls_server_timeout)
        end,
        Result
    after
        ssl:close(Listener),
        exit(Server, kill),
        erlang:demonitor(Monitor, [flush]),
        httpc_adaptive_test_ffi:reset()
    end.

%% A stalled TLS peer must accept alert records sent during client teardown.
drain_tls_until_closed(Socket) ->
    case gen_tcp:recv(Socket, 0, 1000) of
        {ok, _Record} -> drain_tls_until_closed(Socket);
        {error, closed} -> 0;
        {error, econnreset} -> 0;
        {error, timeout} -> erlang:error(tls_client_did_not_close)
    end.

send_chunks(Socket, [], _Delay, Sent) ->
    %% A header-only rejection must close before the server sends any body.
    case gen_tcp:recv(Socket, 0, 1000) of
        {error, closed} -> Sent;
        {error, econnreset} -> Sent;
        {error, timeout} -> erlang:error(client_did_not_close);
        Other -> erlang:error({unexpected_request_data, Other})
    end;
send_chunks(Socket, [Chunk | Rest], Delay, Sent) ->
    timer:sleep(Delay),
    case gen_tcp:send(Socket, Chunk) of
        ok ->
            case Rest of
                [] -> Sent + byte_size(Chunk);
                _ -> send_chunks(Socket, Rest, Delay, Sent + byte_size(Chunk))
            end;
        {error, closed} -> Sent;
        {error, econnreset} -> Sent;
        {error, enotconn} -> Sent;
        {error, Reason} -> erlang:error({send_failed, Reason})
    end.

connection_pids() ->
    [Pid || {_Id, Pid, _Type, _Modules} <- supervisor:which_children(gun_conns_sup),
        is_pid(Pid), is_process_alive(Pid)].

is_gun_message(Message) when is_tuple(Message), tuple_size(Message) > 0 ->
    lists:member(element(1, Message),
        [gun_up, gun_down, gun_error, gun_response, gun_data, gun_inform,
            gun_trailers, gun_push, gun_upgrade, gun_ws]);
is_gun_message(_) ->
    false.
