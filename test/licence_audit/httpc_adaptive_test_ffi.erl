-module(httpc_adaptive_test_ffi).
-export([reset/0, with_http_response/2]).

reset() ->
    erlang:erase({httpc_adaptive_ffi, family}),
    erlang:erase({httpc_adaptive_ffi, ipv6_hosts}),
    erlang:erase({httpc_adaptive_ffi, warning}),
    nil.

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
