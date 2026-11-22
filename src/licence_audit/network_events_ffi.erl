-module(network_events_ffi).
-behaviour(gun_event).
-export([init/2, domain_lookup_start/2, domain_lookup_end/2,
    connect_start/2, connect_end/2, tls_handshake_start/2, tls_handshake_end/2,
    request_start/2, request_headers/2, request_end/2,
    push_promise_start/2, push_promise_end/2, response_start/2,
    response_inform/2, response_headers/2, response_trailers/2, response_end/2,
    ws_upgrade/2, ws_recv_frame_start/2, ws_recv_frame_header/2,
    ws_recv_frame_end/2, ws_send_frame_start/2, ws_send_frame_end/2,
    protocol_changed/2, origin_changed/2, cancel/2, disconnect/2, terminate/2]).
-export([controlling_process/2, connect/4, send/2, recv/3, close/1,
    shutdown/2, setopts/2, getopts/2, getstat/2, peername/1, sockname/1, port/1]).

init(_, State) ->
    erlang:put({?MODULE, owner}, State),
    notify({starting, self()}, State),
    State.

connect_end(Event, State) ->
    case maps:find(socket, Event) of
        {ok, Socket} -> notify({socket, self(), Socket}, State);
        error -> ok
    end,
    State.

tls_handshake_start(_, State) ->
    notify({tls_starting, self()}, State),
    State.

tls_handshake_end(Event, State) ->
    notify({tls_finished, self()}, State),
    gun_default_event_h:tls_handshake_end(Event, State).

%% Register the complete TLS scope before handing it the TCP socket.
controlling_process(Socket, Receiver) ->
    case erlang:get({?MODULE, owner}) of
        undefined -> ok;
        State ->
            notify({tls_ready, self(), network_ffi:tls_scope(Receiver)}, State)
    end,
    gen_tcp:controlling_process(Socket, Receiver).

connect(Host, Port, Options, Timeout) -> gen_tcp:connect(Host, Port, Options, Timeout).
send(Socket, Data) -> gen_tcp:send(Socket, Data).
recv(Socket, Length, Timeout) -> gen_tcp:recv(Socket, Length, Timeout).
close(Socket) -> gen_tcp:close(Socket).
shutdown(Socket, How) -> gen_tcp:shutdown(Socket, How).
setopts(Socket, Options) -> inet:setopts(Socket, Options).
getopts(Socket, Options) -> inet:getopts(Socket, Options).
getstat(Socket, Options) -> inet:getstat(Socket, Options).
peername(Socket) -> inet:peername(Socket).
sockname(Socket) -> inet:sockname(Socket).
port(Socket) -> inet:port(Socket).

notify(Event, #{guardian := Guardian, helper := Helper, reference := Reference}) ->
    Monitor = erlang:monitor(process, Guardian),
    Guardian ! {transport_event, self(), Helper, Reference, Event},
    try
        receive
            {transport_event_ack, Reference, continue} -> ok;
            {transport_event_ack, Reference, cancel} ->
                exit({shutdown, network_open_cancelled});
            {'DOWN', Monitor, process, Guardian, Reason} ->
                exit({shutdown, {http_owner_stopped, Reason}})
        end
    after erlang:demonitor(Monitor, [flush])
    end.

domain_lookup_start(Event, State) -> gun_default_event_h:domain_lookup_start(Event, State).
domain_lookup_end(Event, State) -> gun_default_event_h:domain_lookup_end(Event, State).
connect_start(Event, State) -> gun_default_event_h:connect_start(Event, State).
request_start(Event, State) -> gun_default_event_h:request_start(Event, State).
request_headers(Event, State) -> gun_default_event_h:request_headers(Event, State).
request_end(Event, State) -> gun_default_event_h:request_end(Event, State).
push_promise_start(Event, State) -> gun_default_event_h:push_promise_start(Event, State).
push_promise_end(Event, State) -> gun_default_event_h:push_promise_end(Event, State).
response_start(Event, State) -> gun_default_event_h:response_start(Event, State).
response_inform(Event, State) -> gun_default_event_h:response_inform(Event, State).
response_headers(Event, State) -> gun_default_event_h:response_headers(Event, State).
response_trailers(Event, State) -> gun_default_event_h:response_trailers(Event, State).
response_end(Event, State) -> gun_default_event_h:response_end(Event, State).
ws_upgrade(Event, State) -> gun_default_event_h:ws_upgrade(Event, State).
ws_recv_frame_start(Event, State) -> gun_default_event_h:ws_recv_frame_start(Event, State).
ws_recv_frame_header(Event, State) -> gun_default_event_h:ws_recv_frame_header(Event, State).
ws_recv_frame_end(Event, State) -> gun_default_event_h:ws_recv_frame_end(Event, State).
ws_send_frame_start(Event, State) -> gun_default_event_h:ws_send_frame_start(Event, State).
ws_send_frame_end(Event, State) -> gun_default_event_h:ws_send_frame_end(Event, State).
protocol_changed(Event, State) -> gun_default_event_h:protocol_changed(Event, State).
origin_changed(Event, State) -> gun_default_event_h:origin_changed(Event, State).
cancel(Event, State) -> gun_default_event_h:cancel(Event, State).
disconnect(Event, State) -> gun_default_event_h:disconnect(Event, State).
terminate(Event, State) -> gun_default_event_h:terminate(Event, State).
