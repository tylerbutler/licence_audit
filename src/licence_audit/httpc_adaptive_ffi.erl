-module(httpc_adaptive_ffi).
-export([
    fallback_to_ipv4/1,
    ipv6_host_verified/1,
    normalise_error/1,
    request/4,
    remember_ipv6_host/1,
    select_ipv4/0,
    selected_family/0,
    take_warning/0,
    reset_retry_state/0, host_failures/1, record_host_failure/1, clear_host_failures/1,
    now_ms/0, monotonic_ms/0, sleep/1, http_date_ms/1,
    request_without_retry/10, prepare_tls/2
]).

-define(FAILURES_KEY, {?MODULE, host_failures}).

reset_retry_state() ->
    erlang:erase(?FAILURES_KEY),
    network_ffi:reset_retry_state().

host_failures(Host) -> network_ffi:host_failures(Host).

record_host_failure(Host) -> network_ffi:record_host_failure(Host).

clear_host_failures(Host) -> network_ffi:clear_host_failures(Host).

now_ms() -> erlang:system_time(millisecond).
monotonic_ms() -> erlang:monotonic_time(millisecond).
sleep(Milliseconds) -> timer:sleep(Milliseconds), nil.

http_date_ms(Value) ->
    try httpd_util:convert_request_date(binary_to_list(Value)) of
        {Date, Time} ->
            Seconds = calendar:datetime_to_gregorian_seconds({Date, Time})
                - calendar:datetime_to_gregorian_seconds({{1970, 1, 1}, {0, 0, 0}}),
            {ok, Seconds * 1000};
        bad_date -> {error, nil}
    catch error:_ -> {error, nil}
    end.

%% httpc on OTP 28 auto-retries 503 and leaves retry timers after cancellation.
%% Gun is already installed for archives. One owned connection, no reconnects,
%% one absolute timeout, and a raw response let Gleam enforce the retry policy.
request_without_retry(Host, Port, Secure, Path, Method, Headers, Body, Timeout, Family, ReadErrorBody) ->
    try
        Deadline = monotonic_ms() + Timeout,
        Transport = case Secure of true -> tls; false -> tcp end,
        Inet = case Family of ipv4 -> inet; ipv6 -> inet6 end,
        case network_ffi:open(fun() ->
            case tls_options(Secure, Host) of
                {error, _} = Error -> Error;
                {ok, TlsOptions} ->
                    Options = #{
                        transport => Transport, protocols => [http], retry => 0,
                        tcp_opts => [Inet],
                        domain_lookup_timeout => Timeout,
                        connect_timeout => Timeout,
                        tls_handshake_timeout => Timeout,
                        tls_opts => TlsOptions
                    },
                    gun:open(binary_to_list(Host), Port, network_ffi:gun_options(Options))
            end
        end, Deadline) of
            {ok, Connection} ->
                Monitor = erlang:monitor(process, Connection),
                try
                    case await_deadline(
                        fun(Wait) -> gun:await_up(Connection, Wait, Monitor) end,
                        Deadline
                    ) of
                        {ok, http} ->
                            Stream = gun:request(Connection, Method, Path, Headers, Body),
                            await_headers(Connection, Stream, Deadline, Monitor, ReadErrorBody);
                        {error, Reason} -> {error, raw_error(Reason, Family)}
                    end
                after
                    %% terminate_child waits for the sender to stop before flush.
                    try
                        close_connection(Connection)
                    after
                        erlang:demonitor(Monitor, [flush]),
                        gun:flush(Connection)
                    end
                end;
            {error, Reason = {httpc_exception, _, _}} ->
                {error, normalise_error(Reason)};
            {error, Reason} -> {error, raw_error(Reason, Family)}
        end
    catch
        Class:Exception ->
            {error, normalise_error({httpc_exception, Class, Exception})}
    end.

tls_options(false, _) -> {ok, []};
tls_options(true, Host) -> prepare_tls(Host, fun public_key:cacerts_get/0).

prepare_tls(Host, LoadCacerts) ->
    %% Preparation has not opened resources; keep CA-load failures typed.
    try
        {ok, [
            {verify, verify_peer},
            {cacerts, LoadCacerts()},
            {server_name_indication, binary_to_list(Host)},
            {customize_hostname_check,
                [{match_fun, public_key:pkix_verify_hostname_match_fun(https)}]}
        ]}
    catch
        error:Reason -> {error, {httpc_exception, error, Reason}}
    end.

await_deadline(Await, Deadline) ->
    Remaining = Deadline - monotonic_ms(),
    case Remaining =< 0 of
        true -> {error, timeout};
        false ->
            Event = Await(Remaining),
            case monotonic_ms() >= Deadline of
                true -> {error, timeout};
                false -> Event
            end
    end.

close_connection(Connection) ->
    network_ffi:before_close(Connection),
    Monitor = erlang:monitor(process, Connection),
    try
        case gun:close(Connection) of
            ok -> ok;
            {error, not_found} -> ok;
            {error, Reason} -> erlang:error({connection_teardown_failed, Reason})
        end,
        receive {'DOWN', Monitor, process, Connection, _} -> ok
        after 1000 -> erlang:error(connection_termination_timeout)
        end
    after erlang:demonitor(Monitor, [flush])
    end.

await_headers(Connection, Stream, Deadline, Monitor, ReadErrorBody) ->
    case await_deadline(
        fun(Wait) -> gun:await(Connection, Stream, Wait, Monitor) end, Deadline
    ) of
        {inform, _, _} -> await_headers(Connection, Stream, Deadline, Monitor, ReadErrorBody);
        {response, fin, Status, Headers} ->
            {ok, {response, Status, Headers, <<>>}};
        %% Metadata decoders use error statuses, not their bodies. Surface rate
        %% deadlines now, rather than hiding them behind a stalled error body.
        {response, nofin, Status, Headers}
            when not ReadErrorBody, Status < 200;
                not ReadErrorBody, Status >= 300 ->
            {ok, {response, Status, Headers, <<>>}};
        {response, nofin, Status, Headers} ->
            await_body(Connection, Stream, Deadline, Monitor, Status, Headers, []);
        {error, Reason} -> {error, raw_error(Reason, none)};
        Other -> {error, {request_failed, describe_error({unexpected_response, Other})}}
    end.

await_body(Connection, Stream, Deadline, Monitor, Status, Headers, Chunks) ->
    case await_deadline(
        fun(Wait) -> gun:await(Connection, Stream, Wait, Monitor) end, Deadline
    ) of
        {data, nofin, Data} ->
            await_body(Connection, Stream, Deadline, Monitor, Status, Headers, [Data | Chunks]);
        {data, fin, Data} ->
            complete_response(Status, Headers, [Data | Chunks], Deadline);
        {trailers, _} ->
            complete_response(Status, Headers, Chunks, Deadline);
        {error, Reason} -> {error, raw_error(Reason, none)};
        Other -> {error, {request_failed, describe_error({unexpected_body, Other})}}
    end.

complete_response(Status, Headers, Chunks, Deadline) ->
    Body = iolist_to_binary(lists:reverse(Chunks)),
    case monotonic_ms() >= Deadline of
        true -> {error, response_timeout};
        false -> {ok, {response, Status, Headers, Body}}
    end.

raw_error({down, {shutdown, Reason}}, Family) -> raw_error(Reason, Family);
raw_error({shutdown, Reason}, Family) -> raw_error(Reason, Family);
raw_error({down, Reason}, Family) -> raw_error(Reason, Family);
raw_error({connection_error, Reason}, Family) -> raw_error(Reason, Family);
raw_error({stream_error, Reason}, Family) -> raw_error(Reason, Family);
raw_error({closed, Reason}, Family) -> raw_error(Reason, Family);
raw_error({error, Reason}, Family) -> raw_error(Reason, Family);
raw_error(nxdomain, ipv6) -> no_ipv6_address;
raw_error(Reason, Family) ->
    Prefix = case Family of ipv4 -> <<"IPv4: ">>; ipv6 -> <<"IPv6: ">>; none -> <<>> end,
    case Reason of
        closed -> {connection_closed, <<"closed">>};
        econnreset -> {connection_closed, <<"econnreset">>};
        timeout -> response_timeout;
        etimedout -> response_timeout;
        _ -> connect_failure(Reason, <<Prefix/binary, (describe_connect_error(Reason))/binary>>)
    end.

%% OTP can raise before returning a request error, for example loading CA roots.
request(Method, Request, HttpOptions, Options) ->
    try httpc:request(Method, Request, HttpOptions, Options)
    catch
        Class:Reason -> {error, {httpc_exception, Class, Reason}}
    end.

%% gleam_httpc's inet6fb4 can exhaust the request timeout before IPv4 succeeds.
%% Gleam owns the bounded probe; workers share the command's fallback state.
selected_family() ->
    case network_ffi:state_get(family, undefined) of
        ipv4 -> use_ipv4;
        ipv6 -> use_ipv6;
        _ -> unknown
    end.

ipv6_host_verified(Host) ->
    lists:member(Host, ipv6_hosts()).

remember_ipv6_host(Host) ->
    network_ffi:state_put(family, ipv6),
    network_ffi:state_put(ipv6_hosts, lists:usort([Host | ipv6_hosts()])),
    nil.

fallback_to_ipv4(Warning) ->
    select_ipv4(),
    network_ffi:state_put(warning, Warning),
    nil.

select_ipv4() ->
    network_ffi:state_put(family, ipv4),
    nil.

take_warning() ->
    case network_ffi:state_get(warning, undefined) of
        undefined -> none;
        Warning ->
            network_ffi:state_put(warning, undefined),
            {some, Warning}
    end.

ipv6_hosts() ->
    case network_ffi:state_get(ipv6_hosts, undefined) of
        Hosts when is_list(Hosts) -> Hosts;
        _ -> []
    end.

%% OTP failure tuples have several shapes; the Gleam boundary exposes one typed
%% error while retaining DNS/TCP/TLS and address-family details.
normalise_error(timeout) ->
    response_timeout;
normalise_error(etimedout) ->
    response_timeout;
normalise_error(socket_closed_remotely) ->
    {connection_closed, <<"socket_closed_remotely">>};
normalise_error(shutdown) ->
    {connection_closed, <<"shutdown">>};
normalise_error(econnreset) ->
    {connection_closed, <<"econnreset">>};
normalise_error({tcp_error, _Socket, Reason}) ->
    socket_error(Reason);
normalise_error({ssl_error, _Socket, Reason}) ->
    socket_error(Reason);
normalise_error({stream_error, Reason}) ->
    raw_error(Reason, none);
normalise_error(invalid_request) ->
    {invalid_request, <<"invalid_request">>};
normalise_error({httpc_exception, Class, Reason}) ->
    {request_failed, <<"Erlang ", (atom_to_binary(Class))/binary, ": ",
        (describe_error(Reason))/binary>>};
normalise_error(Error = {failed_connect, Options}) ->
    case lists:keyfind(inet, 1, Options) of
        {inet, _, Reason} ->
            connect_failure(Reason, <<"IPv4: ", (describe_connect_error(Reason))/binary>>);
        false ->
            case lists:keyfind(inet6, 1, Options) of
                {inet6, _, nxdomain} -> no_ipv6_address;
                {inet6, _, Reason} ->
                    connect_failure(Reason, <<"IPv6: ", (describe_connect_error(Reason))/binary>>);
                false -> {failed_to_connect, describe_error(Error)}
            end
    end;
normalise_error(Error) ->
    {request_failed, describe_error(Error)}.

socket_error(econnreset) -> {connection_closed, <<"econnreset">>};
socket_error(closed) -> {connection_closed, <<"closed">>};
socket_error(timeout) -> response_timeout;
socket_error(etimedout) -> response_timeout;
socket_error(Reason = {tls_alert, _}) -> {tls_failure, describe_connect_error(Reason)};
socket_error(Reason) -> {request_failed, describe_error(Reason)}.

connect_failure(Reason, Detail) ->
    case Reason of
        timeout -> {connection_failure, connection_timed_out, Detail};
        etimedout -> {connection_failure, connection_timed_out, Detail};
        nxdomain -> {connection_failure, dns_failure, Detail};
        econnrefused -> {connection_failure, connection_refused, Detail};
        enetunreach -> {connection_failure, network_unreachable, Detail};
        ehostunreach -> {connection_failure, host_unreachable, Detail};
        {tls_alert, _} -> {tls_failure, Detail};
        _ -> {failed_to_connect, Detail}
    end.

describe_error(Error) ->
    unicode:characters_to_binary(io_lib:format("~tp", [Error])).

describe_connect_error(nxdomain) ->
    <<"DNS lookup failed (nxdomain)">>;
describe_connect_error(econnrefused) ->
    <<"TCP connection refused (econnrefused)">>;
describe_connect_error(enetunreach) ->
    <<"network unreachable (enetunreach)">>;
describe_connect_error(ehostunreach) ->
    <<"host unreachable (ehostunreach)">>;
describe_connect_error(Code) when Code =:= timeout; Code =:= etimedout ->
    <<"connection setup timed out (", (atom_to_binary(Code))/binary,
      "; HTTP client did not report the DNS/TCP/TLS stage)">>;
describe_connect_error(Code) when is_atom(Code) ->
    <<"connection error (", (atom_to_binary(Code))/binary, ")">>;
describe_connect_error({tls_alert, {Code, Detail}}) ->
    iolist_to_binary([
        "TLS handshake failed: ",
        erlang:atom_to_binary(Code),
        " (",
        unicode:characters_to_binary(Detail),
        ")"
    ]);
describe_connect_error(Error) ->
    describe_error(Error).
