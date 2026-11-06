-module(httpc_adaptive_ffi).
-export([
    fallback_to_ipv4/1,
    ipv6_host_verified/1,
    normalise_error/1,
    remember_ipv6_host/1,
    selected_family/0,
    take_warning/0
]).

-define(FAMILY_KEY, {?MODULE, family}).
-define(IPV6_HOSTS_KEY, {?MODULE, ipv6_hosts}).
-define(WARNING_KEY, {?MODULE, warning}).

%% gleam_httpc's inet6fb4 can exhaust the request timeout before IPv4 succeeds.
%% Gleam owns the bounded probe; OTP process-local state keeps its fallback for
%% this command without global state or threading transport state through callers.
selected_family() ->
    case erlang:get(?FAMILY_KEY) of
        ipv4 -> use_ipv4;
        ipv6 -> use_ipv6;
        _ -> unknown
    end.

ipv6_host_verified(Host) ->
    lists:member(Host, ipv6_hosts()).

remember_ipv6_host(Host) ->
    erlang:put(?FAMILY_KEY, ipv6),
    erlang:put(?IPV6_HOSTS_KEY, lists:usort([Host | ipv6_hosts()])),
    nil.

fallback_to_ipv4(Warning) ->
    erlang:put(?FAMILY_KEY, ipv4),
    erlang:put(?WARNING_KEY, Warning),
    nil.

take_warning() ->
    case erlang:erase(?WARNING_KEY) of
        undefined -> none;
        Warning -> {some, Warning}
    end.

ipv6_hosts() ->
    case erlang:get(?IPV6_HOSTS_KEY) of
        Hosts when is_list(Hosts) -> Hosts;
        _ -> []
    end.

%% OTP failure tuples have several shapes; the Gleam boundary exposes one typed
%% error while retaining DNS/TCP/TLS and address-family details.
normalise_error(timeout) ->
    response_timeout;
normalise_error(Error = {failed_connect, Options}) ->
    case lists:keyfind(inet, 1, Options) of
        {inet, _, Reason} ->
            {failed_to_connect, <<"IPv4: ", (describe_connect_error(Reason))/binary>>};
        false ->
            case lists:keyfind(inet6, 1, Options) of
                {inet6, _, Reason} ->
                    {failed_to_connect, <<"IPv6: ", (describe_connect_error(Reason))/binary>>};
                false -> {failed_to_connect, describe_error(Error)}
            end
    end;
normalise_error(Error) ->
    {request_failed, describe_error(Error)}.

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
