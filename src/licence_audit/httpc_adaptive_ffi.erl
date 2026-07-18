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

normalise_error(timeout) ->
    response_timeout;
normalise_error(Error = {failed_connect, Options}) ->
    case find_connect_error(Options) of
        {ok, Reason} -> {failed_to_connect, describe_connect_error(Reason)};
        error -> erlang:error({unexpected_httpc_adaptive_error, Error})
    end;
normalise_error(Error) ->
    erlang:error({unexpected_httpc_adaptive_error, Error}).

find_connect_error(Options) ->
    case lists:keyfind(inet, 1, Options) of
        {inet, _, Reason} -> {ok, Reason};
        false ->
            case lists:keyfind(inet6, 1, Options) of
                {inet6, _, Reason} -> {ok, Reason};
                false -> error
            end
    end.

describe_connect_error(Code) when is_atom(Code) ->
    erlang:atom_to_binary(Code);
describe_connect_error({tls_alert, {Code, Detail}}) ->
    iolist_to_binary([
        "TLS ",
        erlang:atom_to_binary(Code),
        " (",
        unicode:characters_to_binary(Detail),
        ")"
    ]);
describe_connect_error(Error) ->
    erlang:error({unexpected_httpc_adaptive_connect_error, Error}).
