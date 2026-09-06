-module(httpc_adaptive_test_ffi).
-export([reset/0]).

reset() ->
    erlang:erase({httpc_adaptive_ffi, family}),
    erlang:erase({httpc_adaptive_ffi, ipv6_hosts}),
    erlang:erase({httpc_adaptive_ffi, warning}),
    nil.
