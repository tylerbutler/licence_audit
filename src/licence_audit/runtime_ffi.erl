-module(runtime_ffi).
-export([start/0]).

start() ->
    %% Queso calls main directly, without starting the OTP application graph.
    case application:ensure_all_started(licence_audit) of
        {ok, _Started} -> {ok, nil};
        {error, {App, Reason}} ->
            Message = unicode:characters_to_binary(io_lib:format("~p: ~p", [App, Reason])),
            {error, {runtime_startup, Message}}
    end.
