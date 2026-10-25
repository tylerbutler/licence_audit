-module(runtime_ffi).
-export([start/0]).

start() ->
    case configure_logger() of
        ok -> start_application();
        {error, Reason} -> startup_error(logger, Reason)
    end.

configure_logger() ->
    case logger:get_handler_config(default) of
        {ok, #{module := logger_std_h, config := #{type := standard_io} = Options} = Config} ->
            ok = logger:remove_handler(default),
            logger:add_handler(default, logger_std_h,
                Config#{config := Options#{type := standard_error}});
        {ok, _} -> ok;
        {error, {not_found, default}} -> ok
    end.

start_application() ->
    %% Queso calls main directly, without starting the OTP application graph.
    case application:ensure_all_started(licence_audit) of
        {ok, _Started} -> {ok, nil};
        {error, {App, Reason}} -> startup_error(App, Reason)
    end.

startup_error(App, Reason) ->
    Message = unicode:characters_to_binary(io_lib:format("~p: ~p", [App, Reason])),
    {error, {runtime_startup, Message}}.
