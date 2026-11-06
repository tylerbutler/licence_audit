-module(runtime_ffi).
-export([start/0]).

%% Queso calls Gleam main without starting the OTP application graph. Core Gleam
%% APIs also do not locate escript NIF sidecars or route OTP logger output away
%% from stdout, which must remain a clean report/JSON stream during startup too.
start() ->
    case configure_logger() of
        ok ->
            case configure_sqlite_sidecar() of
                ok -> start_application();
                {error, Reason} -> startup_error(esqlite, Reason)
            end;
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

configure_sqlite_sidecar() ->
    case init:get_argument(escript) of
        {ok, _} ->
            Directory = filename:dirname(filename:absname(escript:script_name())),
            Default = filename:join([Directory, "sqlite_native", "esqlite", "ebin"]),
            Target = filename:join([Directory, "sqlite_native", escript_target(),
                "esqlite", "ebin"]),
            Ebin = case filelib:is_dir(Target) of true -> Target; false -> Default end,
            case filelib:is_dir(Ebin) of
                false -> ok;
                true ->
                    case code:add_patha(Ebin) of
                        true -> ok;
                        {error, _} = Error -> Error
                    end
            end;
        error -> ok
    end.

escript_target() ->
    Architecture = erlang:system_info(system_architecture),
    [Machine | _] = string:split(Architecture, "-", all),
    Cpu = case Machine of "arm64" -> "aarch64"; _ -> Machine end,
    case os:type() of
        {win32, _} -> "x86_64-windows";
        {unix, darwin} -> Cpu ++ "-macos";
        {unix, linux} ->
            Libc = case string:find(Architecture, "musl") of
                nomatch -> "glibc";
                _ -> "musl"
            end,
            Cpu ++ "-linux-" ++ Libc;
        _ -> "unsupported"
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
