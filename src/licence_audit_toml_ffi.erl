%% @doc FFI bridge for the Rust `licence_audit_toml` port program.
%%
%% Exposes two functions:
%%
%% * `priv_dir/0' returns the binary path of the application's `priv/'
%%   directory (or the raw atom error from `code:priv_dir/1' rendered as a
%%   binary).
%% * `run_port/2' spawns the executable at `BinaryPath', writes
%%   `JsonRequest' to its stdin, collects all stdout until the port closes,
%%   and returns `{ok, Output}' or `{error, Reason}'.
-module(licence_audit_toml_ffi).
-export([priv_dir/0, run_port/2, binary_name/0]).

priv_dir() ->
    Binary = binary_to_list(binary_name()),
    Candidates = candidate_priv_dirs(),
    case first_dir_with_binary(Candidates, Binary) of
        {ok, Dir} -> list_to_binary(Dir);
        none ->
            case Candidates of
                [First | _] -> list_to_binary(First);
                [] -> <<"priv">>
            end
    end.

%% Ordered list of directories where the Rust port binary may live.
%% 1. The OTP application's `priv/' directory (works during `gleam run' /
%%    `gleam test', when the app is loaded from `build/').
%% 2. The directory containing the running escript itself (shipped layout:
%%    the Rust binary sits directly next to `./licence_audit').
%% 3. `priv/' next to the running escript (legacy shipped layout).
%% 4. The current working directory (so users can drop the binary next to
%%    the escript they're invoking via PATH).
%% 5. `priv/' under the current working directory (last-ditch fallback).
candidate_priv_dirs() ->
    FromCode =
        case code:priv_dir(licence_audit) of
            {error, _} -> [];
            P when is_list(P) -> [P];
            P when is_binary(P) -> [binary_to_list(P)]
        end,
    {FromScriptDir, FromScriptPriv} =
        try
            ScriptDir = filename:dirname(escript:script_name()),
            {[ScriptDir], [filename:join(ScriptDir, "priv")]}
        catch
            _:_ -> {[], []}
        end,
    {FromCwdDir, FromCwdPriv} =
        case file:get_cwd() of
            {ok, Cwd} -> {[Cwd], [filename:join(Cwd, "priv")]};
            _ -> {[], []}
        end,
    %% Deduplicate while preserving order.
    dedup(FromCode ++ FromScriptDir ++ FromScriptPriv ++ FromCwdDir ++ FromCwdPriv).

dedup(List) -> dedup(List, [], []).
dedup([], _Seen, Acc) -> lists:reverse(Acc);
dedup([H | T], Seen, Acc) ->
    case lists:member(H, Seen) of
        true -> dedup(T, Seen, Acc);
        false -> dedup(T, [H | Seen], [H | Acc])
    end.

first_dir_with_binary([], _Binary) -> none;
first_dir_with_binary([Dir | Rest], Binary) ->
    case filelib:is_regular(filename:join(Dir, Binary)) of
        true -> {ok, Dir};
        false -> first_dir_with_binary(Rest, Binary)
    end.

binary_name() ->
    case os:type() of
        {win32, _} -> <<"licence_audit_toml.exe">>;
        _ -> <<"licence_audit_toml">>
    end.

run_port(BinaryPath, JsonRequest) when is_binary(BinaryPath), is_binary(JsonRequest) ->
    Path = binary_to_list(BinaryPath),
    case filelib:is_regular(Path) of
        false ->
            {error, list_to_binary("binary not found: " ++ Path)};
        true ->
            try
                Port = erlang:open_port(
                    {spawn_executable, Path},
                    [binary, exit_status, use_stdio, stderr_to_stdout, {args, []}]
                ),
                Line = <<JsonRequest/binary, "\n">>,
                true = erlang:port_command(Port, Line),
                collect(Port, <<>>)
            catch
                _:Reason ->
                    {error, list_to_binary(io_lib:format("~p", [Reason]))}
            end
    end.

collect(Port, Acc) ->
    receive
        {Port, {data, Bin}} ->
            collect(Port, <<Acc/binary, Bin/binary>>);
        {Port, {exit_status, 0}} ->
            {ok, Acc};
        {Port, {exit_status, N}} ->
            {error, list_to_binary(
                "port exited with status " ++ integer_to_list(N) ++ ": " ++ binary_to_list(Acc)
            )}
    after 10000 ->
        catch erlang:port_close(Port),
        {error, <<"port timed out">>}
    end.
