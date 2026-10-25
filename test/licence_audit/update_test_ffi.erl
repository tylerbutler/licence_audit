-module(update_test_ffi).
-export([partial_write/2, set_private_mode/1, metadata/1, temporary_files/1, make_link/2,
    windows_worker/0]).
-include_lib("kernel/include/file.hrl").

partial_write(Path, Interrupt) ->
    Write = fun(File, _Contents) ->
        ok = file:write(File, <<"partial replacement">>),
        case Interrupt of
            true -> exit(interrupted);
            false -> {error, enospc}
        end
    end,
    Result = catch policy_file_ffi:write(Path, <<"complete replacement">>, Write),
    case {Interrupt, Result} of
        {true, {'EXIT', interrupted}} -> {ok, nil};
        {false, {error, enospc}} -> {ok, nil};
        _ -> {error, nil}
    end.

set_private_mode(Path) ->
    ok = file:change_mode(Path, 8#640),
    nil.

metadata(Path) ->
    {ok, #file_info{mode = Mode, uid = User, gid = Group}} = file:read_file_info(Path),
    {Mode, User, Group}.

temporary_files(Path) ->
    [unicode:characters_to_binary(Name) || Name <- filelib:wildcard(
        binary_to_list(Path) ++ ".licence-audit-*.tmp"
    )].

make_link(Target, Link) ->
    case file:make_symlink(Target, Link) of
        ok -> {ok, nil};
        {error, _Reason} -> {error, nil}
    end.

windows_worker() ->
    Path = unicode:characters_to_binary(os:getenv("POLICY_TEST_PATH")),
    case os:getenv("POLICY_TEST_MODE") of
        "update" ->
            Fetcher = fun(_) ->
                {ok, licence_audit@hex:licences_only([<<"MIT">>])}
            end,
            Picker = fun(_, _, _, _) ->
                {ok, {selection, lists:duplicate(1000, <<"MIT-long-policy-entry">>), []}}
            end,
            {{update_result, 0, _}, _} = licence_audit@update:run_with_picker(
                <<"test/fixtures/transitive_manifest.toml">>, <<".">>,
                {some, Path}, true, true, none, Fetcher, Picker,
                licence_audit@progress:capturing(verbose, <<"update">>)
            );
        "failure" ->
            {error, nil} = policy_file_ffi:write(Path, <<"replacement">>);
        "cleanup_failure" ->
            {error, {temporary_cleanup_failed, Directory, _}} = policy_file_ffi:write(
                Path, <<"replacement">>, fun file:write/2, fun(From, _) ->
                    ok = file:delete(From),
                    ok = file:make_dir(From),
                    {error, injected_replacement_failure}
                end
            ),
            ok = file:del_dir(Directory);
        "partial" ->
            owner_session(fun() ->
                policy_file_ffi:write(Path, <<"replacement">>, fun(File, _) ->
                    ok = file:write(File, binary:copy(<<"private!">>, 128)),
                    io:format("PARTIAL~n"),
                    receive continue -> ok end
                end)
            end);
        "timeout" ->
            {error, timeout} = policy_file_ffi:write(
                Path, <<"replacement">>, fun file:write/2, delayed_replace(3000)
            );
        "owner" ->
            owner_session(fun() ->
                policy_file_ffi:write(
                    Path, <<"replacement">>, fun file:write/2, delayed_replace(60000)
                )
            end);
        "loop" ->
            {ok, Original} = file:read_file(Path),
            Replacement = unicode:characters_to_binary(os:getenv("POLICY_TEST_CONTENTS")),
            lists:foreach(fun(_) ->
                windows_write(Path, Replacement),
                windows_write(Path, Original)
            end, lists:seq(1, 4))
    end,
    io:format("PASS~n"),
    halt().

windows_write(Path, Contents) ->
    case policy_file_ffi:write(Path, Contents, fun file:write/2) of
        ok -> io:format("REPLACED~n");
        {error, {windows_command, 1, _Output}} ->
            %% A concurrently open reader may cause a sharing violation.
            io:format("REPLACEMENT_FAILED~n");
        Error -> erlang:error(Error)
    end.

owner_session(Work) ->
    {Owner, Monitor} = spawn_monitor(Work),
    "kill-owner" = string:trim(io:get_line("")),
    exit(Owner, kill),
    receive {'DOWN', Monitor, process, Owner, killed} -> ok end,
    io:format("OWNER_DEAD~n"),
    "finish" = string:trim(io:get_line("")).

delayed_replace(Timeout) ->
    fun(From, To) ->
        policy_file_ffi:windows_command(From, To, [
            "[IO.File]::WriteAllText($from+'.helper',[string]$PID);",
            "$end=[DateTime]::UtcNow.AddSeconds(6);",
            "while([DateTime]::UtcNow -lt $end){",
            "[Console]::Out.WriteLine('waiting');Start-Sleep -Milliseconds 30};",
            "if($native.GetMethod('MoveFileExW').Invoke($null,@($from,$to,[uint32]9)))",
            "{exit 0}else{exit 1}"
        ], Timeout)
    end.
