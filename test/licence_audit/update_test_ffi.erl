-module(update_test_ffi).
-export([partial_write/2, set_private_mode/1, metadata/1, temporary_files/1, make_link/2]).
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
