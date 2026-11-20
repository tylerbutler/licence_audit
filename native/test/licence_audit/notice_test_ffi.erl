-module(notice_test_ffi).
-export([with_unreadable_file/2, with_unreadable_directory/2,
         assert_native_symlink/1, windows_symlink_type/0]).
-include_lib("kernel/include/file.hrl").

assert_native_symlink(Path) ->
    {ok, #file_info{type = symlink}} = file:read_link_info(Path),
    nil.

windows_symlink_type() ->
    notice_ffi:link_type(<<"unused">>, fun(_) ->
        {ok, #file_info{type = symlink, mode = 8#100644}}
    end).

%% File-content fixtures cannot simulate access denial. Change actual Unix
%% permissions and restore them with try/after even if a Gleam assertion raises;
%% privileged users and Windows cannot exercise the same permission check.
with_unreadable_file(Path, Check) ->
    with_unreadable(Path, 8#200, fun file:read_file/1, Check).

with_unreadable_directory(Path, Check) ->
    with_unreadable(Path, 0, fun file:list_dir/1, Check).

with_unreadable(Path, Mode, Read, Check) ->
    case os:type() of
        {win32, _} -> none;
        {unix, _} ->
            {ok, Original} = file:read_file_info(Path),
            ok = file:write_file_info(Path, #file_info{mode = Mode}),
            try
                case Read(Path) of
                    {error, eacces} -> {some, Check()};
                    {ok, _} -> none
                end
            after
                ok = file:write_file_info(Path, #file_info{mode = Original#file_info.mode})
            end
    end.
