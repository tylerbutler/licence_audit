-module(notice_test_ffi).
-export([with_unreadable_file/2, with_unreadable_directory/2]).
-include_lib("kernel/include/file.hrl").

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
