-module(policy_file_ffi).
-export([write/2, write/3]).
-include_lib("kernel/include/file.hrl").

write(Path, Contents) ->
    case write(Path, Contents, fun file:write/2) of
        ok -> {ok, nil};
        {error, _Reason} -> {error, nil}
    end.

%% Keep the write operation injectable to test an interruption after partial I/O.
write(Path, Contents, Write) ->
    case destination(Path, 40) of
        {ok, Target, Metadata} ->
            prepare(Target, Contents, Metadata, Write);
        Error -> Error
    end.

destination(_Path, 0) ->
    {error, eloop};
destination(Path, Remaining) ->
    case file:read_link_info(Path) of
        {ok, #file_info{type = symlink}} ->
            case file:read_link(Path) of
                {ok, Link} ->
                    destination(filename:join(filename:dirname(Path), Link), Remaining - 1);
                Error -> Error
            end;
        {ok, #file_info{type = regular, mode = Mode, uid = User, gid = Group}} ->
            {ok, Path, #file_info{mode = Mode, uid = User, gid = Group}};
        {error, enoent} ->
            {ok, Path, new};
        {ok, _Info} -> {error, einval};
        Error -> Error
    end.

prepare(Path, Contents, Metadata, Write) ->
    Suffix = integer_to_binary(erlang:unique_integer([positive, monotonic])),
    Temporary = <<Path/binary, ".licence-audit-", Suffix/binary, ".tmp">>,
    case file:open(Temporary, [write, binary, exclusive, raw]) of
        {ok, File} ->
            try
                case prepare_file(File, Temporary, Contents, Metadata, Write) of
                    ok ->
                        case file:close(File) of
                            ok -> file:rename(Temporary, Path);
                            Error -> Error
                        end;
                    Error -> Error
                end
            after
                file:close(File),
                file:delete(Temporary)
            end;
        {error, eexist} -> prepare(Path, Contents, Metadata, Write);
        Error -> Error
    end.

prepare_file(File, Path, Contents, Metadata, Write) ->
    case file:read_file_info(File) of
        {ok, #file_info{mode = DefaultMode}} ->
            case file:change_mode(Path, 8#600) of
                ok ->
                    case Write(File, Contents) of
                        ok ->
                            case file:sync(File) of
                                ok -> preserve_metadata(Path, Metadata, DefaultMode);
                                Error -> Error
                            end;
                        Error -> Error
                    end;
                Error -> Error
            end;
        Error -> Error
    end.

preserve_metadata(Path, new, DefaultMode) ->
    file:change_mode(Path, DefaultMode);
preserve_metadata(Path, Metadata, _DefaultMode) ->
    file:write_file_info(Path, Metadata).
