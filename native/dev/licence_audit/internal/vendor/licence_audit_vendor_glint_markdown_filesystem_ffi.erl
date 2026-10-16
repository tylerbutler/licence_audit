% Vendored from vendor/glint_markdown/src/glint_markdown_filesystem_ffi.erl at 9c66ec3a62e43c639b06c3dfa582f223fc2fef14.
% Modified for licence_audit vendoring. Run just vendor-sync to update.
-module(licence_audit_vendor_glint_markdown_filesystem_ffi).
-export([canonical_path/1]).
-include_lib("kernel/include/file.hrl").

-type path_result() :: {ok, binary()} | {error, binary()}.

-spec canonical_path(binary()) -> path_result().
canonical_path(<<>>) ->
    {error, <<"empty path">>};
canonical_path(Path) when is_binary(Path) ->
    case binary:match(Path, <<0>>) of
        nomatch ->
            %% filename:absname retains ".."; resolve links before consuming it.
            case file:get_cwd() of
                {ok, Directory} ->
                    resolve_path(filename:absname(unicode:characters_to_list(Path), Directory), [], 0);
                {error, Reason} ->
                    filesystem_error("get current directory", Path, Reason)
            end;
        _ ->
            {error, <<"NUL in path">>}
    end.

-spec resolve_path(file:filename(), [file:filename()], non_neg_integer()) -> path_result().
resolve_path(Path, Remaining, Followed) ->
    [Root | Components] = filename:split(Path),
    resolve_components(Root, Components ++ Remaining, Followed).

-spec resolve_components(file:filename(), [file:filename()], non_neg_integer()) -> path_result().
resolve_components(Current, [], _Followed) ->
    utf8_path(Current);
resolve_components(Current, ["." | Remaining], Followed) ->
    resolve_components(Current, Remaining, Followed);
resolve_components(Current, [".." | Remaining], Followed) ->
    resolve_components(filename:dirname(Current), Remaining, Followed);
resolve_components(Current, [Component | Remaining], Followed) ->
    Candidate = filename:join(Current, Component),
    case file:read_link_info(Candidate) of
        {ok, #file_info{type = symlink}} when Followed >= 40 ->
            {error, <<"too many symbolic links">>};
        {ok, #file_info{type = symlink}} ->
            case file:read_link_all(Candidate) of
                {ok, Target} ->
                    case utf8_path(Target) of
                        {ok, Utf8Target} ->
                            Absolute = filename:absname(unicode:characters_to_list(Utf8Target), Current),
                            resolve_path(Absolute, Remaining, Followed + 1);
                        {error, _} = Error ->
                            Error
                    end;
                {error, Reason} ->
                    filesystem_error("read symbolic link", Candidate, Reason)
            end;
        {ok, #file_info{type = directory}} ->
            resolve_components(Candidate, Remaining, Followed);
        {ok, _Information} when Remaining =:= [] ->
            utf8_path(Candidate);
        {ok, _Information} ->
            filesystem_error("resolve path component", Candidate, enotdir);
        {error, enoent} ->
            %% Missing suffixes are allowed so the typed caller can create
            %% parents. Still resolve any later existing prefix after "..".
            resolve_components(Candidate, Remaining, Followed);
        {error, Reason} ->
            filesystem_error("inspect path component", Candidate, Reason)
    end.

-spec utf8_path(file:filename_all()) -> path_result().
utf8_path(Path) ->
    case unicode:characters_to_binary(Path) of
        Binary when is_binary(Binary) ->
            {ok, Binary};
        {error, _Converted, _Rest} ->
            {error, <<"filesystem path is not UTF-8">>};
        {incomplete, _Converted, _Rest} ->
            {error, <<"filesystem path is not UTF-8">>}
    end.

-spec filesystem_error(string(), file:filename_all(), atom()) -> path_result().
filesystem_error(Operation, Path, Reason) ->
    {error, unicode:characters_to_binary(
        io_lib:format("~ts ~tp: ~ts (~p)", [Operation, Path, file:format_error(Reason), Reason])
    )}.
