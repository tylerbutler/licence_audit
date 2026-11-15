-module(source_archive_ffi).
-export([
    extract_tar/2,
    extract_tar_gz/2,
    extract_tar_selected/3,
    extract_tar_gz_selected/3,
    extract_root_file_tar_gz/3,
    prepare_tar/2
]).

-define(INFLATE_INPUT_BYTES, 16384).

%% Gleam core has no tar/gzip reader. OTP extracts in memory, avoiding disk paths
%% from untrusted archives; selected reads load only matching regular files and
%% share one inflated tar across inventory and extraction.
extract_tar(Data, Limit) when is_binary(Data) ->
    with_plain_tar(Data, Limit, fun(Tar) -> extract(Tar, []) end);
extract_tar(_Data, _Limit) ->
    {error, invalid_archive}.

extract_tar_gz(Data, Limit) when is_binary(Data) ->
    with_tar(Data, Limit, fun(Tar) -> extract(Tar, []) end);
extract_tar_gz(_Data, _Limit) ->
    {error, invalid_archive}.

extract_tar_selected(Data, Select, Limit) when is_binary(Data) ->
    with_plain_tar(Data, Limit, fun(Tar) -> extract_selected(Tar, [], Select) end);
extract_tar_selected(_Data, _Select, _Limit) ->
    {error, invalid_archive}.

extract_tar_gz_selected(Data, Select, Limit) when is_binary(Data) ->
    with_tar(Data, Limit, fun(Tar) -> extract_selected(Tar, [], Select) end);
extract_tar_gz_selected(_Data, _Select, _Limit) ->
    {error, invalid_archive}.

with_plain_tar(Data, Limit, Read) ->
    case checked_plain_tar(Data, Limit) of
        {ok, Tar} -> Read(Tar);
        Error -> Error
    end.

with_tar(Data, Limit, Read) ->
    case prepare_tar(Data, Limit) of
        {ok, Tar} -> Read(Tar);
        Error -> Error
    end.

%% safeInflate bounds each output allocation; inflateEnd checks the gzip trailer
%% even when safeInflate says it has finished consuming the supplied input.
prepare_tar(<<16#1f, 16#8b, _/binary>> = Data, Limit)
        when is_integer(Limit), Limit >= 0 ->
    Zlib = zlib:open(),
    try
        ok = zlib:inflateInit(Zlib, 31, reset),
        case inflate_input(Zlib, Data, Limit, 0, []) of
            {ok, Chunks} ->
                ok = zlib:inflateEnd(Zlib),
                {ok, iolist_to_binary(lists:reverse(Chunks))};
            Error -> Error
        end
    catch
        error:data_error -> {error, invalid_archive}
    after
        zlib:close(Zlib)
    end;
prepare_tar(Data, Limit) when is_binary(Data), is_integer(Limit), Limit >= 0 ->
    checked_plain_tar(Data, Limit);
prepare_tar(_Data, _Limit) ->
    {error, invalid_archive}.

checked_plain_tar(Data, Limit) when byte_size(Data) =< Limit ->
    {ok, Data};
checked_plain_tar(_Data, _Limit) ->
    {error, invalid_archive}.

inflate_input(_Zlib, <<>>, _Limit, _Size, Chunks) ->
    {ok, Chunks};
inflate_input(Zlib, Data, Limit, Size, Chunks) ->
    Length = min(byte_size(Data), ?INFLATE_INPUT_BYTES),
    <<Input:Length/binary, Rest/binary>> = Data,
    case inflate_output(Zlib, Input, Limit, Size, Chunks) of
        {ok, NewSize, NewChunks} ->
            inflate_input(Zlib, Rest, Limit, NewSize, NewChunks);
        Error -> Error
    end.

inflate_output(Zlib, Input, Limit, Size, Chunks) ->
    {Status, Output} = zlib:safeInflate(Zlib, Input),
    NewSize = Size + iolist_size(Output),
    case NewSize =< Limit of
        false -> {error, invalid_archive};
        true ->
            NewChunks = [Output | Chunks],
            case Status of
                continue -> inflate_output(Zlib, <<>>, Limit, NewSize, NewChunks);
                finished -> {ok, NewSize, NewChunks}
            end
    end.

extract_selected(Data, Options, Select) ->
    case table(Data, Options) of
        {ok, Paths} ->
            Selected = Select(Paths),
            Names = [unicode:characters_to_list(Path) || {Path, _OutputPath} <- Selected],
            case extract(Data, [{files, Names} | Options]) of
                {ok, Files} ->
                    OutputPaths = maps:from_list(Selected),
                    {ok, lists:keysort(1, [
                        {maps:get(Path, OutputPaths), Contents}
                     || {Path, Contents} <- Files
                    ])};
                Error -> Error
            end;
        Error -> Error
    end.

table(Data, Options) ->
    try erl_tar:table({binary, Data}, [verbose | Options]) of
        {ok, Entries} ->
            {ok, [
                unicode:characters_to_binary(Path)
             || {Path, regular, _Size, _Time, _Mode, _Uid, _Gid} <- Entries
            ]};
        {error, _Reason} -> {error, invalid_archive}
    catch
        _:_ -> {error, invalid_archive}
    end.

extract_root_file_tar_gz(Data, Filename, Limit)
        when is_binary(Data), is_binary(Filename) ->
    with_tar(Data, Limit, fun(Tar) -> extract_root_file(Tar, Filename) end);
extract_root_file_tar_gz(_Data, _Filename, _Limit) ->
    {error, invalid_archive}.

extract_root_file(Data, Filename) ->
    try erl_tar:table({binary, Data}, []) of
        {ok, Paths} ->
            case root_file(Paths, Filename) of
                {ok, Path} ->
                    case erl_tar:extract(
                        {binary, Data},
                        [memory, {files, [Path]}]
                    ) of
                        {ok, [{_Path, Contents}]} -> {ok, Contents};
                        _ -> {error, invalid_archive}
                    end;
                error ->
                    {error, missing_root_file}
            end;
        {error, _Reason} ->
            {error, invalid_archive}
    catch
        _:_ -> {error, invalid_archive}
    end.

root_file(Paths, Filename) ->
    Matches = [
        Path
     || Path <- Paths,
        is_root_file(Path, Filename)
    ],
    case Matches of
        [Path] -> {ok, Path};
        _ -> error
    end.

is_root_file(Path, Filename) ->
    BinaryPath = unicode:characters_to_binary(Path),
    Parts = binary:split(BinaryPath, <<"/">>, [global, trim_all]),
    case Parts of
        [Filename] -> true;
        [_Root, Filename] -> true;
        _ -> false
    end.

extract(Data, Options) ->
    try erl_tar:extract({binary, Data}, [memory | Options]) of
        {ok, Files} -> {ok, lists:filtermap(fun to_entry/1, Files)};
        {error, _Reason} -> {error, invalid_archive}
    catch
        _:_ -> {error, invalid_archive}
    end.

to_entry({Path, Contents}) when is_list(Path), is_binary(Contents) ->
    {true, {unicode:characters_to_binary(Path), Contents}};
to_entry({Path, Contents}) when is_binary(Path), is_binary(Contents) ->
    {true, {Path, Contents}};
to_entry(_) ->
    false.
