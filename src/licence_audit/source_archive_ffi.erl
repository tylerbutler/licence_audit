-module(source_archive_ffi).
-export([
    extract_tar/1,
    extract_tar_gz/1,
    extract_tar_selected/2,
    extract_tar_gz_selected/2,
    extract_root_file_tar_gz/2
]).

extract_tar(Data) when is_binary(Data) ->
    extract(Data, []);
extract_tar(_Data) ->
    {error, invalid_archive}.

extract_tar_gz(Data) when is_binary(Data) ->
    extract(Data, [compressed]);
extract_tar_gz(_Data) ->
    {error, invalid_archive}.

extract_tar_selected(Data, Select) when is_binary(Data) ->
    extract_selected(Data, [], Select);
extract_tar_selected(_Data, _Select) ->
    {error, invalid_archive}.

extract_tar_gz_selected(Data, Select) when is_binary(Data) ->
    case tar_data(Data) of
        {ok, Tar} -> extract_selected(Tar, [], Select);
        Error -> Error
    end;
extract_tar_gz_selected(_Data, _Select) ->
    {error, invalid_archive}.

%% OTP inflates binary input eagerly. Reuse one tar binary for both passes.
tar_data(<<16#1f, 16#8b, _/binary>> = Data) ->
    try zlib:gunzip(Data) of
        Tar -> {ok, Tar}
    catch
        error:data_error -> {error, invalid_archive}
    end;
tar_data(Data) ->
    {ok, Data}.

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

extract_root_file_tar_gz(Data, Filename)
        when is_binary(Data), is_binary(Filename) ->
    case tar_data(Data) of
        {ok, Tar} -> extract_root_file(Tar, Filename);
        Error -> Error
    end;
extract_root_file_tar_gz(_Data, _Filename) ->
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
