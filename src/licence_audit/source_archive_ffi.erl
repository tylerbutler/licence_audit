-module(source_archive_ffi).
-export([extract_tar/1, extract_tar_gz/1, extract_root_file_tar_gz/2]).

extract_tar(Data) when is_binary(Data) ->
    extract(Data, []);
extract_tar(_Data) ->
    {error, invalid_archive}.

extract_tar_gz(Data) when is_binary(Data) ->
    extract(Data, [compressed]);
extract_tar_gz(_Data) ->
    {error, invalid_archive}.

extract_root_file_tar_gz(Data, Filename)
        when is_binary(Data), is_binary(Filename) ->
    try erl_tar:table({binary, Data}, [compressed]) of
        {ok, Paths} ->
            case root_file(Paths, Filename) of
                {ok, Path} ->
                    case erl_tar:extract(
                        {binary, Data},
                        [memory, compressed, {files, [Path]}]
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
    end;
extract_root_file_tar_gz(_Data, _Filename) ->
    {error, invalid_archive}.

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
