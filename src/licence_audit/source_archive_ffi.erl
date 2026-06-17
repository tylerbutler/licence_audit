-module(source_archive_ffi).
-export([extract_tar/1, extract_tar_gz/1]).

extract_tar(Data) when is_binary(Data) ->
    extract(Data, []).

extract_tar_gz(Data) when is_binary(Data) ->
    extract(Data, [compressed]).

extract(Data, Options) ->
    case erl_tar:extract({binary, Data}, [memory | Options]) of
        {ok, Files} -> {ok, lists:filtermap(fun to_entry/1, Files)};
        {error, _Reason} -> {error, invalid_archive}
    end.

to_entry({Path, Contents}) when is_list(Path), is_binary(Contents) ->
    {true, {unicode:characters_to_binary(Path), Contents}};
to_entry({Path, Contents}) when is_binary(Path), is_binary(Contents) ->
    {true, {Path, Contents}};
to_entry(_) ->
    false.
