-module(cache_dir_ffi).
-export([windows_user_cache/0]).

windows_user_cache() ->
    case os:type() of
        {win32, _} ->
            try filename:basedir(user_cache, "licence_audit") of
                Path ->
                    case {filename:pathtype(Path), unicode:characters_to_binary(Path)} of
                        {absolute, Binary} when is_binary(Binary) -> {ok, Binary};
                        _ -> {error, nil}
                    end
            catch
                error:badarg -> {error, nil}
            end;
        _ ->
            {error, nil}
    end.
