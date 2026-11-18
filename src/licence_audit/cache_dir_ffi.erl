-module(cache_dir_ffi).
-export([windows_user_cache/0, replace_file/2]).

replace_file(From, To) ->
    Result = case os:type() of
        {win32, _} ->
            %% OTP's destination-aside rename can leak its backup after a race.
            policy_file_ffi:windows_command(From, To, [
                "if($native.GetMethod('MoveFileExW').Invoke($null,@($from,$to,[uint32]9)))",
                "{exit 0}else{exit 1}"
            ], 60000);
        _ -> file:rename(From, To)
    end,
    case Result of
        ok -> {ok, nil};
        {error, {helper_not_stopped, _} = Reason} ->
            {error, {replacement_uncertain, describe(Reason)}};
        {error, Reason} ->
            {error, {replacement_failed, describe(Reason)}}
    end.

describe(Reason) when is_atom(Reason) ->
    unicode:characters_to_binary(file:format_error(Reason));
describe(Reason) ->
    unicode:characters_to_binary(io_lib:format("~tp", [Reason])).

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
