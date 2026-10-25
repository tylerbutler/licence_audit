-module(env_ffi).
-export([get/1]).

get(Name) when is_binary(Name) ->
    case os:getenv(binary_to_list(Name)) of
        false -> {error, nil};
        Value ->
            try unicode:characters_to_binary(Value) of
                Utf8 when is_binary(Utf8) -> {ok, Utf8};
                _ -> {error, nil}
            catch
                error:badarg -> {error, nil}
            end
    end.
