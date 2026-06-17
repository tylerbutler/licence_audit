-module(env_ffi).
-export([get/1]).

get(Name) when is_binary(Name) ->
    case os:getenv(binary_to_list(Name)) of
        false -> {error, nil};
        Value -> {ok, list_to_binary(Value)}
    end.
