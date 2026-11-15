-module(env_ffi).
-export([get/1]).

-ifdef(TEST).
-export([to_utf8/1]).
-endif.

%% Gleam core has no environment API. Decode OTP's Unicode charlists explicitly:
%% byte-oriented conversion corrupts non-ASCII paths and invalid values must fail.
get(Name) when is_binary(Name) ->
    case os:getenv(binary_to_list(Name)) of
        false -> {error, nil};
        Value -> to_utf8(Value)
    end.

to_utf8(Value) ->
    try unicode:characters_to_binary(Value) of
        Binary when is_binary(Binary) -> {ok, Binary};
        {error, _, _} -> {error, nil};
        {incomplete, _, _} -> {error, nil}
    catch
        error:badarg -> {error, nil}
    end.
