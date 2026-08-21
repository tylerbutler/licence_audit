-module(sbom_json_ffi).
-export([pretty_print/1]).

pretty_print(Json) when is_binary(Json) ->
    Decoders = #{
        object_finish => fun(Acc, OldAcc) ->
            {{object, lists:reverse(Acc)}, OldAcc}
        end
    },
    try
        {Term, _, <<>>} = json:decode(Json, ok, Decoders),
        Pretty =
            iolist_to_binary(json:format(Term, fun format/3, #{max => 0})),
        {ok, binary:part(Pretty, 0, byte_size(Pretty) - 1)}
    catch
        error:_ -> {error, invalid_json}
    end.

format({object, Pairs}, Encoder, State) ->
    json:format_key_value_list(Pairs, Encoder, State);
format(Value, Encoder, State) ->
    json:format_value(Value, Encoder, State).
