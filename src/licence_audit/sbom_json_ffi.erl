-module(sbom_json_ffi).
-export([pretty_print/1]).

pretty_print(Json) when is_binary(Json) ->
    case jsone:try_decode(Json, [{object_format, proplist}]) of
        {ok, Term, <<>>} -> encode_pretty(Term);
        {ok, _Term, _Remaining} -> {error, <<"unexpected trailing JSON content">>};
        {error, _Reason} -> {error, <<"invalid JSON">>}
    end.

encode_pretty(Term) ->
    case jsone:try_encode(Term, [native_forward_slash, {indent, 2}, {space, 1}]) of
        {ok, Pretty} -> {ok, Pretty};
        {error, _Reason} -> {error, <<"failed to encode JSON">>}
    end.
