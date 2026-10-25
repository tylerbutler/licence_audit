-module(hex_metadata_ffi).
-export([decode/1]).

-define(MAX_METADATA_BYTES, 1048576).
-define(MAX_DEPTH, 64).

decode(Input) when is_binary(Input), byte_size(Input) =< ?MAX_METADATA_BYTES ->
    try
        Fields = fields(space(Input), #{}),
        Licences = maps:get(<<"licenses">>, Fields),
        true = is_list(Licences),
        true = lists:all(fun is_binary/1, Licences),
        Description = case maps:find(<<"description">>, Fields) of
            {ok, Value} when is_binary(Value) -> {some, Value};
            error -> none
        end,
        Links = maps:get(<<"links">>, Fields, []),
        true = is_list(Links),
        true = lists:all(fun
            ({Label, Url}) -> is_binary(Label) andalso is_binary(Url);
            (_) -> false
        end, Links),
        {ok, {Licences, Description, Links}}
    catch
        error:_ -> {error, nil}
    end;
decode(_Input) ->
    {error, nil}.

fields(<<>>, Fields) ->
    Fields;
fields(Input, Fields) ->
    {{Key, Value}, Rest} = value(Input, 0),
    true = is_binary(Key),
    <<$., Tail/binary>> = space(Rest),
    false = maps:is_key(Key, Fields),
    fields(space(Tail), Fields#{Key => Value}).

%% Parse data only: never scan arbitrary atoms or evaluate binary expressions.
value(_, Depth) when Depth > ?MAX_DEPTH ->
    error(nesting_limit);
value(<<"<<", Rest/binary>>, _Depth) ->
    binary_segments(space(Rest), []);
value(<<$[, Rest/binary>>, Depth) ->
    sequence(space(Rest), $], Depth + 1, []);
value(<<${, Rest/binary>>, Depth) ->
    {Items, Tail} = sequence(space(Rest), $}, Depth + 1, []),
    {list_to_tuple(Items), Tail};
value(<<$", _/binary>> = Input, _Depth) ->
    {Characters, Rest} = quoted(Input, latin1),
    {{ignored_string, Characters}, Rest};
value(Input, _Depth) ->
    %% Other metadata fields contain numbers and atoms, retained without interning.
    {match, [Token]} = re:run(Input, <<"^(?:[a-z][a-zA-Z0-9_@]*|[0-9]+)">>,
        [{capture, first, binary}]),
    Size = byte_size(Token),
    <<_:Size/binary, Rest/binary>> = Input,
    {{ignored_literal, Token}, Rest}.

sequence(<<End, Rest/binary>>, End, _Depth, Acc) ->
    {lists:reverse(Acc), Rest};
sequence(Input, End, Depth, Acc) ->
    {Value, Rest} = value(Input, Depth),
    sequence_after(space(Rest), End, Depth, [Value | Acc]).

sequence_after(<<End, Rest/binary>>, End, _Depth, Acc) ->
    {lists:reverse(Acc), Rest};
sequence_after(<<$,, Rest/binary>>, End, Depth, Acc) ->
    {Value, Tail} = value(space(Rest), Depth),
    sequence_after(space(Tail), End, Depth, [Value | Acc]).

binary_segments(<<">>", Rest/binary>>, []) ->
    {<<>>, Rest};
binary_segments(Input, Acc) ->
    {Segment, Rest} = segment(Input),
    case space(Rest) of
        <<">>", Tail/binary>> ->
            {text(iolist_to_binary(lists:reverse([Segment | Acc]))), Tail};
        <<$,, Tail/binary>> ->
            binary_segments(space(Tail), [Segment | Acc])
    end.

segment(<<$", _/binary>> = Input) ->
    {Quoted, Rest} = take_quoted(Input),
    case space(Rest) of
        <<"/utf8", Tail/binary>> ->
            {Characters, <<>>} = quoted(Quoted, utf8),
            Converted = unicode:characters_to_binary(Characters, unicode, utf8),
            true = is_binary(Converted),
            {Converted, Tail};
        Tail ->
            {Characters, <<>>} = quoted(Quoted, latin1),
            {list_to_binary(Characters), Tail}
    end;
segment(Input) ->
    {match, [Token]} = re:run(Input, <<"^[0-9]{1,3}">>,
        [{capture, first, binary}]),
    Byte = binary_to_integer(Token),
    true = Byte =< 255,
    Size = byte_size(Token),
    <<_:Size/binary, Rest/binary>> = Input,
    {<<Byte>>, Rest}.

take_quoted(Input) ->
    {match, [Quoted]} = re:run(Input, <<"^\"(?:\\\\.|[^\"\\\\])*\"">>,
        [dotall, {capture, first, binary}]),
    Size = byte_size(Quoted),
    <<_:Size/binary, Rest/binary>> = Input,
    {Quoted, Rest}.

quoted(Input, Encoding) ->
    {Quoted, Rest} = take_quoted(Input),
    Source = unicode:characters_to_list(Quoted, Encoding),
    true = is_list(Source),
    {ok, [{string, _, Characters}, {dot, _}], _} = erl_scan:string(Source ++ "."),
    {Characters, Rest}.

text(Raw) ->
    case unicode:characters_to_binary(Raw, utf8, utf8) of
        Converted when is_binary(Converted) -> Converted;
        _ -> unicode:characters_to_binary(Raw, latin1, utf8)
    end.

space(<<Character, Rest/binary>>) when
    Character =:= $\s; Character =:= $\t; Character =:= $\n; Character =:= $\r
->
    space(Rest);
space(<<$%, Rest/binary>>) ->
    case binary:split(Rest, <<"\n">>) of
        [_Comment, Tail] -> space(Tail);
        [_Comment] -> <<>>
    end;
space(Input) ->
    Input.
