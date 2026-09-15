-module(hex_metadata_ffi).
-export([decode/1]).

-define(MAX_METADATA_BYTES, 1048576).
-define(BINARY_STRING, "<<\"((?:\\\\.|[^\"\\\\])*)\"(?:/utf8)?>>").

decode(Input) when is_binary(Input), byte_size(Input) =< ?MAX_METADATA_BYTES ->
    try
        {ok, LicenceSection} = section(Input, <<"licenses">>),
        Licences = strings(LicenceSection),
        Description = description(Input),
        Links = link_pairs(optional_section(Input, <<"links">>)),
        {ok, {Licences, Description, Links}}
    catch
        error:_ -> {error, nil}
    end;
decode(_Input) ->
    {error, nil}.

section(Input, Name) ->
    Pattern = iolist_to_binary([
        "\\{<<\"", Name, "\">>,\\s*\\[(.*?)\\]\\}\\s*\\."
    ]),
    case re:run(Input, Pattern, [dotall, {capture, [1], binary}]) of
        {match, [Value]} -> {ok, Value};
        nomatch -> {error, missing}
    end.

optional_section(Input, Name) ->
    case section(Input, Name) of
        {ok, Value} -> Value;
        {error, missing} -> <<>>
    end.

description(Input) ->
    Pattern = iolist_to_binary([
        "\\{<<\"description\">>,\\s*", ?BINARY_STRING, "\\}\\s*\\."
    ]),
    case re:run(Input, Pattern, [dotall, {capture, [1], binary}]) of
        {match, [Value]} -> {some, decode_string(Value)};
        nomatch -> none
    end.

strings(Input) ->
    case re:run(Input, ?BINARY_STRING, [global, {capture, [1], binary}]) of
        {match, Matches} -> [decode_string(Value) || [Value] <- Matches];
        nomatch -> []
    end.

link_pairs(Input) ->
    String = ?BINARY_STRING,
    Pattern = iolist_to_binary([
        "\\{\\s*", String, "\\s*,\\s*", String, "\\s*\\}"
    ]),
    case re:run(Input, Pattern, [global, {capture, [1, 2], binary}]) of
        {match, Matches} ->
            [
                {decode_string(Label), decode_string(Url)}
             || [Label, Url] <- Matches
            ];
        nomatch ->
            []
    end.

decode_string(Value) ->
    Source = binary_to_list(<<$", Value/binary, $", $.>>),
    {ok, Tokens, _} = erl_scan:string(Source),
    {ok, Characters} = erl_parse:parse_term(Tokens),
    Raw = list_to_binary(Characters),
    case unicode:characters_to_binary(Raw, utf8, utf8) of
        Converted when is_binary(Converted) ->
            Converted;
        _ ->
            unicode:characters_to_binary(Raw, latin1, utf8)
    end.
