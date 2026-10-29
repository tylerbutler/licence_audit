-module(args_ffi).
-export([arguments/0]).

%% Gleam has no core argv API. Escript adds its own filename to OTP's plain
%% arguments; keep that out of CLI options without dropping native-launcher args.
arguments() ->
    Plain = lists:map(
        fun(Arg) -> unicode:characters_to_binary(Arg, utf8) end,
        init:get_plain_arguments()
    ),
    case init:get_argument(escript) of
        {ok, _} -> tl(Plain);
        _ -> Plain
    end.
