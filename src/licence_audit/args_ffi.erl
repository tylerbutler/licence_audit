-module(args_ffi).
-export([arguments/0]).

arguments() ->
    Plain = lists:map(
        fun(Arg) -> unicode:characters_to_binary(Arg, utf8) end,
        init:get_plain_arguments()
    ),
    case init:get_argument(escript) of
        {ok, _} -> tl(Plain);
        _ -> Plain
    end.
