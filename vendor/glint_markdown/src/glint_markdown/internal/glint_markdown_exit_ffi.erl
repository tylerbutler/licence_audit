-module(glint_markdown_exit_ffi).
-export([stderr/1, exit_with/1]).

stderr(Message) ->
    io:put_chars(standard_error, Message),
    nil.

exit_with(Code) ->
    erlang:halt(Code),
    nil.
