-module(notice_ffi).
-export([has_text/1]).

has_text(Text) ->
    re:run(Text, "\\S", [unicode, ucp, {capture, none}]) =:= match.
