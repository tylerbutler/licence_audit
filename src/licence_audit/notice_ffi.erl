-module(notice_ffi).
-export([has_text/1]).

%% string.trim uses Pattern_White_Space, which excludes NBSP and em spaces.
%% OTP's Unicode whitespace classes reject those blank licence files too.
has_text(Text) ->
    re:run(Text, "\\S", [unicode, ucp, {capture, none}]) =:= match.
