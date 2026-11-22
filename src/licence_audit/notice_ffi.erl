-module(notice_ffi).
-export([has_text/1, link_type/1, link_type/2]).
-include_lib("kernel/include/file.hrl").

link_type(Path) ->
    link_type(Path, fun file:read_link_info/1).

%% Windows symlinks have regular-file mode bits; retain the native type.
link_type(Path, ReadLinkInfo) ->
    case ReadLinkInfo(Path) of
        {ok, #file_info{type = regular}} -> {ok, file};
        {ok, #file_info{type = directory}} -> {ok, directory};
        {ok, #file_info{type = symlink}} -> {ok, symlink};
        {ok, #file_info{}} -> {ok, other};
        {error, Reason} -> {error, Reason}
    end.

%% string.trim uses Pattern_White_Space, which excludes NBSP and em spaces.
%% OTP's Unicode whitespace classes reject those blank licence files too.
has_text(Text) ->
    re:run(Text, "\\S", [unicode, ucp, {capture, none}]) =:= match.
