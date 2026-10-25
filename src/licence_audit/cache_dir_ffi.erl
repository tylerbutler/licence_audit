-module(cache_dir_ffi).
-export([take_warning/1, warn/2, is_windows/0]).

is_windows() ->
    case os:type() of
        {win32, _} -> true;
        _ -> false
    end.

take_warning(Ref) ->
    case erlang:erase({?MODULE, Ref}) of
        undefined -> none;
        Warning -> {some, Warning}
    end.

warn(Ref, Warning) ->
    erlang:put({?MODULE, Ref}, Warning),
    nil.
