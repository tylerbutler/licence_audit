-module(cache_dir_ffi).
-export([take_warning/1, warn/2]).

take_warning(Ref) ->
    case erlang:erase({?MODULE, Ref}) of
        undefined -> none;
        Warning -> {some, Warning}
    end.

warn(Ref, Warning) ->
    erlang:put({?MODULE, Ref}, Warning),
    nil.
