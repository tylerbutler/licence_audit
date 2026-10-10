-module(cache_dir_ffi).
-export([new_store/1, read/2, take_warning/1, warn/2, write/3]).

new_store(Path) ->
    {Path, make_ref()}.

read(Store = {Root, _Ref}, Key) ->
    Path = entry_path(Root, Key),
    case file:read_file(Path) of
        {ok, Value} ->
            {ok, Value};
        {error, enoent} ->
            {error, <<"cache entry not found">>};
        {error, Reason} ->
            Error = describe(<<"read">>, Path, Reason),
            remember_warning(Store, Error),
            {error, Error}
    end.

write(Store = {Root, _Ref}, Key, Value) ->
    Target = entry_path(Root, Key),
    Temp = temporary_path(Target),
    Result =
        case file:open(Temp, [write, binary, exclusive, raw]) of
            {ok, File} ->
                write_and_publish(File, Temp, Target, Value);
            {error, Reason} ->
                {error, describe(<<"create temporary">>, Temp, Reason)}
        end,
    case Result of
        ok ->
            {ok, nil};
        {error, Error} ->
            _ = file:delete(Temp),
            remember_warning(Store, Error),
            {error, Error}
    end.

take_warning({_Root, Ref}) ->
    case erlang:erase({?MODULE, Ref}) of
        undefined -> none;
        Warning -> {some, Warning}
    end.

warn(Store, Warning) ->
    remember_warning(Store, Warning),
    nil.

write_and_publish(File, Temp, Target, Value) ->
    case file:write(File, Value) of
        ok ->
            case file:sync(File) of
                ok ->
                    case file:close(File) of
                        ok -> publish(Temp, Target);
                        {error, Reason} ->
                            {error, describe(<<"close temporary">>, Temp, Reason)}
                    end;
                {error, Reason} ->
                    _ = file:close(File),
                    {error, describe(<<"sync temporary">>, Temp, Reason)}
            end;
        {error, Reason} ->
            _ = file:close(File),
            {error, describe(<<"write temporary">>, Temp, Reason)}
    end.

publish(Temp, Target) ->
    case file:rename(Temp, Target) of
        ok ->
            ok;
        {error, Reason} when Reason =:= eexist; Reason =:= eacces ->
            replace_existing(Temp, Target, Reason);
        {error, Reason} ->
            {error, describe(<<"publish">>, Target, Reason)}
    end.

replace_existing(Temp, Target, RenameReason) ->
    case filelib:is_regular(Target) of
        false ->
            {error, describe(<<"publish">>, Target, RenameReason)};
        true ->
            case file:delete(Target) of
                ok -> publish_after_delete(Temp, Target);
                {error, enoent} -> publish_after_delete(Temp, Target);
                {error, Reason} ->
                    {error, describe(<<"replace">>, Target, Reason)}
            end
    end.

publish_after_delete(Temp, Target) ->
    case file:rename(Temp, Target) of
        ok ->
            ok;
        {error, Reason} when Reason =:= eexist; Reason =:= eacces ->
            case filelib:is_regular(Target) of
                true ->
                    _ = file:delete(Temp),
                    ok;
                false ->
                    {error, describe(<<"publish">>, Target, Reason)}
            end;
        {error, Reason} ->
            {error, describe(<<"publish">>, Target, Reason)}
    end.

entry_path(Root, Key) ->
    Digest = crypto:hash(sha256, Key),
    Filename = <<(binary:encode_hex(Digest, lowercase))/binary, ".cache">>,
    filename:join(Root, Filename).

temporary_path(Target) ->
    Pid = unicode:characters_to_binary(os:getpid()),
    Random = binary:encode_hex(crypto:strong_rand_bytes(12), lowercase),
    <<Target/binary, ".tmp.", Pid/binary, ".", Random/binary>>.

remember_warning({_Root, Ref}, Warning) ->
    erlang:put({?MODULE, Ref}, Warning),
    ok.

describe(Operation, Path, Reason) ->
    ReasonText = unicode:characters_to_binary(file:format_error(Reason)),
    <<Operation/binary, " ", Path/binary, ": ", ReasonText/binary>>.
