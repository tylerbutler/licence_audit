-module(cache_dir_ffi).
-export([open/1, lookup/2, insert/4, take_warning/1, warn/2]).

open(Path) ->
    with_connection(Path, fun(Connection) ->
        case query(Connection, <<"PRAGMA journal_mode=WAL">>, []) of
            {ok, [{<<"wal">>}]} ->
                case query(Connection,
                    <<"CREATE TABLE IF NOT EXISTS cache_entries (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        cached_at INTEGER
                    )">>, []) of
                    {ok, []} -> {ok, nil};
                    {error, _} = Error -> Error
                end;
            {ok, _} -> {error, <<"SQLite WAL mode is unavailable">>};
            {error, _} = Error -> Error
        end
    end).

lookup(Path, Key) ->
    with_connection(Path, fun(Connection) ->
        case query(Connection,
            <<"SELECT value, cached_at FROM cache_entries WHERE key = ?">>, [Key]) of
            {ok, []} -> {ok, none};
            {ok, [{Value, undefined}]} when is_binary(Value) ->
                entry(Value, none);
            {ok, [{Value, CachedAt}]} when is_binary(Value), is_integer(CachedAt) ->
                entry(Value, {some, CachedAt});
            {ok, _} -> {error, <<"Invalid cached value or timestamp">>};
            {error, _} = Error -> Error
        end
    end).

entry(Value, CachedAt) ->
    case unicode:characters_to_binary(Value) of
        Value -> {ok, {some, {entry, Value, CachedAt}}};
        _ -> {error, <<"Invalid UTF-8 cached value">>}
    end.

insert(Path, Key, Value, CachedAt) ->
    Timestamp = case CachedAt of none -> undefined; {some, Seconds} -> Seconds end,
    with_connection(Path, fun(Connection) ->
        case query(Connection,
            <<"INSERT INTO cache_entries (key, value, cached_at) VALUES (?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET
                 value = excluded.value, cached_at = excluded.cached_at">>,
            [Key, Value, Timestamp]) of
            {ok, []} -> {ok, nil};
            {error, _} = Error -> Error
        end
    end).

with_connection(Path, Action) ->
    case validate_path(Path) of
        {ok, Absolute} ->
            case prepare_driver() of
                ok -> connect(Absolute, Action);
                {error, _} = Error -> Error
            end;
        {error, _} = Error -> Error
    end.

validate_path(Path) ->
    case binary:match(Path, <<0>>) of
        nomatch ->
            Absolute = filename:absname(Path),
            case os:type() of
                {unix, linux} when byte_size(Absolute) > 504 ->
                    {error, <<"SQLite absolute cache paths on Linux must not exceed 504 UTF-8 bytes">>};
                _ -> {ok, Absolute}
            end;
        _ -> {error, <<"SQLite filenames cannot contain NUL bytes">>}
    end.

connect(Path, Action) ->
    %% Upstream failed-open cleanup is tracked in #168.
    %% The NIF copies Latin-1 list elements to SQLite's UTF-8 filename buffer.
    case esqlite3:open(binary_to_list(Path)) of
        {ok, Connection} ->
            Outcome = case query(Connection, <<"PRAGMA busy_timeout=0">>, []) of
                {ok, _} -> Action(Connection);
                {error, _} = Error -> Error
            end,
            case {Outcome, esqlite3:close(Connection)} of
                {{ok, _}, {error, CloseCode}} -> sqlite_error(Connection, CloseCode);
                _ -> Outcome
            end;
        {error, invalid_filename} ->
            {error, <<"SQLite cache path is too long (Linux absolute-path limit: 504 UTF-8 bytes)">>};
        {error, Code} ->
            {error, <<"Unable to open SQLite database (error ",
                (integer_to_binary(Code))/binary,
                "); check permissions and path length (Linux limit: 504 UTF-8 bytes)">>}
    end.

prepare_driver() ->
    case init:get_argument(escript) of
        {ok, _} ->
            Directory = filename:dirname(filename:absname(escript:script_name())),
            Ebin = filename:join([Directory, "sqlite_native", "esqlite", "ebin"]),
            case code:add_patha(Ebin) of
                true -> load_driver();
                {error, Reason} ->
                    {error, describe(<<"SQLite sidecar is unavailable; keep sqlite_native beside the escript">>, Reason)}
            end;
        error -> load_driver()
    end.

load_driver() ->
    case code:ensure_loaded(esqlite3_nif) of
        {module, esqlite3_nif} -> ok;
        {error, Reason} ->
            {error, describe(<<"Unable to load the SQLite native library">>, Reason)}
    end.

query(Connection, Sql, Arguments) ->
    %% q/3 synchronously finalizes its private statement, including on failure.
    try esqlite3:q(Connection, Sql, Arguments) of
        Rows when is_list(Rows) -> {ok, lists:map(fun list_to_tuple/1, Rows)};
        {error, Code} -> sqlite_error(Connection, Code)
    catch
        error:{case_clause, '$busy'} -> sqlite_error(Connection, 5)
    end.

sqlite_error(Connection, Code) ->
    #{errmsg := Message} = esqlite3:error_info(Connection),
    {error, <<"SQLite error ", (integer_to_binary(Code))/binary, ": ", Message/binary>>}.

describe(Message, Reason) ->
    Detail = unicode:characters_to_binary(io_lib:format("~tp", [Reason])),
    <<Message/binary, ": ", Detail/binary>>.

take_warning(Ref) ->
    case erlang:erase({?MODULE, Ref}) of
        undefined -> none;
        Warning -> {some, Warning}
    end.

warn(Ref, Warning) ->
    erlang:put({?MODULE, Ref}, Warning),
    nil.
