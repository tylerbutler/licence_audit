-module(source_archive_test_ffi).
-export([with_tar_gz/2, large_binary/0, with_inflation_count/1, gunzip/1]).

gunzip(Bytes) ->
    zlib:gunzip(Bytes).

with_inflation_count(Check) ->
    {module, zlib} = code:ensure_loaded(zlib),
    Session = trace:session_create(?MODULE, self(), []),
    1 = trace:function(Session, {zlib, inflate, 2}, true, [local, call_count]),
    1 = trace:process(Session, self(), true, [call]),
    try
        Result = Check(),
        {call_count, Count} = trace:info(Session, {zlib, inflate, 2}, call_count),
        {Result, Count}
    after
        trace:session_destroy(Session)
    end.

large_binary() ->
    binary:copy(<<0>>, 8 * 1024 * 1024).

with_tar_gz(Entries, Check) ->
    Path = filename:join("build/tmp/source_archive_test",
        os:getpid() ++ "-" ++ integer_to_list(erlang:unique_integer([positive])) ++ ".tar.gz"),
    ok = filelib:ensure_dir(Path),
    ok = erl_tar:create(Path, [
        {unicode:characters_to_list(Name), Contents} || {Name, Contents} <- Entries
    ], [compressed]),
    try
        {ok, Bytes} = file:read_file(Path),
        Check(Bytes)
    after
        ok = file:delete(Path)
    end.
