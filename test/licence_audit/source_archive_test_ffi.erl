-module(source_archive_test_ffi).
-export([with_tar_gz/2, large_binary/0, with_inflation_count/1, gunzip/1,
    gzip/1, corrupt_crc/1, with_inflate_stats/1, incompressible_binary/0]).

%% Gleam core has no tar writer or OTP call-count tracing. Generate binary
%% archive fixtures and count real inflations, not calls to an injected reader;
%% try/after removes files and tracing even when an assertion raises.
gunzip(Bytes) ->
    zlib:gunzip(Bytes).

with_inflation_count(Check) ->
    {module, zlib} = code:ensure_loaded(zlib),
    Session = trace:session_create(?MODULE, self(), []),
    1 = trace:function(Session, {zlib, inflateInit, 3}, true, [local, call_count]),
    1 = trace:process(Session, self(), true, [call]),
    try
        Result = Check(),
        {call_count, Count} = trace:info(Session, {zlib, inflateInit, 3}, call_count),
        {Result, Count}
    after
        trace:session_destroy(Session)
    end.

gzip(Bytes) ->
    zlib:gzip(Bytes).

corrupt_crc(Bytes) ->
    Offset = byte_size(Bytes) - 8,
    <<Prefix:Offset/binary, Byte, Rest/binary>> = Bytes,
    <<Prefix/binary, (Byte bxor 255), Rest/binary>>.

with_inflate_stats(Check) ->
    {module, zlib} = code:ensure_loaded(zlib),
    Session = trace:session_create(?MODULE, self(), []),
    Functions = [{zlib, safeInflate, 2}, {zlib, close, 1}],
    [1 = trace:function(Session, Function, true, [local, call_count])
        || Function <- Functions],
    1 = trace:process(Session, self(), true, [call]),
    try
        Result = Check(),
        [{call_count, Inflations}, {call_count, Closes}] =
            [trace:info(Session, Function, call_count) || Function <- Functions],
        {Result, Inflations, Closes}
    after
        trace:session_destroy(Session)
    end.

large_binary() ->
    binary:copy(<<0>>, 8 * 1024 * 1024).

incompressible_binary() ->
    crypto:strong_rand_bytes(32768).

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
