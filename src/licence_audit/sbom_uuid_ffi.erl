-module(sbom_uuid_ffi).
-export([timestamp_now_utc/0, timestamp_of_epoch_utc/1, sha256/1]).

timestamp_now_utc() ->
    timestamp_of_epoch_utc(erlang:system_time(second)).

timestamp_of_epoch_utc(Seconds) ->
    Bin = calendar:system_time_to_rfc3339(Seconds, [{offset, "Z"}, {unit, second}]),
    list_to_binary(Bin).

sha256(Data) ->
    crypto:hash(sha256, Data).
