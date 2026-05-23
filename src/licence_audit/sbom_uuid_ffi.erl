-module(sbom_uuid_ffi).
-export([timestamp_now_utc/0]).

timestamp_now_utc() ->
    Seconds = erlang:system_time(second),
    Bin = calendar:system_time_to_rfc3339(Seconds, [{offset, "Z"}, {unit, second}]),
    list_to_binary(Bin).
