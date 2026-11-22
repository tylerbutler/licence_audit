-module(integration_test_ffi).
-export([record_detail_fetch/1, reset_detail_fetch/1]).

%% Test state stays owned by the caller; network workers share its ETS handle.
reset_detail_fetch(Id) ->
    Table = case get({?MODULE, counters}) of
        undefined ->
            Created = ets:new(?MODULE, [public, set]),
            put({?MODULE, counters}, Created),
            Created;
        Existing -> Existing
    end,
    ets:delete(Table, Id),
    nil.

record_detail_fetch(Id) ->
    {dictionary, Dictionary} = process_info(network_ffi:command_owner(), dictionary),
    Table = proplists:get_value({?MODULE, counters}, Dictionary),
    ets:update_counter(Table, Id, 1, {Id, 0}).
