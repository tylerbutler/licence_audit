-module(integration_test_ffi).
-export([record_detail_fetch/1, reset_detail_fetch/1]).

reset_detail_fetch(Id) ->
    erase({?MODULE, detail_fetch, Id}),
    nil.

record_detail_fetch(Id) ->
    Key = {?MODULE, detail_fetch, Id},
    Count = case get(Key) of undefined -> 1; Previous -> Previous + 1 end,
    put(Key, Count),
    Count.
