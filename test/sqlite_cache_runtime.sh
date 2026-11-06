#!/usr/bin/env bash
set -euo pipefail

work="$PWD/build/sqlite-runtime-$$"
mkdir -p "$work/esqlite/ebin" "$work/esqlite/priv"
trap 'rm -rf -- "$work"' EXIT
cp build/dev/erlang/esqlite/ebin/* "$work/esqlite/ebin/"

for library in missing unloadable; do
  if [ "$library" = unloadable ]; then
    printf 'invalid native library' >"$work/esqlite/priv/esqlite3_nif.so"
  fi
  CACHE_TEST_PATH="$work/$library.sqlite3" \
    timeout --kill-after=5s 30s erl -noshell \
    -pa "$PWD/build/dev/erlang/"*/ebin -pa "$work/esqlite/ebin" -eval '
      false = code:is_loaded(esqlite3_nif),
      Disabled = licence_audit@cache:open(disabled),
      none = licence_audit@cache:close(Disabled),
      DisabledNotices = licence_audit@notice_cache:open(disabled),
      none = licence_audit@notice_cache:close(DisabledNotices),
      false = code:is_loaded(esqlite3_nif),
      Path = unicode:characters_to_binary(os:getenv("CACHE_TEST_PATH")),
      Cache = licence_audit@cache:open({enabled, {some, Path}}),
      {some, Warning} = licence_audit@cache:close(Cache),
      {_, _} = binary:match(Warning, <<"SQLite native library unavailable">>),
      Metadata = licence_audit@hex:licences_only([<<"MIT">>]),
      {{ok, Metadata}, none} = licence_audit@cache:fetch_cached_quiet(
          Cache, <<"example">>, <<"1.0.0">>, fun(_) -> {ok, Metadata} end),
      Notices = licence_audit@notice_cache:open({enabled, {some, Path}}),
      {some, NoticeWarning} = licence_audit@notice_cache:close(Notices),
      {_, _} = binary:match(NoticeWarning, <<"SQLite native library unavailable">>),
      none = licence_audit@notice_cache:put_text(Notices, <<"key">>, <<"text">>),
      {{error, nil}, none} = licence_audit@notice_cache:get_text(Notices, <<"key">>),
      false = code:is_loaded(esqlite3_nif),
      false = filelib:is_regular(Path),
      halt().
    '
done

echo "SQLite native-load fallback and disabled-cache tests passed."
