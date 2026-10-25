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
      false = code:is_loaded(esqlite3_nif),
      Path = unicode:characters_to_binary(os:getenv("CACHE_TEST_PATH")),
      try licence_audit@cache:open({enabled, {some, Path}}) of
        _ -> erlang:error(expected_sqlight_native_load_exception)
      catch
        error:undef -> ok
      end,
      false = filelib:is_regular(Path),
      halt().
    '
done

echo "Sqlight native-load limits and disabled-cache tests passed."
