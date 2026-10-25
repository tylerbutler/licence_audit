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
      Cache = licence_audit@cache:open({enabled, {some, Path}}),
      {some, Warning} = licence_audit@cache:close(Cache),
      true = binary:match(Warning, <<"Unable to load the SQLite native library">>) =/= nomatch,
      false = filelib:is_regular(Path),
      halt().
    '
done

if [ "$(uname -s)" = Linux ]; then
  CACHE_TEST_ROOT="$work" timeout --kill-after=5s 30s erl -noshell \
    -pa "$PWD/build/dev/erlang/"*/ebin -eval '
      Parent = filename:join([os:getenv("CACHE_TEST_ROOT"),
          lists:duplicate(150, $a), lists:duplicate(150, $b)]),
      ok = filelib:ensure_dir(filename:join(Parent, "unused")),
      Prefix = unicode:characters_to_binary(Parent),
      Padding = binary:copy(<<"c">>, 503 - byte_size(Prefix)),
      Accepted = <<Prefix/binary, "/", Padding/binary>>,
      Rejected = <<Accepted/binary, "c">>,
      504 = byte_size(Accepted),
      {ok, Store} = licence_audit@cache_dir:open_table({some, Accepted}, <<"unused">>, <<"test">>),
      {ok, nil} = licence_audit@cache_dir:insert(Store, <<"key">>, <<"value">>),
      {ok, <<"value">>} = licence_audit@cache_dir:lookup(Store, <<"key">>),
      none = licence_audit@cache_dir:close_table(Store, <<"test">>, none),
      Cache = licence_audit@cache:open({enabled, {some, Rejected}}),
      {some, Warning} = licence_audit@cache:close(Cache),
      true = binary:match(Warning, <<"504 UTF-8 bytes">>) =/= nomatch,
      false = filelib:is_regular(Rejected),
      halt().
    '
fi

echo "SQLite native-load failure tests passed."
