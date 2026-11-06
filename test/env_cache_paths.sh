#!/usr/bin/env bash
set -euo pipefail

work="$PWD/build/env-cache-paths-$$"
mkdir "$work"
trap 'rm -rf -- "$work"' EXIT
cp test/fixtures/native_http/{gleam.toml,manifest.toml} "$work/"
binary="$PWD/licence_audit"

# Compile the same conversion code with its test-only export.
timeout --kill-after=5s 30s erl -noshell -eval '
  {ok, env_ffi, Binary} = compile:file("src/licence_audit/env_ffi.erl", [binary, {d, '\''TEST'\''}]),
  {module, env_ffi} = code:load_binary(env_ffi, "env_ffi.erl", Binary),
  {error, nil} = env_ffi:to_utf8([16#D800]),
  {error, nil} = env_ffi:to_utf8([16#110000]),
  {error, nil} = env_ffi:to_utf8(<<16#FF>>),
  {error, nil} = env_ffi:to_utf8(<<16#E4, 16#B8>>),
  {error, nil} = env_ffi:to_utf8([not_a_character]),
  halt().
'

for character in é 中; do
  for variable in XDG_CACHE_HOME HOME; do
    root="$work/$variable-$character"
    if [ "$variable" = XDG_CACHE_HOME ]; then
      environment=(env "HOME=$work/unused-home" "XDG_CACHE_HOME=$root")
    else
      environment=(env -u XDG_CACHE_HOME "HOME=$root")
    fi

    "${environment[@]}" CACHE_TEST_VARIABLE="$variable" CACHE_TEST_ROOT="$root" \
      timeout --kill-after=5s 30s erl -noshell -pa build/dev/erlang/*/ebin -eval '
        Variable = list_to_binary(os:getenv("CACHE_TEST_VARIABLE")),
        Root = unicode:characters_to_binary(os:getenv("CACHE_TEST_ROOT")),
        {ok, Root} = env_ffi:get(Variable),
        Disabled = licence_audit@cache:open(disabled),
        none = licence_audit@cache:close(Disabled),
        false = code:is_loaded(esqlite3_nif),
        halt().
      '
  done
done

for variable in XDG_CACHE_HOME HOME; do
  root="$work/$variable"
  if [ "$variable" = XDG_CACHE_HOME ]; then
    expected="$root/licence_audit"
    environment=(env "HOME=$work/unused-home" "XDG_CACHE_HOME=$root")
  else
    expected="$root/.cache/licence_audit"
    environment=(env -u XDG_CACHE_HOME "HOME=$root")
  fi

  "${environment[@]}" CACHE_TEST_VARIABLE="$variable" \
    CACHE_TEST_ROOT="$root" CACHE_TEST_EXPECTED="$expected" \
    timeout --kill-after=5s 30s erl -noshell -pa build/dev/erlang/*/ebin -eval '
      Variable = list_to_binary(os:getenv("CACHE_TEST_VARIABLE")),
      Root = unicode:characters_to_binary(os:getenv("CACHE_TEST_ROOT")),
      {ok, Root} = env_ffi:get(Variable),
      {ok, Store} = licence_audit@cache_dir:open_table(none, <<"hex-v2.sqlite3">>, <<"licence">>),
      Key = <<"gleam_stdlib@1.0.5">>,
      {ok, nil} = licence_audit@cache_dir:insert_at(Store, Key, <<"{\"licences\":[\"Apache-2.0\"],\"links\":[]}">>, {some, erlang:system_time(second)}),
      Expected = filename:join(os:getenv("CACHE_TEST_EXPECTED"), "hex-v2.sqlite3"),
      true = filelib:is_regular(Expected),
      halt().
    '
  test -s "$expected/hex-v2.sqlite3"

  # A fresh, cache-enabled CLI must read this entry without a network request.
  (
    cd "$work"
    if ! "${environment[@]}" timeout --kill-after=5s 30s "$binary" \
      --verbose --color=never >cli.log 2>&1; then
      cat cli.log >&2
      exit 1
    fi
    grep -Fq 'Cache hit for gleam_stdlib@1.0.5' cli.log
    grep -Eq 'gleam_stdlib[[:space:]]+1\.0\.5[[:space:]]+Apache-2\.0' cli.log
    if grep -Eiq 'warn|cache miss|runtime terminating|crash dump' cli.log; then
      cat cli.log >&2
      exit 1
    fi
  )
done

# Missing environment values still produce a deferred, non-fatal cache warning.
env -u XDG_CACHE_HOME -u HOME timeout --kill-after=5s 30s \
  erl -noshell -pa build/dev/erlang/*/ebin -eval '
    {error, nil} = env_ffi:get(<<"HOME">>),
    Cache = licence_audit@cache:open({enabled, none}),
    {some, Warning} = licence_audit@cache:close(Cache),
    true = binary:match(Warning, <<"neither XDG_CACHE_HOME nor HOME is set">>) =/= nomatch,
    halt().
  '
echo "Environment cache path tests passed."
