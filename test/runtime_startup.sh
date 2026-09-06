#!/usr/bin/env bash
set -euo pipefail

# Use fresh VMs: the Gleam test runner has already started the applications.
timeout --kill-after=5s 30s erl -noshell -pa build/dev/erlang/*/ebin -eval '
  undefined = whereis(httpc_manager),
  {ok, nil} = runtime_ffi:start(),
  true = is_pid(whereis(httpc_manager)),
  true = lists:keymember(ssl, 1, application:which_applications()),
  {ok, nil} = runtime_ffi:start(),
  halt(0).
'

status=0
output=$(timeout --kill-after=5s 30s erl -noshell -pa build/dev/erlang/*/ebin -eval '
  ok = application:load({application, licence_audit, [
    {vsn, "test"}, {applications, [licence_audit_missing_runtime_dependency]}
  ]}),
  licence_audit:main().
' 2>&1) || status=$?
if [ "$status" -ne 2 ] || [[ "$output" != *"Error: Could not start runtime applications: licence_audit_missing_runtime_dependency:"* ]]; then
  printf 'Expected startup diagnostic and exit 2, got exit %s:\n%s\n' "$status" "$output" >&2
  exit 1
fi
if [[ "$output" == *"Runtime terminating"* ]]; then
  printf 'Startup failure crashed the VM:\n%s\n' "$output" >&2
  exit 1
fi
echo "Runtime startup tests passed."
