# license_audit

A standalone Gleam command-line package for auditing dependency licences.

This package is currently bootstrapped with a placeholder CLI entrypoint. The
help path is available and future tasks will add the real audit implementation.

## Development

```sh
mise exec gleam@1.16.0 erlang@27.3.4.11 -- gleam test
mise exec gleam@1.16.0 erlang@27.3.4.11 -- gleam build
mise exec gleam@1.16.0 erlang@27.3.4.11 -- gleam export erlang-shipment
mise exec gleam@1.16.0 erlang@27.3.4.11 -- gleam export escript
```
