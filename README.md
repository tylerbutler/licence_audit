# license_audit

A standalone Gleam command-line package for auditing dependency licences.

This package is currently bootstrapped with a placeholder CLI entrypoint. The
help path is available and future tasks will add the real audit implementation.

## Development

```sh
mise trust
mise exec -- gleam test
mise exec -- gleam build
mise exec -- gleam export erlang-shipment
mise exec -- gleam run -m gleescript
mv ./license_audit ./gleam-audit
```
