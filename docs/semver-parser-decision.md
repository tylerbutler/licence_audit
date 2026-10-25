# SemVer parser decision

Date: 2026-09-11

Status: Keep the local parser

## Context

Policy exceptions use exact package URLs. Hex package URLs contain a Semantic
Versioning 2.0.0 version. The parser must reject ranges, partial versions,
leading zeroes in numeric identifiers, empty identifiers, qualifiers, and
subpaths.

The implementation must support the Erlang and JavaScript targets. A
replacement should remove enough code to justify a new dependency.

## Candidates

### `gleamsver`

- Package: <https://hex.pm/packages/gleamsver>
- Documentation: <https://hexdocs.pm/gleamsver/gleamsver.html#parse>
- Source: <https://github.com/aznashwan/gleamsver>
- Latest release reviewed: 1.0.1, published 2024-07-08
- API: `parse(String) -> Result(SemVer, SemVerParseError)`
- Targets: Erlang and JavaScript
- Dependencies: `gleam_stdlib`

This is the closest match. Its parser accepts inputs that the exception format
must reject, including leading-zero core versions, leading-zero numeric
prerelease identifiers, and empty dot-separated identifiers. Correcting these
cases would keep much of the local validation and add a dependency.

### `version_bump`

- Package: <https://hex.pm/packages/version_bump>
- Source: <https://github.com/blakedietz/version_bump>
- Latest release reviewed: 0.2.0, published 2026-07-09
- Targets: Erlang and JavaScript

This package provides a release automation CLI rather than a focused SemVer
library. It has 11 direct dependencies. Its parser also accepts optional `v`
prefixes, surrounding whitespace, and some invalid identifiers.

### `npm_semver`

- Package: <https://hex.pm/packages/npm_semver>
- Source: <https://github.com/elixir-volt/npm_semver>

This package distinguishes versions from ranges, but it targets the BEAM
through Elixir and does not support JavaScript. It also accepts leading-zero
versions.

### `samovar`

- Package: <https://hex.pm/packages/samovar>
- Source: <https://github.com/crownedgrouse/samovar>

This Erlang package accepts ranges, wildcards, partial versions, and legacy
version forms. It does not provide the strict exact-version check that policy
exceptions require.

## Decision

Keep the string-based parser in `src/licence_audit/semver.gleam`.

The current parser:

- enforces the required SemVer rules;
- supports Erlang and JavaScript;
- does not normalize versions before package identity comparison;
- adds no dependency;
- handles arbitrarily large numeric components as strings.

## Reconsider when

Reconsider this decision when a maintained native Gleam package:

1. validates strict SemVer 2.0.0 without extra guards;
2. supports Erlang and JavaScript;
3. has a focused dependency tree;
4. passes the cases in `semver_test` and `exact_purl_validation_test`.
