# SBOM comparison: ORT (Gleam guide) vs `licence_audit`

Generated for `tylerbutler/licence_audit` on 2026-06-26.

- **Ours:** `./licence_audit sbom --reproducible` -> `dist/sbom.json`
- **ORT:** `ort-minimal:74.0.0` `analyze` -> `report -f CycloneDx` (no `scan`/`advisor` stage run)
- Both emit **CycloneDX 1.6 JSON** and both pass `cyclonedx validate` and `sbom-utility validate`.

> Note: the guide's full pipeline is analyze -> **scan** -> advisor -> report. The `scan`
> stage (ScanCode, which concludes licences + extracts copyright) is **not** bundled in
> `ort-minimal` and was not run, so ORT's licences here are *declared* only — the same
> basis we use. A full ORT run would add concluded licences + copyright that we cannot match.

## 1. Document-level

| Field | Ours | ORT |
|-------|------|-----|
| specVersion | 1.6 | 1.6 |
| `$schema` | present | absent |
| serialNumber | content-derived (reproducible) | random each run |
| metadata.timestamp | `1970-01-01T00:00:00Z` (reproducible) | real wall-clock |
| metadata.tools | `tylerbutler/licence_audit 0.6.0` | `OSS Review Toolkit 74.0.0` |
| metadata.authors | `tylerbutler` | absent |
| metadata.lifecycles | `[{phase: build}]` | `null` |
| root component type | `application` | `file` |
| root component purl | `pkg:github/tylerbutler/licence_audit` | `null` |
| root licences/description | yes (from gleam.toml) | no |
| dependencies graph | 35 nodes | 25 nodes |

**Takeaways:** ours is reproducible and has a richer, properly-typed root component
(`application` + purl + licence + description). ORT's root is an untyped `file` with no purl.

## 2. Component coverage

- 26 Hex packages in common.
- **Only in ours (9):** `glance`, `gleam_time`, `gleescript`, `gleeunit`, `glexer`,
  `glinter`, `tom`, plus the two git deps below. These are dev/test-scope deps — ORT omits
  them from components; we include them with the native `scope: optional` field.
- **Git deps diverge (provenance precision, not correctness):**
  - Ours: `pkg:github/tylerbutler/glint@c082b4af...` — pins the **exact git commit**.
  - ORT: `pkg:otp/glint@1.3.0`, `pkg:otp/glint_markdown@0.0.0`.
  - Correction vs my first pass: `pkg:otp` **is** a registered purl type for BEAM/OTP apps,
    and the `0.0.0` version comes from the manifest (it is in *our* output too), so neither is
    a bug. The real difference: **ours encodes the resolved commit SHA**; ORT's `pkg:otp` purl
    carries no commit pin and no `repository_url` qualifier, so the git origin is not
    recoverable from the purl. For a git-sourced dep that is a meaningful provenance advantage,
    but it is precision, not ORT being "wrong."

## 3. Per-component fields (example: `gleam_stdlib@1.0.3`)

| Field | Ours | ORT |
|-------|------|-----|
| bom-ref / purl | `pkg:hex/gleam_stdlib@1.0.3` | `Hex::gleam_stdlib:1.0.3` ref; purl has `?classifier=sources` |
| supplier | `{name: Hex, url:[hex.pm/...]}` (registry) | `{contact:[{name: Louis Pilfold ...}]}` (author, semantically odd) |
| publisher | `lpil` | — (uses `authors` instead) |
| description | yes | yes |
| hashes (SHA-256) | yes (outer Hex checksum) | yes (same value) |
| licence | id `Apache-2.0` + `acknowledgement: declared` | id `Apache-2.0` + **full licence text** + `ort:origin` property |
| externalReferences | tarball (distribution) + repo (vcs) + sponsor + website | website only |
| scope | `scope: required` (native CycloneDX field) | `scope: required` (native CycloneDX field) |
| extra | `licence_audit:hex_inner_checksum` property | `ort:dependencyType`, `group`, `modified` |

**Where ORT is richer:**
- Embeds the **full licence text** in each component (`licenses[].license.text`).

**Where we are richer:**
- More `externalReferences` (tarball distribution, VCS repo, website, sponsor) vs ORT's single website.
- `supplier` = the Hex registry (the actual artifact source) which is the correct CycloneDX
  semantics (supplier = "the organization that supplied the component... distributor or
  repackager"); ORT puts the package **author** (Louis Pilfold) in `supplier.contact` *and*
  in `authors` — duplicating the author and conflating supplier with author.
- Hex outer + inner checksums; commit-pinned `pkg:github` purl for git deps.

## 4. Copyright

- ORT (this run): **0** copyright statements — requires the unrun `scan` stage.
- Ours: none (by design — we report *declared* licences from Hex metadata, never scan source).
- A full ORT pipeline (`scan`) would surface copyright holders + concluded licences, which is
  the one substantive capability gap. It costs a multi-minute source download + ScanCode run.

## 5. Quality scores (same pinned tooling)

| Scorer | Ours | ORT |
|--------|------|-----|
| `sbomqs` | **7.3/10 (C)** | 6.6/10 (D) |
| `sbom-tools quality` | **87.8/100 (B)** | parse error: "missing field `name`" |

`sbom-tools` *rejects* ORT's document (a licence/component entry lacks a `name`), while it
rates ours COMPLIANT. Ours scores higher on `sbomqs` too.

## 6. Where ORT is ahead (tracked issues)

Each place ORT's output leads ours has a tracking issue:

| Gap | Issue |
|-----|-------|
| ~~Native CycloneDX `scope` field vs our custom `licence_audit:scope` property~~ (resolved: we now emit native `scope`) | [#37](https://github.com/tylerbutler/licence_audit/issues/37) |
| Embed licence text in `licenses[].license.text` | [#38](https://github.com/tylerbutler/licence_audit/issues/38) |
| Optional SPDX output format | [#39](https://github.com/tylerbutler/licence_audit/issues/39) |
| Concluded licences + copyright via source scanning (declared-only gap) | [#40](https://github.com/tylerbutler/licence_audit/issues/40) |

## 7. Recommendations

1. **No tooling switch needed.** Our native generator has correct CycloneDX `supplier`
   semantics, richer external references, commit-pinned git purls, reproducible output, and
   scores higher on both quality tools.
2. **Document the declared-vs-concluded caveat** in our README/SBOM docs: we report *declared*
   licences only, matching `ort-minimal` without `scan`. Full ORT + ScanCode adds *concluded*
   licences + copyright. Tracked in [#40](https://github.com/tylerbutler/licence_audit/issues/40).
3. **Adopt the portable ORT-native ideas**: native `scope`
   ([#37](https://github.com/tylerbutler/licence_audit/issues/37), done) and licence text
   ([#38](https://github.com/tylerbutler/licence_audit/issues/38)).
4. **SPDX output** is the one format the guide produces that we don't —
   [#39](https://github.com/tylerbutler/licence_audit/issues/39).

## Reproduce

`just` recipes wrap the whole flow (requires Docker; output lands in the gitignored
`ort-result/`):

```sh
just sbom-generate   # ours  -> dist/sbom.json
just ort-sbom        # ORT   -> ort-result/bom.cyclonedx.json  (analyze + report)
just ort-compare     # regenerate both and print a purl coverage diff
just ort-clean       # remove ort-result/
```

The underlying ORT commands (run as the host user so the container can write the mounted
output dir):

```sh
docker run --rm -u "$(id -u):$(id -g)" -v "$(pwd)":/workspace -w /workspace \
  ghcr.io/oss-review-toolkit/ort-minimal:74.0.0 \
  analyze --input-dir /workspace --output-dir /workspace/ort-result
docker run --rm -u "$(id -u):$(id -g)" -v "$(pwd)":/workspace -w /workspace \
  ghcr.io/oss-review-toolkit/ort-minimal:74.0.0 \
  report --ort-file /workspace/ort-result/analyzer-result.yml \
  --output-dir /workspace/ort-result -f CycloneDx -O CycloneDX=output.file.formats=json
```

ORT exits non-zero on unresolved issues (this repo's `test/fixtures/gleam.toml` is a
deliberately malformed manifest it cannot parse); the recipes tolerate that and assert the
expected artifact was written.

## Citations / sources

Claims about where we win or where ORT diverges, with sources.

### `supplier` = registry vs ORT putting the author there
- **Spec:** CycloneDX 1.6 schema, `component.supplier`: *"The organization that supplied the
  component. The supplier may often be the manufacturer, but may also be a distributor or
  repackager."* vs `component.authors`: *"The person(s) who created the component."*
  (`schema/bom-1.6.schema.json`, `definitions.component.properties.supplier` / `.authors`).
- **Ours (evidence):** `dist/sbom.json` `gleam_stdlib.supplier` =
  `{"name":"Hex","url":["https://hex.pm/packages/gleam_stdlib"]}` — the distributor. Source:
  `src/licence_audit/sbom.gleam:458-481` (`append_supplier`, emits the Hex registry) and
  `:486-495` (`append_publisher`, author goes to `publisher`).
- **ORT (evidence):** `ort-result/bom.cyclonedx.json` `gleam_stdlib` has
  `supplier.contact=[{name:"Louis Pilfold <louis@lpil.uk>"}]` **and** `authors=[{name:"Louis
  Pilfold ..."}]` — the author duplicated into `supplier`, which the spec reserves for the
  supplying organization.

### Git-dep provenance: commit pin vs no pin
- **Spec:** purl `otp` type is registered (BEAM/OTP apps): purl-spec
  `docs/types/definitions/otp-definition.md` ("BEAM/OTP applications written in Elixir,
  Erlang, Gleam..."); `github` and `hex` are registered too (`purl-types-index.json`). So
  `pkg:otp` is valid — not a defect.
- **Ours (evidence):** `pkg:github/tylerbutler/glint@c082b4afef5dc35bacaf03a2921284c527e6afeb`
  (commit-pinned). Source: `src/licence_audit/sbom.gleam:14-31` (`GitProvenance` ->
  `pkg:github/<owner>/<name>@<commit>`).
- **ORT (evidence):** `pkg:otp/glint@1.3.0` — no commit and no `repository_url` qualifier, so
  the git origin is not recoverable from the purl. (`0.0.0` for glint_markdown appears in both
  outputs; it is a manifest value, not an ORT artefact.)

### `scope` as a native field (resolved — both native now)
- **Spec:** CycloneDX 1.6 `component.scope` enum `["required","optional","excluded"]`, default
  `required` (`definitions.component.properties.scope`). ORT emits this natively
  (`gleam_stdlib.scope="required"`). We originally emitted a custom
  `properties[].name="licence_audit:scope"` property; since
  [#37](https://github.com/tylerbutler/licence_audit/issues/37) we emit the native field too
  (prod -> `required`, dev -> `optional`; `append_scope` in `src/licence_audit/sbom.gleam`).

### More externalReferences
- **Ours (evidence):** `gleam_stdlib` has 4 refs (distribution tarball, vcs repo, sponsor,
  website). Source: `src/licence_audit/sbom.gleam:587-627` (`external_references` +
  `hex_distribution_reference`) and `:631-644` (`reference_type` mapping).
- **ORT (evidence):** `gleam_stdlib.externalReferences` = website only.

### Quality scores (same pinned tooling, from this run)
- `sbomqs score`: ours **7.3/10 (C)** vs ORT **6.6/10 (D)**.
- `sbom-tools quality`: ours **87.8/100 (B), COMPLIANT**; ORT **fails to parse** —
  `Parse failed ... missing field `name` at line 39 column 7`. Runner: justfile `sbom-score`
  (`sbom-tools quality`, `sbomqs score`), justfile:108-110.

### Both valid CycloneDX 1.6
- `cyclonedx validate` and `sbom-utility validate` pass for **both** files (justfile
  `sbom-validate`, justfile:100-103). The quality-score gaps above are independent of schema
  validity.

### Declared vs concluded licences (the genuine ORT-pipeline advantage)
- ORT this run embedded **declared** licence text with property `ort:origin="declared
  license"` and produced **0** copyright statements (`scan` stage not run; `ort-minimal` has no
  ScanCode). A full ORT analyze->scan->report run would add *concluded* licences + copyright,
  which our metadata-only approach (declared Hex licences, `acknowledgement:"declared"`,
  `src/licence_audit/sbom.gleam:646-664`) does not attempt.
