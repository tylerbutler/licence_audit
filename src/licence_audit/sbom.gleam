import gleam/list
import gleam/option
import gleam/regexp
import gleam/string
import licence_audit/error
import licence_audit/hex
import licence_audit/manifest
import licence_audit/osv

pub fn purl_for(entry: manifest.SbomEntry) -> Result(String, error.Error) {
  case entry.provenance {
    manifest.HexProvenance(_, _) ->
      Ok("pkg:hex/" <> entry.name <> "@" <> entry.version)
    manifest.GitProvenance(repo, commit) ->
      case parse_github_repo(repo) {
        Ok(#(owner, name)) ->
          Ok("pkg:github/" <> owner <> "/" <> name <> "@" <> commit)
        Error(_) ->
          Error(error.UnsupportedSourceForSbom(
            package: entry.name,
            source: "git",
            detail: "repo: " <> repo,
          ))
      }
    manifest.PathProvenance(path) ->
      Error(error.UnsupportedSourceForSbom(
        package: entry.name,
        source: "path",
        detail: "path: " <> path,
      ))
    manifest.UnknownProvenance(source) ->
      Error(error.UnsupportedSourceForSbom(
        package: entry.name,
        source: source,
        detail: "unsupported source",
      ))
  }
}

fn parse_github_repo(repo: String) -> Result(#(String, String), Nil) {
  let assert Ok(re) =
    regexp.from_string(
      "^(?:https?://|git@)github\\.com[:/]([^/]+)/([^/]+?)(?:\\.git)?/?$",
    )
  case regexp.scan(with: re, content: repo) {
    [match, ..] ->
      case match.submatches {
        [owner_opt, name_opt] ->
          case owner_opt, name_opt {
            option.Some(owner), option.Some(name) -> Ok(#(owner, name))
            _, _ -> Error(Nil)
          }
        _ -> Error(Nil)
      }
    [] -> Error(Nil)
  }
}

pub type LicenseEntry {
  LicenseId(id: String)
  LicenseName(name: String)
}

const spdx_ids = [
  "0BSD", "AGPL-3.0-only", "AGPL-3.0-or-later", "Apache-1.1", "Apache-2.0",
  "BSD-2-Clause", "BSD-3-Clause", "BSL-1.0", "CC0-1.0", "CC-BY-4.0",
  "CC-BY-SA-4.0", "EPL-1.0", "EPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
  "GPL-3.0-only", "GPL-3.0-or-later", "ISC", "LGPL-2.1-only",
  "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later", "MIT", "MIT-0",
  "MPL-1.1", "MPL-2.0", "Unlicense", "WTFPL", "Zlib",
]

/// Map raw declared licence strings to CycloneDX licence entries, one per
/// declared licence. When a package declares more than one, they are emitted as
/// separate entries: Hex does not record whether the relationship is
/// conjunctive ("AND") or disjunctive ("OR"), so we do not synthesise an SPDX
/// expression that would assert an operator we cannot verify.
pub fn license_entries(licences: List(String)) -> List(LicenseEntry) {
  list.map(licences, fn(raw) {
    case match_spdx(raw) {
      Ok(canonical) -> LicenseId(canonical)
      Error(_) -> LicenseName(raw)
    }
  })
}

fn match_spdx(raw: String) -> Result(String, Nil) {
  let lower = string.lowercase(raw)
  list.find(spdx_ids, fn(id) { string.lowercase(id) == lower })
}

import gleam/dict.{type Dict}
import gleam/json
import gleam/result
import licence_audit/sbom_uuid

pub type RootComponent {
  RootComponent(
    name: String,
    version: String,
    /// Project summary from the root `gleam.toml` `description`, if any.
    description: option.Option(String),
    /// Declared licences from the root `gleam.toml` `licences` array.
    licences: List(String),
    /// Project source URL (e.g. derived from a `repository` github table).
    repository: option.Option(String),
  )
}

/// How the BOM `serialNumber` is produced.
pub type SerialNumber {
  /// Use this exact `urn:uuid` string (a random v4 in normal runs).
  FixedSerial(String)
  /// Derive a deterministic `urn:uuid` from a hash of the BOM content, so the
  /// same dependency set always yields the same serial number.
  ContentDerivedSerial
}

/// An OSV advisory paired with the component `bom-ref`s (purls) it affects,
/// ready to be emitted into the CycloneDX `vulnerabilities` array. An empty
/// list of these on `SbomInput` omits the array entirely.
pub type EmbeddedVulnerability {
  EmbeddedVulnerability(vuln: osv.Vulnerability, affects: List(String))
}

pub type SbomInput {
  SbomInput(
    manifest: manifest.SbomManifest,
    root: RootComponent,
    tool_version: String,
    serial_number: SerialNumber,
    timestamp: String,
    package_metadata: Dict(String, hex.PackageMetadata),
    scopes: Dict(String, manifest.Scope),
    /// Vulnerabilities to embed (CycloneDX `vulnerabilities`); empty omits it.
    vulnerabilities: List(EmbeddedVulnerability),
  )
}

/// Returns the rendered JSON, or an `Error` if any entry has an unsupported
/// source for purl generation.
pub fn try_render(input: SbomInput) -> Result(String, error.Error) {
  // Emit components and dependencies in a stable, content-defined order so the
  // output is canonical regardless of how the manifest happened to be ordered.
  let sorted_entries =
    list.sort(input.manifest.entries, by: fn(a, b) {
      string.compare(sort_key(a), sort_key(b))
    })
  let sorted_manifest =
    manifest.SbomManifest(..input.manifest, entries: sorted_entries)
  use components <- result.try(
    list.try_map(sorted_entries, fn(entry) {
      build_component(entry, input.package_metadata, input.scopes)
    }),
  )
  let dependencies = build_dependencies(sorted_manifest)
  let vulnerabilities = build_vulnerabilities(input.vulnerabilities)
  let serial = resolve_serial(input, components, dependencies, vulnerabilities)
  let document =
    build_document(input, serial, components, dependencies, vulnerabilities)
  Ok(json.to_string(document))
}

/// Sort key for a component: its purl when available, falling back to the
/// package name for sources without one.
fn sort_key(entry: manifest.SbomEntry) -> String {
  case purl_for(entry) {
    Ok(purl) -> purl
    Error(_) -> entry.name
  }
}

/// Resolve the BOM `serialNumber`: either the caller-supplied fixed value, or a
/// deterministic UUID derived from a hash of the rendered components and
/// dependencies plus the described project.
fn resolve_serial(
  input: SbomInput,
  components: List(json.Json),
  dependencies: List(json.Json),
  vulnerabilities: List(json.Json),
) -> String {
  case input.serial_number {
    FixedSerial(value) -> value
    ContentDerivedSerial -> {
      let content =
        json.to_string(json.preprocessed_array(components))
        <> json.to_string(json.preprocessed_array(dependencies))
        <> json.to_string(json.preprocessed_array(vulnerabilities))
        <> json.to_string(root_component_json(input.root))
        <> input.tool_version
      sbom_uuid.serial_number_from_content(content)
    }
  }
}

/// Convenience wrapper that panics on unsupported-source errors. Used in
/// tests with pre-validated input.
pub fn render(input: SbomInput) -> String {
  let assert Ok(rendered) = try_render(input)
  rendered
}

fn build_component(
  entry: manifest.SbomEntry,
  package_metadata: Dict(String, hex.PackageMetadata),
  scopes: Dict(String, manifest.Scope),
) -> Result(json.Json, error.Error) {
  use purl <- result.try(purl_for(entry))
  let metadata = dict.get(package_metadata, entry.name)

  let fields =
    [
      #("bom-ref", json.string(purl)),
      #("type", json.string("library")),
      #("name", json.string(entry.name)),
      #("version", json.string(entry.version)),
      #("purl", json.string(purl)),
    ]
    |> append_supplier(entry, metadata)
    |> append_publisher(metadata)
    |> append_description(metadata)
    |> append_hashes(entry)
    |> append_licenses(metadata)
    |> append_external_references(entry, metadata)
    |> append_properties(entry, scopes)

  Ok(json.object(fields))
}

type Field =
  #(String, json.Json)

fn append_description(
  fields: List(Field),
  metadata: Result(hex.PackageMetadata, Nil),
) -> List(Field) {
  case metadata {
    Ok(hex.PackageMetadata(description: option.Some(description), ..)) ->
      list.append(fields, [#("description", json.string(description))])
    _ -> fields
  }
}

/// CycloneDX `supplier` is the organisation that supplied the component. For
/// Hex packages that is always the Hex registry, so we emit a uniform
/// `{name: "Hex", url: ["https://hex.pm/packages/<name>"]}` object per Hex
/// component. Package owners/maintainers are surfaced separately via
/// `publisher`, so the two fields stay semantically distinct: supplier = where
/// the artefact came from, publisher = who authored/released it.
fn append_supplier(
  fields: List(Field),
  entry: manifest.SbomEntry,
  _metadata: Result(hex.PackageMetadata, Nil),
) -> List(Field) {
  case entry.provenance {
    manifest.HexProvenance(_, _) ->
      list.append(fields, [
        #(
          "supplier",
          json.object([
            #("name", json.string("Hex")),
            #(
              "url",
              json.preprocessed_array([
                json.string("https://hex.pm/packages/" <> entry.name),
              ]),
            ),
          ]),
        ),
      ])
    _ -> fields
  }
}

/// CycloneDX `publisher` is a single string identifying the person or
/// organisation that published the component. We populate it from Hex
/// `owners` (preferred) or `meta.maintainers`; see `hex.publisher_from_names`.
fn append_publisher(
  fields: List(Field),
  metadata: Result(hex.PackageMetadata, Nil),
) -> List(Field) {
  case metadata {
    Ok(hex.PackageMetadata(publisher: option.Some(publisher), ..)) ->
      list.append(fields, [#("publisher", json.string(publisher))])
    _ -> fields
  }
}

fn append_hashes(
  fields: List(Field),
  entry: manifest.SbomEntry,
) -> List(Field) {
  case entry.provenance {
    manifest.HexProvenance(checksum, _) ->
      list.append(fields, [
        #(
          "hashes",
          json.preprocessed_array([
            json.object([
              #("alg", json.string("SHA-256")),
              #("content", json.string(string.lowercase(checksum))),
            ]),
          ]),
        ),
      ])
    _ -> fields
  }
}

fn append_licenses(
  fields: List(Field),
  metadata: Result(hex.PackageMetadata, Nil),
) -> List(Field) {
  case metadata {
    Ok(meta) ->
      case license_entries(meta.licences) {
        [] -> fields
        entries ->
          list.append(fields, [
            #(
              "licenses",
              json.preprocessed_array(list.map(entries, license_to_json)),
            ),
          ])
      }
    Error(_) -> fields
  }
}

fn append_external_references(
  fields: List(Field),
  entry: manifest.SbomEntry,
  metadata: Result(hex.PackageMetadata, Nil),
) -> List(Field) {
  let links = case metadata {
    Ok(meta) -> meta.links
    Error(_) -> []
  }
  case external_references(entry, links) {
    [] -> fields
    refs ->
      list.append(fields, [
        #("externalReferences", json.preprocessed_array(refs)),
      ])
  }
}

fn append_properties(
  fields: List(Field),
  entry: manifest.SbomEntry,
  scopes: Dict(String, manifest.Scope),
) -> List(Field) {
  let scope = case dict.get(scopes, entry.name) {
    Ok(scope) -> scope
    Error(_) -> manifest.Prod
  }
  let scope_property =
    json.object([
      #("name", json.string("licence_audit:scope")),
      #("value", json.string(manifest.scope_label(scope))),
    ])
  // CycloneDX `hashes` cannot distinguish two SHA-256 entries (the schema
  // only allows `alg`/`content`), so the Hex inner checksum is surfaced as a
  // labelled property when present. The outer checksum stays in `hashes`
  // because that is the canonical artefact hash consumers verify against.
  let properties = case entry.provenance {
    manifest.HexProvenance(_, option.Some(inner)) -> [
      scope_property,
      json.object([
        #("name", json.string("licence_audit:hex_inner_checksum")),
        #("value", json.string(string.lowercase(inner))),
      ]),
    ]
    _ -> [scope_property]
  }
  list.append(fields, [#("properties", json.preprocessed_array(properties))])
}

/// Build CycloneDX `externalReferences` for a component: the Hex tarball as a
/// `distribution` reference (Hex packages only), followed by each Hex
/// `meta.links` entry mapped to a reference type. The original link label is
/// preserved as the reference `comment`.
fn external_references(
  entry: manifest.SbomEntry,
  links: List(#(String, String)),
) -> List(json.Json) {
  let from_links =
    list.map(links, fn(pair) {
      json.object([
        #("url", json.string(pair.1)),
        #("type", json.string(reference_type(pair.0))),
        #("comment", json.string(pair.0)),
      ])
    })
  case entry.provenance {
    manifest.HexProvenance(_, _) -> [
      hex_distribution_reference(entry),
      ..from_links
    ]
    _ -> from_links
  }
}

fn hex_distribution_reference(entry: manifest.SbomEntry) -> json.Json {
  json.object([
    #(
      "url",
      json.string(
        "https://repo.hex.pm/tarballs/"
        <> entry.name
        <> "-"
        <> entry.version
        <> ".tar",
      ),
    ),
    #("type", json.string("distribution")),
    #("comment", json.string("Hex package tarball")),
  ])
}

/// Map a Hex link label to a CycloneDX external-reference type. Unknown labels
/// fall back to `other` so no link is dropped.
fn reference_type(label: String) -> String {
  case string.lowercase(label) {
    "github"
    | "gitlab"
    | "bitbucket"
    | "source"
    | "repository"
    | "repo"
    | "vcs" -> "vcs"
    "website" | "homepage" | "home" -> "website"
    "docs" | "documentation" | "hexdocs" -> "documentation"
    _ -> "other"
  }
}

fn license_to_json(entry: LicenseEntry) -> json.Json {
  // `acknowledgement: declared` (CycloneDX 1.6) records that these licences are
  // as declared by the package's own metadata (Hex / gleam.toml), not concluded
  // by scanning the source.
  let fields = case entry {
    LicenseId(id) -> [#("id", json.string(id))]
    LicenseName(name) -> [#("name", json.string(name))]
  }
  json.object([
    #(
      "license",
      json.object(
        list.append(fields, [
          #("acknowledgement", json.string("declared")),
        ]),
      ),
    ),
  ])
}

fn build_dependencies(
  manifest_value: manifest.SbomManifest,
) -> List(json.Json) {
  let purl_index =
    list.fold(manifest_value.entries, dict.new(), fn(acc, entry) {
      case purl_for(entry) {
        Ok(purl) -> dict.insert(acc, entry.name, purl)
        Error(_) -> acc
      }
    })
  let root_entry =
    component_refs(
      "root",
      resolve_purls(manifest_value.root_requirements, purl_index),
    )
  let other_entries =
    list.filter_map(manifest_value.entries, fn(entry) {
      component_entry(entry, purl_index)
    })
  [root_entry, ..other_entries]
}

/// Map dependency names to their purls, dropping any not present in the index.
fn resolve_purls(
  names: List(String),
  purl_index: Dict(String, String),
) -> List(String) {
  list.filter_map(names, fn(name) { dict.get(purl_index, name) })
}

/// Build the `dependencies` entry for a single component, or `Error(Nil)` if
/// the entry has no purl (e.g. a non-Hex package).
fn component_entry(
  entry: manifest.SbomEntry,
  purl_index: Dict(String, String),
) -> Result(json.Json, Nil) {
  case purl_for(entry) {
    Error(_) -> Error(Nil)
    Ok(self_purl) ->
      Ok(component_refs(
        self_purl,
        resolve_purls(entry.requirements, purl_index),
      ))
  }
}

fn component_refs(ref: String, deps: List(String)) -> json.Json {
  json.object([
    #("ref", json.string(ref)),
    #("dependsOn", json.array(list.sort(deps, string.compare), of: json.string)),
  ])
}

const bom_vendor = "tylerbutler"

const bom_vendor_url = "https://github.com/tylerbutler/licence_audit"

/// Build the `metadata.component` object for the project being described,
/// enriching the bare name/version with whatever `gleam.toml` provided.
fn root_component_json(root: RootComponent) -> json.Json {
  [
    #("bom-ref", json.string("root")),
    #("type", json.string("application")),
    #("name", json.string(root.name)),
    #("version", json.string(root.version)),
  ]
  |> fn(fields) {
    case root.description {
      option.Some(description) ->
        list.append(fields, [#("description", json.string(description))])
      option.None -> fields
    }
  }
  |> fn(fields) {
    case license_entries(root.licences) {
      [] -> fields
      entries ->
        list.append(fields, [
          #(
            "licenses",
            json.preprocessed_array(list.map(entries, license_to_json)),
          ),
        ])
    }
  }
  |> fn(fields) {
    case root.repository {
      option.Some(url) ->
        list.append(fields, [
          #(
            "externalReferences",
            json.preprocessed_array([
              json.object([
                #("url", json.string(url)),
                #("type", json.string("vcs")),
              ]),
            ]),
          ),
        ])
      option.None -> fields
    }
  }
  |> json.object
}

fn build_document(
  input: SbomInput,
  serial: String,
  components: List(json.Json),
  dependencies: List(json.Json),
  vulnerabilities: List(json.Json),
) -> json.Json {
  let base = [
    #("bomFormat", json.string("CycloneDX")),
    #("specVersion", json.string("1.6")),
    #("serialNumber", json.string(serial)),
    #("version", json.int(1)),
    #(
      "metadata",
      json.object([
        #("timestamp", json.string(input.timestamp)),
        // SBOMs are produced from the locked manifest, i.e. the dependency set
        // used to build the project.
        #(
          "lifecycles",
          json.preprocessed_array([
            json.object([#("phase", json.string("build"))]),
          ]),
        ),
        #(
          "tools",
          json.preprocessed_array([
            json.object([
              #("vendor", json.string(bom_vendor)),
              #("name", json.string("licence_audit")),
              #("version", json.string(input.tool_version)),
            ]),
          ]),
        ),
        // The BOM is authored and supplied by the licence_audit maintainer,
        // independent of whichever project it describes.
        #(
          "authors",
          json.preprocessed_array([
            json.object([#("name", json.string(bom_vendor))]),
          ]),
        ),
        #(
          "supplier",
          json.object([
            #("name", json.string(bom_vendor)),
            #("url", json.preprocessed_array([json.string(bom_vendor_url)])),
          ]),
        ),
        #("component", root_component_json(input.root)),
      ]),
    ),
    #("components", json.preprocessed_array(components)),
    #("dependencies", json.preprocessed_array(dependencies)),
    // The locked manifest is the fully resolved dependency tree, so the graph
    // rooted at `root` is complete rather than partial.
    #(
      "compositions",
      json.preprocessed_array([
        json.object([
          #("aggregate", json.string("complete")),
          #("dependencies", json.preprocessed_array([json.string("root")])),
        ]),
      ]),
    ),
  ]
  // Only emit `vulnerabilities` when vulnerabilities were embedded, so a plain
  // SBOM keeps its existing shape.
  let fields = case vulnerabilities {
    [] -> base
    _ ->
      list.append(base, [
        #("vulnerabilities", json.preprocessed_array(vulnerabilities)),
      ])
  }
  json.object(fields)
}

/// Map each embedded advisory to a CycloneDX `vulnerabilities[]` entry,
/// emitted in a stable order by advisory id for canonical output.
fn build_vulnerabilities(
  vulnerabilities: List(EmbeddedVulnerability),
) -> List(json.Json) {
  vulnerabilities
  |> list.sort(by: fn(a, b) { string.compare(a.vuln.id, b.vuln.id) })
  |> list.map(vulnerability_json)
}

fn vulnerability_json(embedded: EmbeddedVulnerability) -> json.Json {
  let vuln = embedded.vuln
  let source =
    json.object([
      #("name", json.string("OSV")),
      #("url", json.string("https://osv.dev/vulnerability/" <> vuln.id)),
    ])
  let base = [
    #("bom-ref", json.string("vuln:" <> vuln.id)),
    #("id", json.string(vuln.id)),
    #("source", source),
    #("ratings", json.preprocessed_array(ratings_json(vuln))),
  ]
  let with_description = case vuln.summary {
    "" -> base
    summary -> list.append(base, [#("description", json.string(summary))])
  }
  let affects =
    embedded.affects
    |> list.sort(string.compare)
    |> list.map(fn(ref) { json.object([#("ref", json.string(ref))]) })
  json.object(
    list.append(with_description, [
      #("affects", json.preprocessed_array(affects)),
    ]),
  )
}

/// CycloneDX `ratings` for an advisory: one entry per CVSS vector reported by
/// OSV (with `method` + `vector`), or a single severity-only entry when OSV
/// gave no machine-readable vector. The advisory's resolved severity bucket is
/// used as the `severity` in all cases, since OSV's `database_specific` label
/// (when present) is authoritative.
fn ratings_json(vuln: osv.Vulnerability) -> List(json.Json) {
  let severity = json.string(osv.severity_to_string(vuln.severity))
  let osv_source = json.object([#("name", json.string("OSV"))])
  case vuln.scores {
    [] -> [json.object([#("source", osv_source), #("severity", severity)])]
    scores ->
      list.map(scores, fn(score) {
        json.object([
          #("source", osv_source),
          #("method", json.string(cvss_method(score.kind, score.vector))),
          #("vector", json.string(score.vector)),
          #("severity", severity),
        ])
      })
  }
}

/// Map an OSV CVSS score to a CycloneDX `ratings.method` enum value. The vector
/// string's version prefix is authoritative when present (CVSS v2 vectors carry
/// no prefix); otherwise we fall back to the OSV score `type`.
fn cvss_method(kind: String, vector: String) -> String {
  let upper = string.uppercase(vector)
  case
    string.contains(upper, "CVSS:3.1"),
    string.contains(upper, "CVSS:3.0"),
    string.contains(upper, "CVSS:4.0")
  {
    True, _, _ -> "CVSSv31"
    _, True, _ -> "CVSSv3"
    _, _, True -> "CVSSv4"
    _, _, _ ->
      case string.uppercase(kind) {
        "CVSS_V4" -> "CVSSv4"
        "CVSS_V3" -> "CVSSv3"
        "CVSS_V2" -> "CVSSv2"
        _ -> "other"
      }
  }
}
