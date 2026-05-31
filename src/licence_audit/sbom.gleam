import gleam/list
import gleam/option
import gleam/regexp
import gleam/string
import licence_audit/error
import licence_audit/manifest

pub fn purl_for(entry: manifest.SbomEntry) -> Result(String, error.Error) {
  case entry.provenance {
    manifest.HexProvenance(_) ->
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

pub type RootComponent {
  RootComponent(name: String, version: String)
}

pub type SbomInput {
  SbomInput(
    manifest: manifest.SbomManifest,
    root: RootComponent,
    tool_version: String,
    serial_number: String,
    timestamp: String,
    license_metadata: Dict(String, List(String)),
    scopes: Dict(String, manifest.Scope),
  )
}

/// Returns the rendered JSON, or an `Error` if any entry has an unsupported
/// source for purl generation.
pub fn try_render(input: SbomInput) -> Result(String, error.Error) {
  use components <- result.try(
    list.try_map(input.manifest.entries, fn(entry) {
      build_component(entry, input.license_metadata, input.scopes)
    }),
  )
  let dependencies = build_dependencies(input.manifest)
  let document = build_document(input, components, dependencies)
  Ok(json.to_string(document))
}

/// Convenience wrapper that panics on unsupported-source errors. Used in
/// tests with pre-validated input.
pub fn render(input: SbomInput) -> String {
  let assert Ok(rendered) = try_render(input)
  rendered
}

fn build_component(
  entry: manifest.SbomEntry,
  license_metadata: Dict(String, List(String)),
  scopes: Dict(String, manifest.Scope),
) -> Result(json.Json, error.Error) {
  use purl <- result.try(purl_for(entry))
  let base_fields = [
    #("bom-ref", json.string(purl)),
    #("type", json.string("library")),
    #("name", json.string(entry.name)),
    #("version", json.string(entry.version)),
    #("purl", json.string(purl)),
  ]
  let with_hashes = case entry.provenance {
    manifest.HexProvenance(checksum) ->
      list.append(base_fields, [
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
    _ -> base_fields
  }
  let final_fields = case dict.get(license_metadata, entry.name) {
    Ok(raws) ->
      case license_entries(raws) {
        [] -> with_hashes
        entries ->
          list.append(with_hashes, [
            #(
              "licenses",
              json.preprocessed_array(list.map(entries, license_to_json)),
            ),
          ])
      }
    Error(_) -> with_hashes
  }
  let scope = case dict.get(scopes, entry.name) {
    Ok(scope) -> scope
    Error(_) -> manifest.Prod
  }
  let with_properties =
    list.append(final_fields, [
      #(
        "properties",
        json.preprocessed_array([
          json.object([
            #("name", json.string("licence_audit:scope")),
            #("value", json.string(manifest.scope_label(scope))),
          ]),
        ]),
      ),
    ])
  Ok(json.object(with_properties))
}

fn license_to_json(entry: LicenseEntry) -> json.Json {
  case entry {
    LicenseId(id) ->
      json.object([
        #("license", json.object([#("id", json.string(id))])),
      ])
    LicenseName(name) ->
      json.object([
        #("license", json.object([#("name", json.string(name))])),
      ])
  }
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
    #("dependsOn", json.array(deps, of: json.string)),
  ])
}

fn build_document(
  input: SbomInput,
  components: List(json.Json),
  dependencies: List(json.Json),
) -> json.Json {
  json.object([
    #("bomFormat", json.string("CycloneDX")),
    #("specVersion", json.string("1.5")),
    #("serialNumber", json.string(input.serial_number)),
    #("version", json.int(1)),
    #(
      "metadata",
      json.object([
        #("timestamp", json.string(input.timestamp)),
        #(
          "tools",
          json.preprocessed_array([
            json.object([
              #("vendor", json.string("tylerbutler")),
              #("name", json.string("licence_audit")),
              #("version", json.string(input.tool_version)),
            ]),
          ]),
        ),
        #(
          "component",
          json.object([
            #("bom-ref", json.string("root")),
            #("type", json.string("application")),
            #("name", json.string(input.root.name)),
            #("version", json.string(input.root.version)),
          ]),
        ),
      ]),
    ),
    #("components", json.preprocessed_array(components)),
    #("dependencies", json.preprocessed_array(dependencies)),
  ])
}
