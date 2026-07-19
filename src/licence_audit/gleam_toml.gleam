//// Reusable parser for a dependency's `gleam.toml`.
////
//// Git and path dependencies have no Hex registry metadata, but their checked
//// out source tree carries a `gleam.toml` with `description`, `licences`, and
//// `links`. This module extracts those into a `hex.PackageMetadata` value so
//// the SBOM and notices flows can treat local and Hex-sourced metadata
//// uniformly. The repository link is always the caller-supplied `repo_url`
//// (the manifest-recorded source), not gleam.toml's declared `repository`,
//// which may point at an upstream project for a fork.

import gleam/bool
import gleam/list
import gleam/option
import gleam/result
import gleam/string

import licence_audit/hex
import licence_audit/toml

/// Build package metadata from a dependency's `gleam.toml` contents, mirroring
/// the fields Hex enrichment provides (minus publisher, which gleam.toml
/// lacks).
pub fn package_metadata(
  contents: String,
  repo_url: String,
) -> Result(hex.PackageMetadata, Nil) {
  use doc <- result.try(toml.parse(contents))
  let description = option.from_result(toml.get_string(doc, ["description"]))
  let licences = declared_licences(doc)
  let links = append_repo_link(links(doc), repo_url)
  Ok(hex.PackageMetadata(
    licences:,
    description:,
    links:,
    publisher: option.None,
  ))
}

/// Read the `licences` array from a parsed `gleam.toml`, dropping non-string
/// entries. Returns `[]` when the key is absent or not an array.
pub fn declared_licences(doc: toml.Document) -> List(String) {
  case toml.get_array(doc, ["licences"]) {
    Ok(items) -> list.filter_map(items, toml.as_string)
    Error(_) -> []
  }
}

/// Parse a gleam.toml `links = [{ title, href }]` array into `#(title, href)`
/// pairs, skipping malformed entries.
pub fn links(doc: toml.Document) -> List(#(String, String)) {
  case toml.get_array(doc, ["links"]) {
    Ok(items) ->
      list.filter_map(items, fn(value) {
        use entry <- result.try(toml.as_table(value))
        use title <- result.try(result.try(
          toml.field(entry, "title"),
          toml.as_string,
        ))
        use href <- result.try(result.try(
          toml.field(entry, "href"),
          toml.as_string,
        ))
        Ok(#(title, href))
      })
    Error(_) -> []
  }
}

/// Append the repository link unless an equivalent URL is already present
/// (comparing with any trailing `.git` stripped).
fn append_repo_link(
  links: List(#(String, String)),
  repo_url: String,
) -> List(#(String, String)) {
  let already_present =
    list.any(links, fn(pair) { strip_git_suffix(pair.1) == repo_url })
  use <- bool.guard(when: already_present, return: links)
  list.append(links, [#("Repository", repo_url)])
}

/// Drop a trailing `.git` suffix from a URL, if present.
pub fn strip_git_suffix(url: String) -> String {
  use <- bool.guard(when: !string.ends_with(url, ".git"), return: url)
  string.drop_end(url, 4)
}
