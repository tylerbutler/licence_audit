import gleam/dict.{type Dict}
import gleam/list
import gleam/result
import gleam/string
import licence_audit/toml
import simplifile
import tomlet.{type Document, type Value}

pub type Source {
  Hex
}

/// Where a package sits in the resolved dependency tree relative to the
/// project. `Direct` packages are listed in the manifest's `[requirements]`
/// table; everything else is `Transitive`.
pub type Kind {
  Direct
  Transitive
}

pub type Package {
  Package(
    name: String,
    version: String,
    source: Source,
    kind: Kind,
    requirements: List(String),
  )
}

/// A node in the full dependency graph. Includes non-Hex packages so that
/// dependency paths can render correctly through git/path deps even though
/// those packages are not audited for licences.
pub type GraphNode {
  GraphNode(name: String, requirements: List(String))
}

pub type LockedPackages {
  LockedPackages(
    packages: List(Package),
    skipped_non_hex: Int,
    skipped_packages: List(SkippedPackage),
    direct_names: List(String),
    graph: List(GraphNode),
  )
}

/// A package present in the lockfile but excluded from licence auditing
/// because it isn't sourced from Hex (e.g. git or path deps). Still surfaced
/// in the dependency tree so the structure of the graph is visible.
pub type SkippedPackage {
  SkippedPackage(
    name: String,
    version: String,
    source: String,
    kind: Kind,
    requirements: List(String),
  )
}

pub type Error {
  InvalidToml(String)
  MissingPackages
  InvalidPackageField(package: String, field: String, expected: String)
  FileReadError(String)
}

pub type Provenance {
  HexProvenance(outer_checksum: String)
  GitProvenance(repo: String, commit: String)
  PathProvenance(path: String)
  UnknownProvenance(source: String)
}

pub type SbomEntry {
  SbomEntry(
    name: String,
    version: String,
    kind: Kind,
    requirements: List(String),
    provenance: Provenance,
  )
}

pub type SbomManifest {
  SbomManifest(entries: List(SbomEntry), root_requirements: List(String))
}

pub fn sbom_entries(input: String) -> Result(SbomManifest, Error) {
  case toml.parse(input) {
    Error(_) -> Error(InvalidToml("Invalid TOML"))
    Ok(document) -> sbom_entries_from_document(document)
  }
}

fn sbom_entries_from_document(
  document: Document,
) -> Result(SbomManifest, Error) {
  case toml.get_array(document, ["packages"]) {
    Error(toml.ArrayMissing) -> Error(MissingPackages)
    Error(toml.ArrayNotArray) ->
      Error(InvalidPackageField("<manifest>", "packages", "Array"))
    Ok(packages) -> {
      let direct_names = decode_direct_names(document)
      use entries <- result.try(
        list.try_map(packages, fn(package) {
          decode_sbom_entry(package, direct_names)
        }),
      )
      Ok(SbomManifest(entries: entries, root_requirements: direct_names))
    }
  }
}

pub fn load_sbom(path: String) -> Result(SbomManifest, Error) {
  case simplifile.read(from: path) {
    Ok(contents) -> sbom_entries(contents)
    Error(_) -> Error(FileReadError(path))
  }
}

fn decode_sbom_entry(
  package: Value,
  direct_names: List(String),
) -> Result(SbomEntry, Error) {
  case toml.as_table(package) {
    Error(_) ->
      Error(InvalidPackageField(
        package: "<unknown>",
        field: "package",
        expected: "Table",
      ))
    Ok(table) -> {
      use source <- result.try(required_string(table, "source", "<unknown>"))
      use name <- result.try(required_string(table, "name", "<unknown>"))
      use version <- result.try(required_string(table, "version", name))
      use requirements <- result.try(optional_string_list(
        table,
        "requirements",
        name,
      ))
      use provenance <- result.try(decode_provenance(source, table, name))
      let kind = case list.contains(direct_names, name) {
        True -> Direct
        False -> Transitive
      }
      Ok(SbomEntry(
        name: name,
        version: version,
        kind: kind,
        requirements: requirements,
        provenance: provenance,
      ))
    }
  }
}

fn decode_provenance(
  source: String,
  table: toml.Entry,
  package_name: String,
) -> Result(Provenance, Error) {
  case source {
    "hex" -> {
      use checksum <- result.try(required_string(
        table,
        "outer_checksum",
        package_name,
      ))
      Ok(HexProvenance(outer_checksum: checksum))
    }
    "git" -> {
      use repo <- result.try(required_string(table, "repo", package_name))
      use commit <- result.try(required_string(table, "commit", package_name))
      Ok(GitProvenance(repo: repo, commit: commit))
    }
    "path" -> {
      use path <- result.try(required_string(table, "path", package_name))
      Ok(PathProvenance(path: path))
    }
    other -> Ok(UnknownProvenance(source: other))
  }
}

type RawPackage {
  RawPackage(
    name: String,
    version: String,
    source: String,
    source_kind: SourceKind,
    requirements: List(String),
  )
}

type SourceKind {
  HexSource
  NonHexSource
}

pub fn load(path: String) -> Result(LockedPackages, Error) {
  case simplifile.read(from: path) {
    Ok(contents) -> parse(contents)
    Error(_) -> Error(FileReadError(path))
  }
}

pub fn parse(input: String) -> Result(LockedPackages, Error) {
  case toml.parse(input) {
    Error(_) -> Error(InvalidToml("Invalid TOML"))
    Ok(document) -> {
      case toml.get_array(document, ["packages"]) {
        Error(toml.ArrayMissing) -> Error(MissingPackages)
        Error(toml.ArrayNotArray) ->
          Error(InvalidPackageField("<manifest>", "packages", "Array"))
        Ok(packages) -> {
          use raw_packages <- result.try(list.try_map(packages, decode_package))
          let direct_names = decode_direct_names(document)
          Ok(build_locked(raw_packages, direct_names))
        }
      }
    }
  }
}

fn build_locked(
  raw_packages: List(RawPackage),
  direct_names: List(String),
) -> LockedPackages {
  let direct_set =
    list.fold(direct_names, dict.new(), fn(acc, name) {
      dict.insert(acc, name, Nil)
    })

  let #(hex_packages, skipped, skipped_pkgs, graph) =
    list.fold(raw_packages, #([], 0, [], []), fn(acc, raw) {
      let #(hex_acc, skipped_acc, skipped_pkgs_acc, graph_acc) = acc
      let node = GraphNode(name: raw.name, requirements: raw.requirements)
      let kind = case dict.has_key(direct_set, raw.name) {
        True -> Direct
        False -> Transitive
      }
      case raw.source_kind {
        HexSource -> {
          let package =
            Package(
              name: raw.name,
              version: raw.version,
              source: Hex,
              kind: kind,
              requirements: raw.requirements,
            )
          #([package, ..hex_acc], skipped_acc, skipped_pkgs_acc, [
            node,
            ..graph_acc
          ])
        }
        NonHexSource -> {
          let skipped_pkg =
            SkippedPackage(
              name: raw.name,
              version: raw.version,
              source: raw.source,
              kind: kind,
              requirements: raw.requirements,
            )
          #(hex_acc, skipped_acc + 1, [skipped_pkg, ..skipped_pkgs_acc], [
            node,
            ..graph_acc
          ])
        }
      }
    })

  LockedPackages(
    packages: list.reverse(hex_packages),
    skipped_non_hex: skipped,
    skipped_packages: list.reverse(skipped_pkgs),
    direct_names: direct_names,
    graph: list.reverse(graph),
  )
}

/// Compute the shortest dependency path from any direct dependency to every
/// reachable package in the locked graph.
///
/// The path is inclusive of both endpoints: for a direct dependency `A`, the
/// path is `["A"]`; for a transitive `C` reached via `A -> B -> C`, the path
/// is `["A", "B", "C"]`. Multi-source BFS from all direct deps guarantees
/// shortest length; ties are broken by the order packages appear in the
/// manifest.
///
/// Packages with no incoming edges from a direct dep (orphans, which a
/// well-formed lockfile should not contain) are omitted.
pub fn dep_paths(locked: LockedPackages) -> Dict(String, List(String)) {
  let edges =
    list.fold(locked.graph, dict.new(), fn(acc, node) {
      dict.insert(acc, node.name, node.requirements)
    })

  let nodes =
    list.fold(locked.graph, dict.new(), fn(acc, node) {
      dict.insert(acc, node.name, Nil)
    })

  let sources =
    list.filter(locked.direct_names, fn(name) { dict.has_key(nodes, name) })

  let visited =
    list.fold(sources, dict.new(), fn(acc, name) { dict.insert(acc, name, Nil) })

  let #(visited, parents) = bfs_loop(sources, edges, visited, dict.new())

  dict.keys(visited)
  |> list.fold(dict.new(), fn(acc, name) {
    dict.insert(acc, name, reconstruct_path(name, parents, []))
  })
}

fn bfs_loop(
  frontier: List(String),
  edges: Dict(String, List(String)),
  visited: Dict(String, Nil),
  parents: Dict(String, String),
) -> #(Dict(String, Nil), Dict(String, String)) {
  case frontier {
    [] -> #(visited, parents)
    _ -> {
      let #(next_rev, visited, parents) =
        list.fold(frontier, #([], visited, parents), fn(acc, node) {
          let #(next, visited, parents) = acc
          let children = case dict.get(edges, node) {
            Ok(reqs) -> reqs
            Error(_) -> []
          }
          visit_children(node, children, #(next, visited, parents))
        })
      bfs_loop(list.reverse(next_rev), edges, visited, parents)
    }
  }
}

/// Visit each child of `node`, queueing and recording any not yet seen.
/// Threads the BFS accumulator `#(next_frontier, visited, parents)`.
fn visit_children(
  node: String,
  children: List(String),
  acc: #(List(String), Dict(String, Nil), Dict(String, String)),
) -> #(List(String), Dict(String, Nil), Dict(String, String)) {
  list.fold(children, acc, fn(inner, child) {
    let #(next, visited, parents) = inner
    case dict.has_key(visited, child) {
      True -> #(next, visited, parents)
      False -> #(
        [child, ..next],
        dict.insert(visited, child, Nil),
        dict.insert(parents, child, node),
      )
    }
  })
}

fn reconstruct_path(
  name: String,
  parents: Dict(String, String),
  acc: List(String),
) -> List(String) {
  case dict.get(parents, name) {
    Error(_) -> [name, ..acc]
    Ok(parent) -> reconstruct_path(parent, parents, [name, ..acc])
  }
}

fn decode_direct_names(document: Document) -> List(String) {
  case toml.table_keys(document, ["requirements"]) {
    Ok(keys) -> list.sort(keys, by: string.compare)
    Error(_) -> []
  }
}

fn decode_package(package: Value) -> Result(RawPackage, Error) {
  case toml.as_table(package) {
    Error(_) ->
      Error(InvalidPackageField(
        package: "<unknown>",
        field: "package",
        expected: "Table",
      ))

    Ok(package) -> {
      use source <- result.try(required_string(package, "source", "<unknown>"))
      use name <- result.try(required_string(package, "name", "<unknown>"))
      use version <- result.try(required_string(package, "version", name))
      use requirements <- result.try(optional_string_list(
        package,
        "requirements",
        name,
      ))
      let source_kind = case source {
        "hex" -> HexSource
        _ -> NonHexSource
      }
      Ok(RawPackage(
        name: name,
        version: version,
        source: source,
        source_kind: source_kind,
        requirements: requirements,
      ))
    }
  }
}

fn optional_string_list(
  package: toml.Entry,
  field: String,
  package_name: String,
) -> Result(List(String), Error) {
  case toml.field(package, field) {
    Error(_) -> Ok([])
    Ok(value) ->
      case toml.as_array(value) {
        Error(_) ->
          Error(InvalidPackageField(
            package: package_name,
            field: field,
            expected: "Array",
          ))
        Ok(items) -> decode_string_list(items, package_name, field, [])
      }
  }
}

fn decode_string_list(
  items: List(Value),
  package_name: String,
  field: String,
  acc: List(String),
) -> Result(List(String), Error) {
  case items {
    [] -> Ok(list.reverse(acc))
    [item, ..rest] ->
      case toml.as_string(item) {
        Error(_) ->
          Error(InvalidPackageField(
            package: package_name,
            field: field,
            expected: "String",
          ))
        Ok(value) ->
          decode_string_list(rest, package_name, field, [value, ..acc])
      }
  }
}

fn required_string(
  package: toml.Entry,
  field: String,
  package_name: String,
) -> Result(String, Error) {
  case toml.field(package, field) {
    Error(_) ->
      Error(InvalidPackageField(
        package: package_name,
        field: field,
        expected: "String",
      ))

    Ok(value) -> {
      case toml.as_string(value) {
        Ok(value) -> Ok(value)
        Error(_) ->
          Error(InvalidPackageField(
            package: package_name,
            field: field,
            expected: "String",
          ))
      }
    }
  }
}
