import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import licence_audit/color
import licence_audit/manifest
import licence_audit/policy

pub type Mode {
  Default
  Audit
}

pub type Status {
  NotChecked
  Checked(policy.AuditStatus)
  Failed(String)
  Skipped(source: String)
}

pub type Row {
  Row(
    package: String,
    version: String,
    licences: List(String),
    status: Status,
    kind: manifest.Kind,
    scope: manifest.Scope,
    path: List(String),
  )
}

pub type Summary {
  /// `skipped_names` are the non-Hex packages encountered but not audited. The
  /// summary line reports both the count and the names so the user knows
  /// exactly what was omitted (issue #3).
  Summary(skipped_names: List(String))
}

pub fn format(
  rows: List(Row),
  summary: Summary,
  mode: Mode,
  palette: color.Palette,
) -> String {
  let widths = widths(rows)
  let #(prod_rows, dev_rows) =
    list.partition(rows, fn(r) { r.scope == manifest.Prod })
  let sections =
    [
      #("Production dependencies", prod_rows),
      #("Development dependencies", dev_rows),
    ]
    |> list.filter(fn(section) { section.1 != [] })
    |> list.map(fn(section) {
      section_text(section.0, section.1, widths, mode, palette)
    })
  let summary_line = skipped_summary_text(summary.skipped_names)

  string.join(sections, "\n\n") <> "\n" <> summary_line <> "\n" <> "\n"
}

/// Keep only rows that belong to a dependency tree containing at least one
/// policy failure. Used by `check` to focus output on offending trees.
pub fn filter_failing_trees(rows: List(Row)) -> List(Row) {
  let by_name =
    list.fold(rows, dict.new(), fn(acc, r) { dict.insert(acc, r.package, r) })
  let failing_roots =
    list.fold(rows, dict.new(), fn(acc, row) {
      case is_failure(row.status) {
        True -> dict.insert(acc, root_for(row, by_name), Nil)
        False -> acc
      }
    })
  list.filter(rows, fn(row) {
    dict.has_key(failing_roots, root_for(row, by_name))
  })
}

fn root_for(row: Row, by_name: Dict(String, Row)) -> String {
  case visual_root_name(row.path, by_name) {
    Some(name) -> name
    None -> row.package
  }
}

fn visual_root_name(
  path: List(String),
  by_name: Dict(String, Row),
) -> Option(String) {
  case path {
    [] -> None
    [name, ..rest] ->
      case dict.has_key(by_name, name) {
        True -> Some(name)
        False -> visual_root_name(rest, by_name)
      }
  }
}

fn is_failure(status: Status) -> Bool {
  case status {
    Checked(policy.Allowed) -> False
    Checked(_) -> True
    _ -> False
  }
}

/// Render the summary line tallying non-Hex packages omitted from the audit.
/// Lists the names (sorted) so the user knows exactly what was skipped; falls
/// back to a bare `0` when nothing was omitted.
fn skipped_summary_text(skipped_names: List(String)) -> String {
  let prefix =
    "Skipped non-Hex packages: " <> int.to_string(list.length(skipped_names))
  case list.sort(skipped_names, by: string.compare) {
    [] -> prefix
    names -> prefix <> " (" <> string.join(names, ", ") <> ")"
  }
}

fn section_text(
  title: String,
  rows: List(Row),
  widths: Widths,
  mode: Mode,
  palette: color.Palette,
) -> String {
  let tree = build_tree(rows)
  let body = tree_text(tree, widths, mode, palette)
  color.bold(palette, title)
  <> "\n"
  <> color.dim(palette, header(widths, mode))
  <> "\n"
  <> body
}

fn header(widths: Widths, mode: Mode) -> String {
  let prefix = "  "
  case mode {
    Default ->
      prefix
      <> pad("Package", widths.package)
      <> "  "
      <> pad("Version", widths.version)
      <> "  Licences"

    Audit ->
      prefix
      <> pad("Package", widths.package)
      <> "  "
      <> pad("Version", widths.version)
      <> "  "
      <> pad("Licences", widths.licences)
      <> "  Status"
  }
}

type Tree {
  Tree(roots: List(Row), children: Dict(String, List(Row)))
}

fn build_tree(rows: List(Row)) -> Tree {
  let by_name =
    list.fold(rows, dict.new(), fn(acc, r) { dict.insert(acc, r.package, r) })

  let #(roots_rev, children_rev) =
    list.fold(rows, #([], dict.new()), fn(acc, row) {
      let #(roots, children) = acc
      case parent_in_rows(row, by_name) {
        None -> #([row, ..roots], children)
        Some(parent_name) -> {
          let existing = case dict.get(children, parent_name) {
            Ok(c) -> c
            Error(_) -> []
          }
          #(roots, dict.insert(children, parent_name, [row, ..existing]))
        }
      }
    })

  let roots = list.reverse(roots_rev)
  let children =
    dict.keys(children_rev)
    |> list.fold(dict.new(), fn(acc, k) {
      let ordered =
        dict.get(children_rev, k) |> result.unwrap([]) |> list.reverse
      dict.insert(acc, k, ordered)
    })

  Tree(roots: roots, children: children)
}

fn parent_in_rows(row: Row, by_name: Dict(String, Row)) -> Option(String) {
  // path = [root, ..., self]. Walk ancestors from immediate parent backwards;
  // return the first one that has a corresponding row (skipping non-Hex
  // intermediates that have no row of their own).
  let ancestors_rev = case list.reverse(row.path) {
    [_self, ..rest] -> rest
    _ -> []
  }
  find_present(ancestors_rev, by_name)
}

fn find_present(
  candidates: List(String),
  by_name: Dict(String, Row),
) -> Option(String) {
  case candidates {
    [] -> None
    [name, ..rest] ->
      case dict.has_key(by_name, name) {
        True -> Some(name)
        False -> find_present(rest, by_name)
      }
  }
}

fn indexed_fold(list: List(a), index: Int, acc: b, f: fn(b, a, Int) -> b) -> b {
  case list {
    [] -> acc
    [x, ..rest] -> indexed_fold(rest, index + 1, f(acc, x, index), f)
  }
}

fn tree_text(
  tree: Tree,
  widths: Widths,
  mode: Mode,
  palette: color.Palette,
) -> String {
  render_nodes(tree.roots, tree.children, "", True, widths, mode, palette, [])
  |> list.reverse
  |> string.join(with: "\n")
}

fn render_nodes(
  nodes: List(Row),
  children: Dict(String, List(Row)),
  parent_prefix: String,
  is_root_level: Bool,
  widths: Widths,
  mode: Mode,
  palette: color.Palette,
  acc: List(String),
) -> List(String) {
  let count = list.length(nodes)
  indexed_fold(nodes, 0, acc, fn(acc, node, i) {
    let is_last = i == count - 1
    let row_prefix = case is_root_level {
      True -> ""
      False ->
        parent_prefix
        <> case is_last {
          True -> "└─ "
          False -> "├─ "
        }
    }
    let line = row_text(node, row_prefix, widths, mode, palette)
    let next_parent_prefix = case is_root_level {
      True -> ""
      False ->
        parent_prefix
        <> case is_last {
          True -> "   "
          False -> "│  "
        }
    }
    let kids = dict.get(children, node.package) |> result.unwrap([])
    render_nodes(
      kids,
      children,
      next_parent_prefix,
      False,
      widths,
      mode,
      palette,
      [line, ..acc],
    )
  })
}

fn row_text(
  row: Row,
  prefix: String,
  widths: Widths,
  mode: Mode,
  palette: color.Palette,
) -> String {
  let licences_raw = licences_text(row)
  let licences_padded = pad(licences_raw, widths.licences)
  let glyph = glyph(row.status, mode, palette)
  let licences_padded_colored =
    colorize_for_status(row.status, mode, palette, licences_padded)
  let name_padded = pad_name(prefix, row.package, widths.package)

  case mode {
    Default ->
      prefix
      <> glyph
      <> " "
      <> name_padded
      <> "  "
      <> pad(row.version, widths.version)
      <> "  "
      <> licences_padded_colored

    Audit ->
      prefix
      <> glyph
      <> " "
      <> name_padded
      <> "  "
      <> pad(row.version, widths.version)
      <> "  "
      <> licences_padded_colored
      <> "  "
      <> status_text(row.status)
  }
}

// Pads `prefix + name` such that the column ending the package field aligns
// across rows regardless of tree depth. `widths.package` is the maximum of
// (prefix length + name length) across all rows, so this reserves enough
// trailing space for shallower rows.
fn pad_name(prefix: String, name: String, width: Int) -> String {
  let used = string.length(prefix) + string.length(name)
  name <> string.repeat(" ", times: width - used)
}

fn colorize_for_status(
  status: Status,
  mode: Mode,
  palette: color.Palette,
  text: String,
) -> String {
  case mode {
    Default -> color.yellow(palette, text)
    Audit ->
      case status {
        Checked(policy.Allowed) -> color.green(palette, text)
        Checked(policy.UnallowedLicence(_)) -> color.yellow(palette, text)
        Checked(_) -> color.red(palette, text)
        Failed(_) -> color.yellow(palette, text)
        NotChecked -> color.yellow(palette, text)
        Skipped(_) -> color.yellow(palette, text)
      }
  }
}

fn glyph(status: Status, mode: Mode, palette: color.Palette) -> String {
  case mode {
    Default ->
      case status {
        Skipped(_) -> color.yellow(palette, "·")
        _ -> color.yellow(palette, "?")
      }
    Audit ->
      case status {
        Checked(policy.Allowed) -> color.green(palette, "✓")
        Checked(policy.UnallowedLicence(_)) -> color.yellow(palette, "?")
        Checked(_) -> color.red(palette, "✗")
        Failed(_) -> color.yellow(palette, "?")
        NotChecked -> color.yellow(palette, "?")
        Skipped(_) -> color.yellow(palette, "·")
      }
  }
}

type Widths {
  Widths(package: Int, version: Int, licences: Int)
}

fn widths(rows: List(Row)) -> Widths {
  widths_loop(rows, Widths(package: 7, version: 7, licences: 8))
}

fn widths_loop(rows: List(Row), current: Widths) -> Widths {
  case rows {
    [] -> current
    [row, ..rest] -> {
      let licences_width =
        int.max(current.licences, string.length(licences_text(row)))
      // Package column must fit every row's (tree prefix + name). Roots have
      // an empty prefix, so deep transitive children dominate this width.
      let row_prefix_len = case row.path {
        [] | [_] -> 0
        path -> { list.length(path) - 1 } * 3
      }
      let package_width =
        int.max(current.package, row_prefix_len + string.length(row.package))

      widths_loop(
        rest,
        Widths(
          package: package_width,
          version: int.max(current.version, string.length(row.version)),
          licences: licences_width,
        ),
      )
    }
  }
}

fn licences_text(row: Row) -> String {
  case row.licences {
    [] -> {
      case row.status {
        Failed(message) -> "ERROR: " <> message
        Skipped(source) -> "non-hex (" <> source <> ")"
        _ -> "-"
      }
    }
    licences -> licences |> sort_dedupe |> string.join(", ")
  }
}

fn status_text(status: Status) -> String {
  case status {
    NotChecked -> "-"
    Checked(policy.Allowed) -> "allowed"
    Checked(policy.NoLicencesDeclared) -> "no licences declared"
    Checked(policy.DeniedLicence(licence)) -> "denied: " <> licence
    Checked(policy.UnallowedLicence(licence)) -> "unknown: " <> licence
    Failed(message) -> "error: " <> message
    Skipped(source) -> "skipped: " <> source
  }
}

fn sort_dedupe(licences: List(String)) -> List(String) {
  licences
  |> list.sort(by: string.compare)
  |> list.unique
}

fn pad(text: String, width: Int) -> String {
  text <> string.repeat(" ", times: width - string.length(text))
}
