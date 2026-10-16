//// Auto-generate Markdown reference documentation from a `glint` CLI.
////
//// Pair with [`glint.document/1`](https://hexdocs.pm/glint/glint.html#document):
////
//// ```gleam
//// import gleam/io
//// import glint
//// import glint_markdown
////
//// pub fn main() {
////   let tree = glint.document(my_app())
////
////   // Single-file: render the whole tree to one Markdown document.
////   tree
////   |> glint_markdown.to_string(glint_markdown.options("myapp"))
////   |> io.println
////
////   // Or inject into an existing README between sentinel comments:
////   //     <!-- root -->
////   //     <!-- rootstop -->
////   //     <!-- commands -->
////   //     <!-- commandsstop -->
////   let root = glint_markdown.to_root_body(tree, options)
////   let body = glint_markdown.to_commands_body(tree, options)
////   let updated =
////     existing_readme
////     |> glint_markdown.inject("root", root)
////     |> glint_markdown.inject("commands", body)
//// }
//// ```
////
//// Patterned after [oclif's readme generator][oclif] — supports both
//// single-file output (one README with every command as a `##` section) and
//// multi-file output (one file per top-level subcommand plus an index).
////
//// [oclif]: https://github.com/oclif/oclif/blob/main/src/readme-generator.ts
////
//// ## CLI integration
////
//// The companion module [`glint_markdown/cli`](./glint_markdown/cli.html)
//// provides a ready-made `gen-docs` subcommand you can mount into your own
//// glint app with a single line:
////
//// ```gleam
//// glint.new()
//// |> glint.with_name("myapp")
//// |> glint.add(at: ["greet"], do: greet_cmd())
//// |> glint_markdown_cli.mount(at: ["gen-docs"])
//// |> glint.run(argv.load().arguments)
//// ```
////
//// **Note**: `mount` is restricted to `Glint(Nil)` host apps — the common
//// case. For non-`Nil` hosts, use `glint_markdown_cli.command/1` directly
//// with `glint.map_command`.

// Vendored from vendor/glint_markdown/src/glint_markdown.gleam at 9c66ec3a62e43c639b06c3dfa582f223fc2fef14.
// Modified for licence_audit vendoring. Run just vendor-sync to update.

import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/set.{type Set}
import gleam/string
import gleam/uri
import glugify
import licence_audit/internal/vendor/glint/help.{type Flag, type Tree}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// Output mode.
pub type Mode {
  /// Render the entire tree into one Markdown document.
  Single
  /// Render one Markdown file per top-level subcommand under `output_dir`,
  /// plus an index body suitable for injection into an existing README.
  Multi(output_dir: String)
}

/// Renderer configuration. Construct with [`options`](#options) and customise
/// with [`with_mode`](#with_mode) / [`with_repository_prefix`](#with_repository_prefix).
pub type Options {
  Options(
    bin: String,
    mode: Mode,
    include_hidden: Bool,
    repository_prefix: Option(String),
  )
}

/// Build an `Options` value with sensible defaults.
///
/// - `bin` is the executable name shown in headings and usage blocks
///   (typically the same string passed to `glint.with_name`).
/// - mode defaults to [`Single`](#Mode).
/// - hidden commands are filtered (future-compatible; the field is currently
///   ignored because `glint/help.Tree` has no hidden marker yet).
pub fn options(bin: String) -> Options {
  Options(
    bin: bin,
    mode: Single,
    include_hidden: False,
    repository_prefix: None,
  )
}

/// Switch between [`Single`](#Mode) and [`Multi`](#Mode) output.
pub fn with_mode(options: Options, mode: Mode) -> Options {
  Options(..options, mode: mode)
}

/// Set a repository URL prefix used for `_See code:_` links beneath each
/// rendered command. Currently a no-op; will be wired up once `glint/help.Tree`
/// carries source-location data.
pub fn with_repository_prefix(options: Options, prefix: String) -> Options {
  Options(..options, repository_prefix: Some(prefix))
}

// ---------------------------------------------------------------------------
// Single-file rendering
// ---------------------------------------------------------------------------

/// Render `tree` to a complete single-page Markdown document:
/// `# bin`, TOC, then one `##`-headed section per command.
///
/// For incremental updates to an existing README prefer
/// [`to_root_body`](#to_root_body) +
/// [`to_commands_body`](#to_commands_body) +
/// [`to_toc_body`](#to_toc_body) + [`inject`](#inject).
pub fn to_string(tree: Tree, options: Options) -> String {
  let entries = flatten(tree, options)
  let toc = render_toc(entries)
  let body = render_entries(entries)
  let parts = [
    "# " <> options.bin,
    toc,
    body,
  ]
  parts
  |> list.filter(non_empty)
  |> string.join("\n\n")
}

/// Render the body that should go between `<!-- commands -->` and
/// `<!-- commandsstop -->` sentinels in an existing README — a flat sequence
/// of `##`-headed command sections, with no enclosing title.
pub fn to_commands_body(tree: Tree, options: Options) -> String {
  flatten(tree, options)
  |> render_entries
}

/// Render the body for `<!-- toc -->` / `<!-- tocstop -->` sentinels — a
/// bulleted list of links to every command in the tree.
pub fn to_toc_body(tree: Tree, options: Options) -> String {
  flatten(tree, options)
  |> render_toc
}

/// Render the body for `<!-- root -->` / `<!-- rootstop -->` sentinels — the
/// root command's description, usage, flags, and arguments, with no enclosing
/// title or subcommand list.
pub fn to_root_body(tree: Tree, options: Options) -> String {
  let entry = Entry(path: [options.bin], tree: tree, anchor: "")
  [tree.meta.description, render_entry_body(entry, [], False)]
  |> list.filter(non_empty)
  |> string.join("\n\n")
}

// ---------------------------------------------------------------------------
// Multi-file rendering
// ---------------------------------------------------------------------------

/// Render the tree as one file per top-level subcommand.
///
/// Returns a `Dict(filename, contents)` keyed by paths relative to the
/// project root (e.g. `"docs/user.md"`). The caller is responsible for
/// writing the files to disk — this keeps the library pure.
///
/// Top-level flags and the root command's description are **not** included
/// in the per-topic files; render them separately into your main README via
/// [`to_topics_index_body`](#to_topics_index_body) and [`inject`](#inject).
pub fn to_files(tree: Tree, options: Options) -> Dict(String, String) {
  let directory = case options.mode {
    Multi(output_dir: output_directory) -> output_directory
    Single -> "."
  }
  tree.subcommands
  |> filter_visible(options)
  |> sort_subcommands
  |> list.fold(dict.new(), fn(acc, topic) {
    let filename = directory <> "/" <> topic.meta.name <> ".md"
    let path = [options.bin, topic.meta.name]
    let entries =
      flatten_with_path(topic, options, path)
      |> sort_entries
      |> assign_anchors
    // The file's `#` heading and description already title the topic, so the
    // topic's own section is rendered without re-emitting them. Descendant
    // subcommands are still rendered as their own `##` sections.
    let contents =
      entries
      |> list.map(fn(entry) {
        let heading_level = case entry.path == path {
          True -> "#"
          False -> "##"
        }
        render_entry(entry, entries, heading_level)
      })
      |> string.join("\n\n")
    dict.insert(acc, filename, contents <> "\n")
  })
}

/// Render the body for `<!-- commands -->` when using [`Multi`](#Mode) mode —
/// a `## Subcommands` heading followed by a bulleted index linking each
/// topic file produced by [`to_files`](#to_files).
pub fn to_topics_index_body(tree: Tree, options: Options) -> String {
  let directory = case options.mode {
    Multi(output_dir: output_directory) -> output_directory
    Single -> "."
  }
  let topics =
    tree.subcommands
    |> filter_visible(options)
    |> sort_subcommands
  let bullets =
    topics
    |> list.map(fn(topic) {
      let label = "`" <> options.bin <> " " <> topic.meta.name <> "`"
      let link = encode_link_path(directory <> "/" <> topic.meta.name <> ".md")
      let summary = first_line(topic.meta.description)
      let suffix = case summary {
        "" -> ""
        description -> " - " <> description
      }
      "* [" <> label <> "](" <> link <> ")" <> suffix
    })
    |> string.join("\n")
  case bullets {
    "" -> "## Subcommands"
    _ -> "## Subcommands\n\n" <> bullets
  }
}

// ---------------------------------------------------------------------------
// Sentinel-comment injection (oclif `replaceTag` analogue)
// ---------------------------------------------------------------------------

/// Replace the section delimited by `<!-- tag -->` and `<!-- tagstop -->` in
/// `readme` with `body`. Pure string transformation — no filesystem IO.
///
/// Mirrors oclif's [`ReadmeGenerator.replaceTag`][rt]:
///
/// - If both start and stop markers are present, everything between them
///   (including the markers) is replaced with the fresh marker pair plus body.
/// - If only the start marker is present, the body and a new stop marker are
///   inserted after it.
/// - If no start marker is present, `readme` is returned unchanged.
///
/// [rt]: https://github.com/oclif/oclif/blob/main/src/readme-generator.ts
pub fn inject(readme: String, tag: String, body: String) -> String {
  let start = "<!-- " <> tag <> " -->"
  let stop = "<!-- " <> tag <> "stop -->"
  let replacement = start <> "\n" <> body <> "\n" <> stop
  case string.contains(readme, start) {
    False -> readme
    True ->
      case string.contains(readme, stop) {
        True -> replace_between(readme, start, stop, replacement)
        False -> string.replace(readme, start, replacement)
      }
  }
}

fn replace_between(
  input: String,
  start: String,
  stop: String,
  replacement: String,
) -> String {
  case string.split_once(input, start) {
    Error(_) -> input
    Ok(#(before, after)) ->
      case string.split_once(after, stop) {
        Error(_) -> input
        Ok(#(_, rest)) -> before <> replacement <> rest
      }
  }
}

// ---------------------------------------------------------------------------
// Tree flattening
// ---------------------------------------------------------------------------

type Entry {
  Entry(path: List(String), tree: Tree, anchor: String)
}

fn flatten(tree: Tree, options: Options) -> List(Entry) {
  flatten_with_path(tree, options, [options.bin])
  |> sort_entries
  |> assign_anchors
}

fn flatten_with_path(
  tree: Tree,
  options: Options,
  path: List(String),
) -> List(Entry) {
  let head = Entry(path: path, tree: tree, anchor: "")
  let children =
    tree.subcommands
    |> filter_visible(options)
    |> list.flat_map(fn(subcommand) {
      flatten_with_path(
        subcommand,
        options,
        list.append(path, [subcommand.meta.name]),
      )
    })
  [head, ..children]
}

fn sort_entries(entries: List(Entry)) -> List(Entry) {
  list.sort(entries, fn(a, b) {
    string.compare(string.join(a.path, " "), string.join(b.path, " "))
  })
}

fn assign_anchors(entries: List(Entry)) -> List(Entry) {
  let #(_, anchored_entries) =
    list.map_fold(entries, set.new(), fn(used, entry) {
      let base = "command-" <> glugify.slugify(string.join(entry.path, " "))
      let anchor = unique_anchor(base, used, 0)
      #(set.insert(used, anchor), Entry(..entry, anchor: anchor))
    })
  anchored_entries
}

fn unique_anchor(base: String, used: Set(String), suffix: Int) -> String {
  let candidate = case suffix {
    0 -> base
    _ -> base <> "-" <> int.to_string(suffix)
  }
  case set.contains(used, candidate) {
    True -> unique_anchor(base, used, suffix + 1)
    False -> candidate
  }
}

fn sort_subcommands(subcommands: List(Tree)) -> List(Tree) {
  list.sort(subcommands, fn(a, b) { string.compare(a.meta.name, b.meta.name) })
}

fn filter_visible(subcommands: List(Tree), _options: Options) -> List(Tree) {
  // Placeholder: glint/help.Tree has no `hidden` marker yet.
  // When it lands, gate filtering on `options.include_hidden`.
  subcommands
}

// ---------------------------------------------------------------------------
// Section rendering
// ---------------------------------------------------------------------------

fn render_entries(entries: List(Entry)) -> String {
  entries
  |> list.map(render_entry(_, entries, "##"))
  |> string.join("\n\n")
}

fn render_entry(
  entry: Entry,
  entries: List(Entry),
  heading_level: String,
) -> String {
  let title = string.join(entry.path, " ")
  let heading =
    "<a id=\""
    <> entry.anchor
    <> "\"></a>\n\n"
    <> heading_level
    <> " `"
    <> title
    <> "`"
  let body = render_entry_body(entry, entries, True)

  [heading, entry.tree.meta.description, body]
  |> list.filter(non_empty)
  |> string.join("\n\n")
}

fn render_entry_body(
  entry: Entry,
  entries: List(Entry),
  include_subcommands: Bool,
) -> String {
  let usage = render_usage(entry)
  let arguments = render_arguments(entry.tree)
  let flags = render_flags(entry.tree.flags)
  let subcommands = case include_subcommands {
    True -> render_subcommands_list(entry, entries)
    False -> ""
  }

  [usage, arguments, flags, subcommands]
  |> list.filter(non_empty)
  |> string.join("\n\n")
}

fn render_usage(entry: Entry) -> String {
  let path = string.join(entry.path, " ")
  let named =
    entry.tree.named_args
    |> list.map(fn(name) { "<" <> name <> ">" })
    |> string.join(" ")
  let unnamed = case entry.tree.unnamed_args {
    Some(help.EqArgs(0)) -> ""
    Some(help.EqArgs(1)) -> "[1 argument]"
    Some(help.EqArgs(count)) -> "[" <> int.to_string(count) <> " arguments]"
    Some(help.MinArgs(count)) ->
      "[" <> int.to_string(count) <> " or more arguments]"
    None -> "[ARGS]"
  }
  let subcommands = case entry.tree.subcommands {
    [] -> ""
    _ ->
      "("
      <> entry.tree.subcommands
      |> list.map(fn(subcommand) { subcommand.meta.name })
      |> sort_strings
      |> string.join(" | ")
      <> ")"
  }
  let flags_token = case entry.tree.flags {
    [] -> ""
    _ -> "[--flags]"
  }
  let parts =
    [path, subcommands, named, unnamed, flags_token]
    |> list.filter(non_empty)
    |> string.join(" ")
  "**Usage:**\n\n```\n" <> parts <> "\n```"
}

fn render_arguments(tree: Tree) -> String {
  case tree.named_args {
    [] -> ""
    arguments -> {
      let items =
        arguments
        |> list.map(fn(name) { "- `<" <> name <> ">`" })
        |> string.join("\n")
      "**Arguments:**\n\n" <> items
    }
  }
}

fn render_flags(flags: List(Flag)) -> String {
  case flags {
    [] -> ""
    _ -> {
      let header =
        "| Name | Type | Default | Description |\n"
        <> "|------|------|---------|-------------|"
      let rows =
        flags
        |> list.sort(fn(a, b) { string.compare(a.meta.name, b.meta.name) })
        |> list.map(render_flag_row)
        |> string.join("\n")
      "**Flags:**\n\n" <> header <> "\n" <> rows
    }
  }
}

fn render_flag_row(flag: Flag) -> String {
  let name = "`--" <> flag.meta.name <> "`"
  let type_ = case flag.type_ {
    "" -> ""
    flag_type -> "`" <> flag_type <> "`"
  }
  let default = case flag.default {
    None -> ""
    Some(value) -> "`" <> escape_table_cell(value) <> "`"
  }
  let description = escape_table_cell(flag.meta.description)
  "| "
  <> name
  <> " | "
  <> type_
  <> " | "
  <> default
  <> " | "
  <> description
  <> " |"
}

fn render_subcommands_list(entry: Entry, entries: List(Entry)) -> String {
  let children =
    entries
    |> list.filter(fn(child) {
      list.length(child.path) == list.length(entry.path) + 1
      && list.take(child.path, list.length(entry.path)) == entry.path
    })
  case children {
    [] -> ""
    subcommands -> {
      let items =
        subcommands
        |> list.map(fn(child) {
          let label = "`" <> string.join(child.path, " ") <> "`"
          let summary = first_line(child.tree.meta.description)
          let suffix = case summary {
            "" -> ""
            description -> " - " <> description
          }
          "- [" <> label <> "](#" <> child.anchor <> ")" <> suffix
        })
        |> string.join("\n")
      "**Subcommands:**\n\n" <> items
    }
  }
}

fn render_toc(entries: List(Entry)) -> String {
  case entries {
    [] -> ""
    _ -> {
      let bullets =
        entries
        |> list.map(fn(entry) {
          let title = string.join(entry.path, " ")
          "* [`" <> title <> "`](#" <> entry.anchor <> ")"
        })
        |> string.join("\n")
      "## Table of Contents\n\n" <> bullets
    }
  }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn non_empty(input: String) -> Bool {
  input != ""
}

fn first_line(input: String) -> String {
  case string.split_once(input, "\n") {
    Ok(#(first, _)) -> first
    Error(_) -> input
  }
}

fn sort_strings(items: List(String)) -> List(String) {
  list.sort(items, string.compare)
}

fn escape_table_cell(input: String) -> String {
  input
  |> string.replace("|", "\\|")
  |> string.replace("\n", " ")
}

fn encode_link_path(path: String) -> String {
  path
  |> string.split("/")
  |> list.map(fn(segment) {
    segment
    |> uri.percent_encode
    |> string.replace("(", "%28")
    |> string.replace(")", "%29")
    |> string.replace("$", "%24")
  })
  |> string.join("/")
}
