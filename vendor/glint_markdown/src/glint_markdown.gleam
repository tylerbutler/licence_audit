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

import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import glint/help.{type Flag, type Tree}
import glugify

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
pub fn with_mode(opts: Options, mode: Mode) -> Options {
  Options(..opts, mode: mode)
}

/// Set a repository URL prefix used for `_See code:_` links beneath each
/// rendered command. Currently a no-op; will be wired up once `glint/help.Tree`
/// carries source-location data.
pub fn with_repository_prefix(opts: Options, prefix: String) -> Options {
  Options(..opts, repository_prefix: Some(prefix))
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
pub fn to_string(tree: Tree, opts: Options) -> String {
  let entries = flatten(tree, opts)
  let toc = render_toc(entries)
  let body = render_entries(entries, opts)
  let parts = [
    "# " <> opts.bin,
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
pub fn to_commands_body(tree: Tree, opts: Options) -> String {
  flatten(tree, opts)
  |> render_entries(opts)
}

/// Render the body for `<!-- toc -->` / `<!-- tocstop -->` sentinels — a
/// bulleted list of links to every command in the tree.
pub fn to_toc_body(tree: Tree, opts: Options) -> String {
  flatten(tree, opts)
  |> render_toc
}

/// Render the body for `<!-- root -->` / `<!-- rootstop -->` sentinels — the
/// root command's description, usage, flags, and arguments, with no enclosing
/// title or subcommand list.
pub fn to_root_body(tree: Tree, opts: Options) -> String {
  let entry = Entry(path: [opts.bin], tree: tree)
  [tree.meta.description, render_entry_body(entry, opts, False)]
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
pub fn to_files(tree: Tree, opts: Options) -> Dict(String, String) {
  let dir = case opts.mode {
    Multi(output_dir: d) -> d
    Single -> "."
  }
  tree.subcommands
  |> filter_visible(opts)
  |> sort_subcommands
  |> list.fold(dict.new(), fn(acc, topic) {
    let filename = dir <> "/" <> topic.meta.name <> ".md"
    let path = [opts.bin, topic.meta.name]
    let topic_entry = Entry(path: path, tree: topic)
    // The file's `#` heading and description already title the topic, so the
    // topic's own section is rendered without re-emitting them. Descendant
    // subcommands are still rendered as their own `##` sections.
    let descendants =
      topic.subcommands
      |> filter_visible(opts)
      |> list.flat_map(fn(sub) {
        flatten_with_path(sub, opts, list.append(path, [sub.meta.name]))
      })
      |> sort_entries
    let header = "# `" <> opts.bin <> " " <> topic.meta.name <> "`"
    let description = case topic.meta.description {
      "" -> ""
      d -> d
    }
    let topic_body = render_entry_body(topic_entry, opts, True)
    let descendants_body = render_entries(descendants, opts)
    let contents =
      [header, description, topic_body, descendants_body]
      |> list.filter(non_empty)
      |> string.join("\n\n")
    dict.insert(acc, filename, contents <> "\n")
  })
}

/// Render the body for `<!-- commands -->` when using [`Multi`](#Mode) mode —
/// a `## Subcommands` heading followed by a bulleted index linking each
/// topic file produced by [`to_files`](#to_files).
pub fn to_topics_index_body(tree: Tree, opts: Options) -> String {
  let dir = case opts.mode {
    Multi(output_dir: d) -> d
    Single -> "."
  }
  let topics =
    tree.subcommands
    |> filter_visible(opts)
    |> sort_subcommands
  let bullets =
    topics
    |> list.map(fn(t) {
      let label = "`" <> opts.bin <> " " <> t.meta.name <> "`"
      let link = dir <> "/" <> t.meta.name <> ".md"
      let summary = first_line(t.meta.description)
      let suffix = case summary {
        "" -> ""
        s -> " - " <> s
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
  s: String,
  start: String,
  stop: String,
  replacement: String,
) -> String {
  case string.split_once(s, start) {
    Error(_) -> s
    Ok(#(before, after)) ->
      case string.split_once(after, stop) {
        Error(_) -> s
        Ok(#(_, rest)) -> before <> replacement <> rest
      }
  }
}

// ---------------------------------------------------------------------------
// Tree flattening
// ---------------------------------------------------------------------------

type Entry {
  Entry(path: List(String), tree: Tree)
}

fn flatten(tree: Tree, opts: Options) -> List(Entry) {
  flatten_with_path(tree, opts, [opts.bin])
  |> sort_entries
}

fn flatten_with_path(
  tree: Tree,
  opts: Options,
  path: List(String),
) -> List(Entry) {
  let head = Entry(path: path, tree: tree)
  let children =
    tree.subcommands
    |> filter_visible(opts)
    |> list.flat_map(fn(sub) {
      flatten_with_path(sub, opts, list.append(path, [sub.meta.name]))
    })
  [head, ..children]
}

fn sort_entries(entries: List(Entry)) -> List(Entry) {
  list.sort(entries, fn(a, b) {
    string.compare(string.join(a.path, " "), string.join(b.path, " "))
  })
}

fn sort_subcommands(subs: List(Tree)) -> List(Tree) {
  list.sort(subs, fn(a, b) { string.compare(a.meta.name, b.meta.name) })
}

fn filter_visible(subs: List(Tree), _opts: Options) -> List(Tree) {
  // Placeholder: glint/help.Tree has no `hidden` marker yet.
  // When it lands, gate filtering on `opts.include_hidden`.
  subs
}

// ---------------------------------------------------------------------------
// Section rendering
// ---------------------------------------------------------------------------

fn render_entries(entries: List(Entry), opts: Options) -> String {
  entries
  |> list.map(render_entry(_, opts))
  |> string.join("\n\n")
}

fn render_entry(entry: Entry, opts: Options) -> String {
  let title = string.join(entry.path, " ")
  let heading = "## `" <> title <> "`"
  let description = case entry.tree.meta.description {
    "" -> ""
    d -> d
  }
  let body = render_entry_body(entry, opts, True)

  [heading, description, body]
  |> list.filter(non_empty)
  |> string.join("\n\n")
}

fn render_entry_body(
  entry: Entry,
  opts: Options,
  include_subcommands: Bool,
) -> String {
  let usage = render_usage(entry, opts)
  let arguments = render_arguments(entry.tree)
  let flags = render_flags(entry.tree.flags)
  let subs = case include_subcommands {
    True -> render_subcommands_list(entry, opts)
    False -> ""
  }

  [usage, arguments, flags, subs]
  |> list.filter(non_empty)
  |> string.join("\n\n")
}

fn render_usage(entry: Entry, _opts: Options) -> String {
  let path = string.join(entry.path, " ")
  let named =
    entry.tree.named_args
    |> list.map(fn(n) { "<" <> n <> ">" })
    |> string.join(" ")
  let unnamed = case entry.tree.unnamed_args {
    Some(help.EqArgs(0)) -> ""
    Some(help.EqArgs(1)) -> "[1 argument]"
    Some(help.EqArgs(n)) -> "[" <> int.to_string(n) <> " arguments]"
    Some(help.MinArgs(n)) -> "[" <> int.to_string(n) <> " or more arguments]"
    None -> "[ARGS]"
  }
  let subs = case entry.tree.subcommands {
    [] -> ""
    _ ->
      "("
      <> entry.tree.subcommands
      |> list.map(fn(s) { s.meta.name })
      |> sort_strings
      |> string.join(" | ")
      <> ")"
  }
  let flags_token = case entry.tree.flags {
    [] -> ""
    _ -> "[--flags]"
  }
  let parts =
    [path, subs, named, unnamed, flags_token]
    |> list.filter(non_empty)
    |> string.join(" ")
  "**Usage:**\n\n```\n" <> parts <> "\n```"
}

fn render_arguments(tree: Tree) -> String {
  case tree.named_args {
    [] -> ""
    args -> {
      let items =
        args
        |> list.map(fn(n) { "- `<" <> n <> ">`" })
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
    t -> "`" <> t <> "`"
  }
  let default = case flag.default {
    None -> ""
    Some(v) -> "`" <> escape_table_cell(v) <> "`"
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

fn render_subcommands_list(entry: Entry, _opts: Options) -> String {
  case entry.tree.subcommands {
    [] -> ""
    subs -> {
      let items =
        subs
        |> sort_subcommands
        |> list.map(fn(sub) {
          let sub_title =
            string.join(list.append(entry.path, [sub.meta.name]), " ")
          let label = "`" <> sub_title <> "`"
          let summary = first_line(sub.meta.description)
          let suffix = case summary {
            "" -> ""
            s -> " - " <> s
          }
          "- [" <> label <> "](#" <> slugify(sub_title) <> ")" <> suffix
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
        |> list.map(fn(e) {
          let title = string.join(e.path, " ")
          "* [`" <> title <> "`](#" <> slugify(title) <> ")"
        })
        |> string.join("\n")
      "## Table of Contents\n\n" <> bullets
    }
  }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn non_empty(s: String) -> Bool {
  s != ""
}

fn first_line(s: String) -> String {
  case string.split_once(s, "\n") {
    Ok(#(first, _)) -> first
    Error(_) -> s
  }
}

fn sort_strings(items: List(String)) -> List(String) {
  list.sort(items, string.compare)
}

fn escape_table_cell(s: String) -> String {
  s
  |> string.replace("|", "\\|")
  |> string.replace("\n", " ")
}

/// GitHub-style anchor slug, delegating to the
/// [`glugify`](https://hex.pm/packages/glugify) library.
fn slugify(s: String) -> String {
  glugify.slugify(s)
}
