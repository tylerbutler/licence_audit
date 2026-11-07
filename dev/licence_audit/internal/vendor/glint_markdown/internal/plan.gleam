//// Pure planner for the `glint_markdown` CLI.
////
//// Given a parsed `glint/help.Tree` and a `PlanOptions` record describing the
//// flag surface, [`plan`](#plan) returns a list of [`Action`](#Action) values
//// describing the IO that should happen — without performing any IO itself.
////
//// The companion `glint_markdown/internal/io` module is responsible for
//// executing actions against the filesystem (and stdout).

// Vendored from vendor/glint_markdown/src/glint_markdown/internal/plan.gleam at 9c66ec3a62e43c639b06c3dfa582f223fc2fef14.
// Modified for licence_audit vendoring. Run just vendor-sync to update.

import filepath
import gleam/dict
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import licence_audit/internal/vendor/glint/help.{type Tree}
import licence_audit/internal/vendor/glint_markdown

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single IO operation the CLI should perform.
pub type Action {
  /// Print `contents` to stdout.
  WriteStdout(contents: String)
  /// Write `contents` to `path`, replacing any existing file.
  WriteFile(path: String, contents: String)
  /// Replace the `<!-- tag -->` / `<!-- tagstop -->` block inside the file at
  /// `path` with `body`, using `glint_markdown.inject`.
  InjectFile(path: String, tag: String, body: String)
}

/// Errors the pure planner can surface before any IO happens.
pub type PlanError {
  /// `--mode` was passed an unrecognised value.
  InvalidMode(value: String)
  UnsafeTopic(name: String)
  InvalidPath(path: String)
  ConflictingDestination(path: String)
}

/// `--mode` choice. Parsed from the raw CLI string via [`parse_mode`](#parse_mode).
pub type ModeChoice {
  SingleMode
  MultiMode
}

/// CLI flag bundle consumed by [`plan`](#plan).
pub type PlanOptions {
  PlanOptions(
    bin: String,
    working_directory: String,
    mode: ModeChoice,
    output: Option(String),
    readme: Option(String),
    repository_prefix: Option(String),
    include_hidden: Bool,
    no_toc: Bool,
  )
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const default_documentation_directory: String = "./docs"

const toc_tag: String = "toc"

const root_tag: String = "root"

const commands_tag: String = "commands"

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse the raw `--mode` string into a [`ModeChoice`](#ModeChoice).
pub fn parse_mode(input: String) -> Result(ModeChoice, PlanError) {
  case input {
    "single" -> Ok(SingleMode)
    "multi" -> Ok(MultiMode)
    other -> Error(InvalidMode(other))
  }
}

/// Build the list of [`Action`](#Action)s the CLI should execute.
///
/// Pure: performs no IO. See the behaviour matrix in `plan.md` for the
/// mapping from `(mode, --readme, --out)` to emitted actions.
pub fn plan(
  tree: Tree,
  options: PlanOptions,
) -> Result(List(Action), PlanError) {
  case options.mode {
    SingleMode -> Ok(plan_single(tree, options))
    MultiMode -> plan_multi(tree, options)
  }
}

pub fn describe_error(error: PlanError) -> String {
  case error {
    InvalidMode(value) ->
      "invalid --mode value: " <> value <> " (expected 'single' or 'multi')"
    UnsafeTopic(name) -> "unsafe topic filename for command: " <> name
    InvalidPath(path) -> "invalid output or README path: " <> path
    ConflictingDestination(path) ->
      "cannot replace and inject the same file: " <> path
  }
}

// ---------------------------------------------------------------------------
// Single-mode planning
// ---------------------------------------------------------------------------

fn plan_single(tree: Tree, options: PlanOptions) -> List(Action) {
  let render_options = to_render_options(options)
  case options.readme {
    Some(readme_path) -> {
      // --readme wins; --out is ignored when injecting.
      let root_body = glint_markdown.to_root_body(tree, render_options)
      let commands_body = glint_markdown.to_commands_body(tree, render_options)
      let root_action =
        InjectFile(path: readme_path, tag: root_tag, body: root_body)
      let commands_action =
        InjectFile(path: readme_path, tag: commands_tag, body: commands_body)
      case options.no_toc {
        True -> [root_action, commands_action]
        False -> {
          let toc_body = glint_markdown.to_toc_body(tree, render_options)
          [
            root_action,
            InjectFile(path: readme_path, tag: toc_tag, body: toc_body),
            commands_action,
          ]
        }
      }
    }
    None -> {
      let document = render_single_document(tree, options, render_options)
      case options.output {
        Some(file) -> [WriteFile(path: file, contents: document)]
        None -> [WriteStdout(contents: document)]
      }
    }
  }
}

fn render_single_document(
  tree: Tree,
  options: PlanOptions,
  render_options: glint_markdown.Options,
) -> String {
  case options.no_toc {
    False -> glint_markdown.to_string(tree, render_options)
    True -> {
      // Reproduce the `to_string` layout without the TOC section so we don't
      // need to extend the public renderer API.
      let body = glint_markdown.to_commands_body(tree, render_options)
      case body {
        "" -> "# " <> options.bin
        _ -> "# " <> options.bin <> "\n\n" <> body
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Multi-mode planning
// ---------------------------------------------------------------------------

fn plan_multi(
  tree: Tree,
  options: PlanOptions,
) -> Result(List(Action), PlanError) {
  use _ <- result.try(list.try_each(tree.subcommands, validate_topic))
  let directory = option.unwrap(options.output, default_documentation_directory)
  let render_options =
    to_render_options(options)
    |> glint_markdown.with_mode(glint_markdown.Multi(output_dir: directory))

  let file_actions =
    glint_markdown.to_files(tree, render_options)
    |> dict.to_list
    |> list.sort(fn(a, b) {
      let #(path_a, _) = a
      let #(path_b, _) = b
      string.compare(path_a, path_b)
    })
    |> list.map(fn(entry) {
      let #(path, contents) = entry
      WriteFile(path: path, contents: contents)
    })

  case options.readme {
    None -> Ok(file_actions)
    Some(readme_path) -> {
      use absolute_readme <- result.try(absolute_path(
        readme_path,
        options.working_directory,
      ))
      use _ <- result.try(
        list.try_each(file_actions, fn(action) {
          case action {
            WriteFile(path, _) -> {
              use absolute_output <- result.try(absolute_path(
                path,
                options.working_directory,
              ))
              case absolute_output == absolute_readme {
                True -> Error(ConflictingDestination(path))
                False -> Ok(Nil)
              }
            }
            InjectFile(..) | WriteStdout(..) -> Ok(Nil)
          }
        }),
      )
      use absolute_directory <- result.try(absolute_path(
        directory,
        options.working_directory,
      ))
      let index_options =
        glint_markdown.with_mode(
          render_options,
          glint_markdown.Multi(relative_directory(
            filepath.directory_name(absolute_readme),
            absolute_directory,
          )),
        )
      let root_body = glint_markdown.to_root_body(tree, render_options)
      let index_body = glint_markdown.to_topics_index_body(tree, index_options)
      Ok(
        list.append(file_actions, [
          InjectFile(path: readme_path, tag: root_tag, body: root_body),
          InjectFile(path: readme_path, tag: commands_tag, body: index_body),
        ]),
      )
    }
  }
}

fn validate_topic(topic: Tree) -> Result(Nil, PlanError) {
  let name = topic.meta.name
  case
    name == ""
    || name == "."
    || name == ".."
    || list.any(["/", "\\", ":", "\u{0}"], string.contains(name, _))
  {
    True -> Error(UnsafeTopic(name))
    False -> Ok(Nil)
  }
}

fn absolute_path(
  path: String,
  working_directory: String,
) -> Result(String, PlanError) {
  let absolute = case filepath.is_absolute(path) {
    True -> path
    False -> filepath.join(working_directory, path)
  }
  absolute
  |> filepath.expand
  |> result.map_error(fn(_) { InvalidPath(path) })
}

fn relative_directory(from: String, to: String) -> String {
  let segments = relative_segments(filepath.split(from), filepath.split(to))
  case segments {
    [] -> "."
    _ -> string.join(segments, "/")
  }
}

fn relative_segments(from: List(String), to: List(String)) -> List(String) {
  case from, to {
    [parent, ..parents], [child, ..children] if parent == child ->
      relative_segments(parents, children)
    _, _ -> list.append(list.repeat("..", list.length(from)), to)
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn to_render_options(options: PlanOptions) -> glint_markdown.Options {
  let base = glint_markdown.options(options.bin)
  let base = case options.include_hidden {
    True -> glint_markdown.Options(..base, include_hidden: True)
    False -> base
  }
  case options.repository_prefix {
    Some(prefix) -> glint_markdown.with_repository_prefix(base, prefix)
    None -> base
  }
}
