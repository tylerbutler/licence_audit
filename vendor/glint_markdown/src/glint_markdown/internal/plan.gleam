//// Pure planner for the `glint_markdown` CLI.
////
//// Given a parsed `glint/help.Tree` and a `PlanOpts` record describing the
//// flag surface, [`plan`](#plan) returns a list of [`Action`](#Action) values
//// describing the IO that should happen — without performing any IO itself.
////
//// The companion `glint_markdown/internal/io` module is responsible for
//// executing actions against the filesystem (and stdout).

import gleam/dict
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import glint/help.{type Tree}
import glint_markdown

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
}

/// `--mode` choice. Parsed from the raw CLI string via [`parse_mode`](#parse_mode).
pub type ModeChoice {
  SingleMode
  MultiMode
}

/// CLI flag bundle consumed by [`plan`](#plan).
pub type PlanOpts {
  PlanOpts(
    bin: String,
    mode: ModeChoice,
    out: Option(String),
    readme: Option(String),
    repo_prefix: Option(String),
    include_hidden: Bool,
    no_toc: Bool,
  )
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const default_docs_dir: String = "./docs"

const toc_tag: String = "toc"

const root_tag: String = "root"

const commands_tag: String = "commands"

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse the raw `--mode` string into a [`ModeChoice`](#ModeChoice).
pub fn parse_mode(s: String) -> Result(ModeChoice, PlanError) {
  case s {
    "single" -> Ok(SingleMode)
    "multi" -> Ok(MultiMode)
    other -> Error(InvalidMode(other))
  }
}

/// Build the list of [`Action`](#Action)s the CLI should execute.
///
/// Pure: performs no IO. See the behaviour matrix in `plan.md` for the
/// mapping from `(mode, --readme, --out)` to emitted actions.
pub fn plan(tree: Tree, opts: PlanOpts) -> Result(List(Action), PlanError) {
  case opts.mode {
    SingleMode -> Ok(plan_single(tree, opts))
    MultiMode -> Ok(plan_multi(tree, opts))
  }
}

// ---------------------------------------------------------------------------
// Single-mode planning
// ---------------------------------------------------------------------------

fn plan_single(tree: Tree, opts: PlanOpts) -> List(Action) {
  let render_opts = to_render_options(opts)
  case opts.readme {
    Some(readme_path) -> {
      // --readme wins; --out is ignored when injecting.
      let root_body = glint_markdown.to_root_body(tree, render_opts)
      let commands_body = glint_markdown.to_commands_body(tree, render_opts)
      let root_action =
        InjectFile(path: readme_path, tag: root_tag, body: root_body)
      let commands_action =
        InjectFile(path: readme_path, tag: commands_tag, body: commands_body)
      case opts.no_toc {
        True -> [root_action, commands_action]
        False -> {
          let toc_body = glint_markdown.to_toc_body(tree, render_opts)
          [
            root_action,
            InjectFile(path: readme_path, tag: toc_tag, body: toc_body),
            commands_action,
          ]
        }
      }
    }
    None -> {
      let doc = render_single_document(tree, opts, render_opts)
      case opts.out {
        Some(file) -> [WriteFile(path: file, contents: doc)]
        None -> [WriteStdout(contents: doc)]
      }
    }
  }
}

fn render_single_document(
  tree: Tree,
  opts: PlanOpts,
  render_opts: glint_markdown.Options,
) -> String {
  case opts.no_toc {
    False -> glint_markdown.to_string(tree, render_opts)
    True -> {
      // Reproduce the `to_string` layout without the TOC section so we don't
      // need to extend the public renderer API.
      let body = glint_markdown.to_commands_body(tree, render_opts)
      case body {
        "" -> "# " <> opts.bin
        _ -> "# " <> opts.bin <> "\n\n" <> body
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Multi-mode planning
// ---------------------------------------------------------------------------

fn plan_multi(tree: Tree, opts: PlanOpts) -> List(Action) {
  let dir = option.unwrap(opts.out, default_docs_dir)
  let render_opts =
    to_render_options(opts)
    |> glint_markdown.with_mode(glint_markdown.Multi(output_dir: dir))

  let file_actions =
    glint_markdown.to_files(tree, render_opts)
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

  case opts.readme {
    None -> file_actions
    Some(readme_path) -> {
      let root_body = glint_markdown.to_root_body(tree, render_opts)
      let index_body = glint_markdown.to_topics_index_body(tree, render_opts)
      list.append(file_actions, [
        InjectFile(path: readme_path, tag: root_tag, body: root_body),
        InjectFile(path: readme_path, tag: commands_tag, body: index_body),
      ])
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn to_render_options(opts: PlanOpts) -> glint_markdown.Options {
  let base = glint_markdown.options(opts.bin)
  let base = case opts.include_hidden {
    True -> glint_markdown.Options(..base, include_hidden: True)
    False -> base
  }
  case opts.repo_prefix {
    Some(prefix) -> glint_markdown.with_repository_prefix(base, prefix)
    None -> base
  }
}
