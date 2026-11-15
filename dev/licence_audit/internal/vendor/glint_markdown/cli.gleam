//// Ready-made `gen-docs` subcommand for hosting `glint_markdown` inside a
//// `glint`-based application.
////
//// Most users want one-line integration via [`mount`](#mount):
////
//// ```gleam
//// import glint
//// import glint_markdown/cli as glint_markdown_cli
////
//// pub fn main() {
////   glint.new()
////   |> glint.with_name("myapp")
////   |> glint.add(at: ["greet"], do: greet_cmd())
////   |> glint_markdown_cli.mount(at: ["gen-docs"])
////   |> glint.run(argv.load().arguments)
//// }
//// ```
////
//// The resulting `myapp gen-docs` subcommand renders the rest of the CLI's
//// command tree as Markdown — to stdout by default, or to one or more files
//// when `--out` / `--readme` are passed. See the flag list in
//// [`command`](#command) for the full surface.

// Vendored from vendor/glint_markdown/src/glint_markdown/cli.gleam at 9c66ec3a62e43c639b06c3dfa582f223fc2fef14.
// Modified for licence_audit vendoring. Run just vendor-sync to update.

import gleam/bool
import gleam/int
import gleam/list
import gleam/option
import gleam/result
import licence_audit/internal/vendor/glint
import licence_audit/internal/vendor/glint/help
import licence_audit/internal/vendor/glint_markdown/internal/exit
import licence_audit/internal/vendor/glint_markdown/internal/io as file_io
import licence_audit/internal/vendor/glint_markdown/internal/plan
import simplifile

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Build the `gen-docs` subcommand from a pre-computed `Tree`.
///
/// Use this when you need finer control than [`mount`](#mount) — e.g. you
/// want to customise the placement, or your host CLI is `Glint(a)` with
/// `a != Nil` and you need to thread the return type through
/// [`glint.map_command`](https://hexdocs.pm/glint/glint.html#map_command):
///
/// ```gleam
/// app
/// |> glint.add(
///   at: ["docs"],
///   do: glint_markdown_cli.command(glint.document(app))
///     |> glint.map_command(fn(_) { my_default_return_value }),
/// )
/// ```
///
/// ## Flags
///
/// | Flag | Type | Default | Notes |
/// |------|------|---------|-------|
/// | `--mode` | string | `single` | `single` \| `multi` |
/// | `--out` | string | — | file (single) or directory (multi, defaults to `./docs`) |
/// | `--readme` | string | — | inject into an existing README between sentinels |
/// | `--repo-prefix` | string | — | passed to `with_repository_prefix` |
/// | `--include-hidden` | bool | `false` | include hidden commands |
/// | `--no-toc` | bool | `false` | skip TOC in single-file mode |
/// | `--check` | bool | `false` | render + diff, exit 1 if differs, write nothing |
/// | `--quiet` | bool | `false` | suppress the "wrote N files" summary |
pub fn command(tree: help.Tree) -> glint.Command(Nil) {
  use <- glint.command_help(
    "Generate Markdown reference documentation from this CLI.",
  )
  use mode_get <- glint.flag(
    glint.string_flag("mode")
    |> glint.flag_default("single")
    |> glint.flag_help("Output mode: 'single' or 'multi'."),
  )
  use output_get <- glint.flag(
    glint.string_flag("out")
    |> glint.flag_help(
      "Output file (single mode) or directory (multi mode, defaults to './docs').",
    ),
  )
  use readme_get <- glint.flag(
    glint.string_flag("readme")
    |> glint.flag_help(
      "Inject rendered Markdown into the README at this path between sentinel comments.",
    ),
  )
  use repository_prefix_get <- glint.flag(
    glint.string_flag("repo-prefix")
    |> glint.flag_help(
      "Repository URL prefix used for '_See code:_' links beneath each command.",
    ),
  )
  use include_hidden_get <- glint.flag(
    glint.bool_flag("include-hidden")
    |> glint.flag_default(False)
    |> glint.flag_help("Include hidden commands in the rendered output."),
  )
  use no_toc_get <- glint.flag(
    glint.bool_flag("no-toc")
    |> glint.flag_default(False)
    |> glint.flag_help("Skip the table of contents in single-file mode."),
  )
  use check_get <- glint.flag(
    glint.bool_flag("check")
    |> glint.flag_default(False)
    |> glint.flag_help(
      "Don't write; exit 1 if any file on disk would differ from the rendered output.",
    ),
  )
  use quiet_get <- glint.flag(
    glint.bool_flag("quiet")
    |> glint.flag_default(False)
    |> glint.flag_help("Suppress the 'wrote N files' summary line."),
  )

  use _named, _arguments, flags <- glint.command()

  let mode_raw = result.unwrap(mode_get(flags), "single")
  let output = option.from_result(output_get(flags))
  let readme = option.from_result(readme_get(flags))
  let repository_prefix = option.from_result(repository_prefix_get(flags))
  let include_hidden = result.unwrap(include_hidden_get(flags), False)
  let no_toc = result.unwrap(no_toc_get(flags), False)
  let check = result.unwrap(check_get(flags), False)
  let quiet = result.unwrap(quiet_get(flags), False)

  case plan.parse_mode(mode_raw) {
    Error(error) -> {
      exit.stderr("glint_markdown: " <> plan.describe_error(error) <> "\n")
      exit.exit_with(2)
      Nil
    }
    Ok(mode_choice) -> {
      let bin = case tree.meta.name {
        "" -> "app"
        name -> name
      }
      case simplifile.current_directory() {
        Error(reason) ->
          report_errors([
            "could not read working directory: "
            <> simplifile.describe_error(reason),
          ])
        Ok(working_directory) -> {
          let options =
            plan.PlanOptions(
              bin: bin,
              working_directory: working_directory,
              mode: mode_choice,
              output: output,
              readme: readme,
              repository_prefix: repository_prefix,
              include_hidden: include_hidden,
              no_toc: no_toc,
            )
          run_plan(tree, options, check, quiet)
        }
      }
    }
  }
}

/// One-line integration: registers a `gen-docs` subcommand at `path` that
/// renders this CLI's command tree as Markdown.
///
/// The tree handed to the subcommand is computed via
/// [`glint.document`](https://hexdocs.pm/glint/glint.html#document) on `app`
/// **before** `gen-docs` itself is added — so `gen-docs` deliberately does
/// not show up inside its own rendered output. (If you want it to appear,
/// build the tree yourself with the desired ordering and use
/// [`command`](#command) directly.)
///
/// ## Restriction: `Glint(Nil)` only
///
/// `mount` is intentionally restricted to apps whose command return type is
/// `Nil`. This is the overwhelmingly common case (most glint apps print
/// directly and return `Nil`). For apps with a non-`Nil` return type, use
/// the lower-level [`command`](#command) function with `glint.map_command`
/// to bridge the type — see the example in `command`'s docs.
pub fn mount(app: glint.Glint(Nil), at path: List(String)) -> glint.Glint(Nil) {
  glint.add(app, at: path, do: command(glint.document(app)))
}

// ---------------------------------------------------------------------------
// Internal: runner
// ---------------------------------------------------------------------------

fn run_plan(
  tree: help.Tree,
  options: plan.PlanOptions,
  check: Bool,
  quiet: Bool,
) -> Nil {
  case plan.plan(tree, options) {
    Error(error) -> report_errors([plan.describe_error(error)])
    Ok(actions) -> execute_plan(actions, check, quiet)
  }
}

fn execute_plan(actions: List(plan.Action), check: Bool, quiet: Bool) -> Nil {
  // The CLI owns all human-facing summary output, so suppress the
  // internal io module's own log line by passing `quiet: True`.
  case file_io.execute(actions, check, True) {
    Ok(summary) -> report_summary(summary, quiet)
    Error(diagnostics) -> report_errors(diagnostics)
  }
}

fn report_summary(summary: file_io.Summary, quiet: Bool) -> Nil {
  use <- bool.guard(quiet, Nil)
  exit.stderr(
    "glint_markdown: wrote "
    <> int.to_string(summary.written)
    <> ", injected "
    <> int.to_string(summary.injected)
    <> ", unchanged "
    <> int.to_string(summary.unchanged)
    <> "\n",
  )
}

fn report_errors(diagnostics: List(String)) -> Nil {
  list.each(diagnostics, fn(diagnostic) {
    exit.stderr("glint_markdown: " <> diagnostic <> "\n")
  })
  exit.exit_with(1)
  Nil
}
