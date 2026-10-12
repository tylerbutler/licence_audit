//// Side-effecting execution layer for plans produced by
//// [`glint_markdown/internal/plan`](./plan.html).
////
//// This module is intentionally tiny: it walks a list of `Action`s and either
//// applies them to disk (normal mode) or compares them to disk and reports
//// would-change descriptions (check mode). It never calls `exit_with` itself —
//// the caller decides how to surface failures.

import gleam/bool
import gleam/int
import gleam/io
import gleam/list
import gleam/string
import glint_markdown
import glint_markdown/internal/plan.{
  type Action, InjectFile, WriteFile, WriteStdout,
}
import simplifile

/// Errors surfaced by [`execute`](#execute). Each variant carries enough
/// context for the caller to render a human-readable stderr line.
pub type IoError {
  ReadFailed(path: String, reason: String)
  WriteFailed(path: String, reason: String)
  /// The injection target file exists but does not contain the
  /// `<!-- tag -->` sentinel, so [`glint_markdown.inject`](../glint_markdown.html#inject)
  /// would silently no-op.
  MissingMarker(path: String, tag: String)
}

/// Counters returned on a successful [`execute`](#execute).
pub type Summary {
  Summary(written: Int, injected: Int, unchanged: Int)
}

/// Execute the given actions.
///
/// - When `check` is `True`, no files are written. Any prospective change is
///   collected into the `Error` list as a human-readable description (e.g.
///   `"would create docs/REF.md"` or `"would change README.md (tag: commands)"`).
///   The function returns `Ok(summary)` only when every action would leave
///   the filesystem byte-for-byte unchanged.
/// - When `check` is `False`, actions are applied. Files whose contents
///   already match are skipped to avoid touching mtimes.
///
/// `WriteStdout` in check mode is treated as always "would differ" — there is
/// no file to compare against, so `--check` is only meaningful in combination
/// with `--out` or `--readme`.
pub fn execute(
  actions: List(Action),
  check: Bool,
  quiet: Bool,
) -> Result(Summary, List(String)) {
  let init = Summary(written: 0, injected: 0, unchanged: 0)
  let #(summary, errors) =
    list.fold(actions, #(init, []), fn(acc, action) {
      let #(s, errs) = acc
      case run_action(action, s, check) {
        Ok(next) -> #(next, errs)
        Error(msg) -> #(s, [msg, ..errs])
      }
    })

  case errors {
    [] -> {
      use <- bool.guard(quiet, Ok(summary))
      log_summary(summary, check)
      Ok(summary)
    }
    _ -> Error(list.reverse(errors))
  }
}

fn run_action(
  action: Action,
  summary: Summary,
  check: Bool,
) -> Result(Summary, String) {
  case action {
    WriteStdout(contents) -> handle_stdout(contents, summary, check)
    WriteFile(path, contents) ->
      handle_write_file(path, contents, summary, check)
    InjectFile(path, tag, body) ->
      handle_inject_file(path, tag, body, summary, check)
  }
}

fn handle_stdout(
  contents: String,
  summary: Summary,
  check: Bool,
) -> Result(Summary, String) {
  case check {
    True ->
      Error("--check requires --out or --readme; cannot diff against stdout")
    False -> {
      io.println(contents)
      Ok(Summary(..summary, written: summary.written + 1))
    }
  }
}

fn handle_write_file(
  path: String,
  contents: String,
  summary: Summary,
  check: Bool,
) -> Result(Summary, String) {
  case check {
    True ->
      case simplifile.read(path) {
        Ok(existing) if existing == contents ->
          Ok(Summary(..summary, unchanged: summary.unchanged + 1))
        Ok(existing) ->
          Error(diff_hint("would change", path, existing, contents))
        Error(simplifile.Enoent) -> Error("would create " <> path)
        Error(reason) ->
          Error("could not read " <> path <> ": " <> describe(reason))
      }
    False ->
      case maybe_skip_write(path, contents) {
        Ok(True) -> Ok(Summary(..summary, unchanged: summary.unchanged + 1))
        Ok(False) ->
          case ensure_parent_dir(path) {
            Error(reason) ->
              Error(
                "could not create parent of "
                <> path
                <> ": "
                <> describe(reason),
              )
            Ok(_) ->
              case simplifile.write(to: path, contents: contents) {
                Ok(_) -> Ok(Summary(..summary, written: summary.written + 1))
                Error(reason) ->
                  Error("could not write " <> path <> ": " <> describe(reason))
              }
          }
        Error(reason) ->
          Error("could not read " <> path <> ": " <> describe(reason))
      }
  }
}

fn handle_inject_file(
  path: String,
  tag: String,
  body: String,
  summary: Summary,
  check: Bool,
) -> Result(Summary, String) {
  case simplifile.read(path) {
    Error(simplifile.Enoent) -> Error("inject target missing: " <> path)
    Error(reason) ->
      Error("could not read " <> path <> ": " <> describe(reason))
    Ok(existing) -> {
      let updated = glint_markdown.inject(existing, tag, body)
      case updated == existing {
        True ->
          case string.contains(existing, "<!-- " <> tag <> " -->") {
            // No marker present — inject silently no-ops. Surface this to
            // the user so they know to add the sentinel comment.
            False if body != "" ->
              Error("missing sentinel <!-- " <> tag <> " --> in " <> path)
            _ -> Ok(Summary(..summary, unchanged: summary.unchanged + 1))
          }
        False ->
          case check {
            True ->
              Error(
                "would change "
                <> path
                <> " (tag: "
                <> tag
                <> ", "
                <> int.to_string(string.byte_size(existing))
                <> " -> "
                <> int.to_string(string.byte_size(updated))
                <> " bytes)",
              )
            False ->
              case simplifile.write(to: path, contents: updated) {
                Ok(_) -> Ok(Summary(..summary, injected: summary.injected + 1))
                Error(reason) ->
                  Error("could not write " <> path <> ": " <> describe(reason))
              }
          }
      }
    }
  }
}

/// `Ok(True)` means "file on disk already matches; skip the write".
fn maybe_skip_write(
  path: String,
  contents: String,
) -> Result(Bool, simplifile.FileError) {
  case simplifile.read(path) {
    Ok(existing) -> Ok(existing == contents)
    Error(simplifile.Enoent) -> Ok(False)
    Error(reason) -> Error(reason)
  }
}

fn ensure_parent_dir(path: String) -> Result(Nil, simplifile.FileError) {
  case parent_dir(path) {
    "" -> Ok(Nil)
    "." -> Ok(Nil)
    dir -> simplifile.create_directory_all(dir)
  }
}

fn parent_dir(path: String) -> String {
  case string.split(path, "/") {
    [] -> ""
    [_] -> ""
    parts ->
      parts
      |> list.reverse
      |> list.drop(1)
      |> list.reverse
      |> string.join("/")
  }
}

fn diff_hint(
  prefix: String,
  path: String,
  existing: String,
  proposed: String,
) -> String {
  prefix
  <> " "
  <> path
  <> " ("
  <> int.to_string(string.byte_size(existing))
  <> " -> "
  <> int.to_string(string.byte_size(proposed))
  <> " bytes)"
}

fn describe(error: simplifile.FileError) -> String {
  simplifile.describe_error(error)
}

fn log_summary(summary: Summary, check: Bool) -> Nil {
  case check {
    True -> Nil
    False ->
      case summary.written + summary.injected {
        0 -> Nil
        _ ->
          io.println(
            "wrote "
            <> int.to_string(summary.written)
            <> " file(s), injected "
            <> int.to_string(summary.injected)
            <> " section(s)",
          )
      }
  }
}
