//// Side-effecting execution layer for plans produced by
//// [`glint_markdown/internal/plan`](./plan.html).
////
//// All destinations are preflighted before any output or filesystem mutation.
//// Normal mode stages replacements before renaming; check mode compares bytes.
//// It never calls `exit_with` — the caller decides how to surface failures.

import gleam/bit_array
import gleam/bool
import gleam/dict.{type Dict}
import gleam/int
import gleam/io
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import glint_markdown
import glint_markdown/internal/exit
import glint_markdown/internal/filesystem
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

type Destination {
  Destination(path: String, resolved: String, identity: Option(#(Int, Int)))
}

type PreparedAction {
  PreparedStdout(contents: String)
  PreparedWrite(destination: Destination, contents: String)
  PreparedInject(destination: Destination, tag: String, body: String)
}

type Intent {
  FullFile(contents: String)
  Injection
}

type SeenDestinations {
  SeenDestinations(
    paths: Dict(String, Intent),
    identities: Dict(#(Int, Int), Intent),
  )
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
  use prepared <- result.try(
    preflight(actions)
    |> result.map_error(fn(reason) { [reason] }),
  )
  let initial = Summary(written: 0, injected: 0, unchanged: 0)
  let #(summary, errors) =
    list.fold(prepared, #(initial, []), fn(accumulator, action) {
      let #(previous, failures) = accumulator
      case run_action(action, previous, check) {
        Ok(next) -> #(next, failures)
        Error(message) -> #(previous, [message, ..failures])
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

fn preflight(actions: List(Action)) -> Result(List(PreparedAction), String) {
  use prepared <- result.try(list.try_map(actions, prepare_action))
  let initial = SeenDestinations(dict.new(), dict.new())
  use _ <- result.try(list.try_fold(prepared, initial, record_destination))
  Ok(prepared)
}

fn prepare_action(action: Action) -> Result(PreparedAction, String) {
  case action {
    WriteStdout(contents) -> Ok(PreparedStdout(contents))
    WriteFile(path, contents) ->
      prepare_destination(path)
      |> result.map(PreparedWrite(_, contents))
    InjectFile(path, tag, body) ->
      prepare_destination(path)
      |> result.map(PreparedInject(_, tag, body))
  }
}

fn prepare_destination(path: String) -> Result(Destination, String) {
  use resolved <- result.try(
    filesystem.canonical_path(path)
    |> result.map_error(fn(reason) {
      "could not resolve destination " <> path <> ": " <> reason
    }),
  )
  case simplifile.file_info(resolved) {
    Ok(information) ->
      Ok(Destination(
        path,
        resolved,
        // Some filesystems do not supply an inode; do not make unrelated
        // destinations collide on a placeholder zero.
        case information.inode {
          0 -> None
          _ -> Some(#(information.dev, information.inode))
        },
      ))
    Error(simplifile.Enoent) -> Ok(Destination(path, resolved, None))
    Error(reason) ->
      Error(
        "could not inspect destination " <> path <> ": " <> describe(reason),
      )
  }
}

fn record_destination(
  seen: SeenDestinations,
  action: PreparedAction,
) -> Result(SeenDestinations, String) {
  case action {
    PreparedStdout(_) -> Ok(seen)
    PreparedWrite(destination, contents) ->
      record_intent(seen, destination, FullFile(contents))
    PreparedInject(destination, _, _) ->
      record_intent(seen, destination, Injection)
  }
}

fn record_intent(
  seen: SeenDestinations,
  destination: Destination,
  intent: Intent,
) -> Result(SeenDestinations, String) {
  let previous_identity = case destination.identity {
    None -> Error(Nil)
    Some(identity) -> dict.get(seen.identities, identity)
  }
  case
    conflicts(dict.get(seen.paths, destination.resolved), intent)
    || conflicts(previous_identity, intent)
  {
    True ->
      Error(
        "conflicting file actions target "
        <> destination.path
        <> " (resolved: "
        <> destination.resolved
        <> "); full-file writes cannot overlap injections or differing writes",
      )
    False -> {
      let identities = case destination.identity {
        None -> seen.identities
        Some(identity) -> dict.insert(seen.identities, identity, intent)
      }
      Ok(SeenDestinations(
        dict.insert(seen.paths, destination.resolved, intent),
        identities,
      ))
    }
  }
}

fn conflicts(previous: Result(Intent, Nil), proposed: Intent) -> Bool {
  case previous, proposed {
    Error(Nil), FullFile(_) | Error(Nil), Injection -> False
    Ok(Injection), Injection -> False
    Ok(FullFile(before)), FullFile(after) -> before != after
    Ok(Injection), FullFile(_) | Ok(FullFile(_)), Injection -> True
  }
}

fn run_action(
  action: PreparedAction,
  summary: Summary,
  check: Bool,
) -> Result(Summary, String) {
  case action {
    PreparedStdout(contents) -> handle_stdout(contents, summary, check)
    PreparedWrite(destination, contents) ->
      handle_write_file(destination, contents, summary, check)
    PreparedInject(destination, tag, body) ->
      handle_inject_file(destination, tag, body, summary, check)
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
  destination: Destination,
  contents: String,
  summary: Summary,
  check: Bool,
) -> Result(Summary, String) {
  let path = destination.path
  let proposed = bit_array.from_string(contents)
  case check {
    True ->
      case simplifile.read_bits(destination.resolved) {
        Ok(existing) if existing == proposed ->
          Ok(Summary(..summary, unchanged: summary.unchanged + 1))
        Ok(existing) ->
          Error(diff_hint("would change", path, existing, proposed))
        Error(simplifile.Enoent) -> Error("would create " <> path)
        Error(reason) ->
          Error("could not read " <> path <> ": " <> describe(reason))
      }
    False ->
      case maybe_skip_write(destination.resolved, proposed) {
        Ok(True) -> Ok(Summary(..summary, unchanged: summary.unchanged + 1))
        Ok(False) ->
          case filesystem.replace(destination.resolved, proposed) {
            Ok(_) -> Ok(Summary(..summary, written: summary.written + 1))
            Error(reason) -> Error("could not write " <> path <> ": " <> reason)
          }
        Error(reason) ->
          Error("could not read " <> path <> ": " <> describe(reason))
      }
  }
}

fn handle_inject_file(
  destination: Destination,
  tag: String,
  body: String,
  summary: Summary,
  check: Bool,
) -> Result(Summary, String) {
  let path = destination.path
  case simplifile.read_bits(destination.resolved) {
    Error(simplifile.Enoent) -> Error("inject target missing: " <> path)
    Error(reason) ->
      Error("could not read " <> path <> ": " <> describe(reason))
    Ok(existing_bytes) -> {
      use existing <- result.try(
        decode_utf8(existing_bytes)
        |> result.map_error(fn(reason) {
          "could not read injection target " <> path <> ": " <> describe(reason)
        }),
      )
      let updated = glint_markdown.inject(existing, tag, body)
      let updated_bytes = bit_array.from_string(updated)
      case updated_bytes == existing_bytes {
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
                <> int.to_string(bit_array.byte_size(existing_bytes))
                <> " -> "
                <> int.to_string(bit_array.byte_size(updated_bytes))
                <> " bytes)",
              )
            False ->
              case filesystem.replace(destination.resolved, updated_bytes) {
                Ok(_) -> Ok(Summary(..summary, injected: summary.injected + 1))
                Error(reason) ->
                  Error("could not inject " <> path <> ": " <> reason)
              }
          }
      }
    }
  }
}

/// `Ok(True)` means "file on disk already matches; skip the write".
fn maybe_skip_write(
  path: String,
  contents: BitArray,
) -> Result(Bool, simplifile.FileError) {
  case simplifile.read_bits(path) {
    Ok(existing) -> Ok(existing == contents)
    Error(simplifile.Enoent) -> Ok(False)
    Error(reason) -> Error(reason)
  }
}

fn decode_utf8(contents: BitArray) -> Result(String, simplifile.FileError) {
  // JS TextDecoder in the installed stdlib strips a leading UTF-8 BOM.
  // Prefixing ASCII protects the BOM; removing only the prefix is lossless.
  case bit_array.to_string(<<0x78, contents:bits>>) {
    Ok(prefixed) ->
      // Remove one codepoint, not one grapheme. A leading combining mark
      // joins the sentinel's grapheme on Erlang, including during splitting.
      prefixed
      |> string.to_utf_codepoints
      |> list.drop(1)
      |> string.from_utf_codepoints
      |> Ok
    Error(Nil) -> Error(simplifile.NotUtf8)
  }
}

fn diff_hint(
  prefix: String,
  path: String,
  existing: BitArray,
  proposed: BitArray,
) -> String {
  prefix
  <> " "
  <> path
  <> " ("
  <> int.to_string(bit_array.byte_size(existing))
  <> " -> "
  <> int.to_string(bit_array.byte_size(proposed))
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
          exit.stderr(
            "wrote "
            <> int.to_string(summary.written)
            <> " file(s), injected "
            <> int.to_string(summary.injected)
            <> " section(s)\n",
          )
      }
  }
}
