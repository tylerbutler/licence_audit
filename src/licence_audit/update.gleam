//// Workflow for the `update` subcommand: discover licences from the locked
//// manifest, present an interactive picker preselected with the current
//// policy, then write the result back to `gleam.toml` under
//// `[tools.licence_audit]`.

import gleam/dict
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import licence_audit/cache
import licence_audit/config
import licence_audit/error
import licence_audit/hex
import licence_audit/manifest
import licence_audit/network
import licence_audit/notice
import licence_audit/path
import licence_audit/picker
import licence_audit/progress
import licence_audit/spdx_expression
import licence_audit/toml
import simplifile
import tty

pub type UpdateResult {
  UpdateResult(exit_code: Int, output: String)
  UpdateDiagnostic(exit_code: Int, output: String)
}

pub fn run(
  manifest_path: String,
  project_root: String,
  config_path: Option(String),
  no_cache: Bool,
  cache_root: Option(String),
  source_clients: notice.Clients,
  reporter: progress.Reporter,
) -> #(UpdateResult, progress.Reporter) {
  run_with_terminal_check(
    manifest_path,
    project_root,
    config_path,
    no_cache,
    cache_root,
    source_clients,
    reporter,
    stdin_is_tty: fn() { tty.is_tty(tty.Stdin) },
    stdout_is_tty: fn() { tty.is_tty(tty.Stdout) },
  )
}

/// Check the real picker path before policy, manifest, or metadata discovery.
pub fn run_with_terminal_check(
  manifest_path: String,
  project_root: String,
  config_path: Option(String),
  no_cache: Bool,
  cache_root: Option(String),
  source_clients: notice.Clients,
  reporter: progress.Reporter,
  stdin_is_tty stdin_is_tty: fn() -> Bool,
  stdout_is_tty stdout_is_tty: fn() -> Bool,
) -> #(UpdateResult, progress.Reporter) {
  case stdin_is_tty(), stdout_is_tty() {
    True, True ->
      run_with_picker(
        manifest_path,
        project_root,
        config_path,
        no_cache,
        cache_root,
        source_clients,
        picker.pick,
        reporter,
      )
    _, _ -> #(not_interactive(), reporter)
  }
}

fn not_interactive() -> UpdateResult {
  UpdateDiagnostic(
    exit_code: 2,
    output: "Error: The update picker requires an interactive terminal on stdin and stdout\n",
  )
}

/// Run the update workflow with an injected picker, allowing tests to drive the
/// interactive selection step headlessly.
pub fn run_with_picker(
  manifest_path: String,
  project_root: String,
  config_path: Option(String),
  no_cache: Bool,
  cache_root: Option(String),
  source_clients: notice.Clients,
  pick: fn(String, List(String), List(String), List(String)) ->
    Result(picker.Selection, picker.PickerError),
  reporter: progress.Reporter,
) -> #(UpdateResult, progress.Reporter) {
  let reporter = progress.phase(reporter, "Starting licence policy update")

  let outcome = {
    use existing <- result.try(
      load_existing_policy(config_path, project_root)
      |> result.map_error(fn(config_error) {
        #(
          UpdateDiagnostic(
            exit_code: error.exit_code(error.from_config_error(config_error)),
            output: "Error: "
              <> error.message(error.from_config_error(config_error))
              <> "\n",
          ),
          reporter,
        )
      }),
    )
    let reporter = progress.detail(reporter, "Loading package manifest")
    use locked <- result.try(
      manifest.load(manifest_path)
      |> result.map_error(fn(err) {
        #(
          UpdateDiagnostic(
            exit_code: error.exit_code(error.from_manifest_error(err)),
            output: "Error: "
              <> error.message(error.from_manifest_error(err))
              <> "\n",
          ),
          reporter,
        )
      }),
    )
    let reporter =
      progress.package_count(reporter, list.length(locked.packages))

    let cache_mode = case no_cache {
      True -> cache.Disabled
      False -> cache.Enabled(path: cache_root)
    }
    let cache_handle = cache.open(cache_mode)
    let cached_fetcher =
      cache.wrap_locked(cache_handle, fn(name, version, checksum) {
        notice.hex_metadata_from_locked_source(
          name,
          version,
          checksum,
          source_clients.fetch_hex_tarball,
        )
      })

    let #(discovered, fetch_failed, reporter) =
      discover_licences(locked.packages, cached_fetcher, reporter, [], False)
    let cache_warning = cache.close(cache_handle)

    Ok(case fetch_failed {
      True -> {
        let reporter =
          progress.fail(reporter, "Could not gather all package licences")
        let reporter = warn_cache(reporter, cache_warning)
        #(
          UpdateDiagnostic(
            exit_code: 2,
            output: "Error: failed to fetch metadata for one or more packages\n",
          ),
          reporter,
        )
      }
      False ->
        handle_selection(
          existing,
          discovered,
          config_path,
          project_root,
          cache_warning,
          pick,
          reporter,
        )
    })
  }
  case outcome {
    Ok(outcome) | Error(outcome) -> outcome
  }
}

/// Present the picker preselected with the current policy and act on the
/// result: cancel, report a non-interactive terminal, or write the selection.
fn handle_selection(
  existing: config.Policy,
  discovered: List(String),
  config_path: Option(String),
  project_root: String,
  cache_warning: Option(String),
  pick: fn(String, List(String), List(String), List(String)) ->
    Result(picker.Selection, picker.PickerError),
  reporter: progress.Reporter,
) -> #(UpdateResult, progress.Reporter) {
  let reporter = progress.detail(reporter, "Awaiting selection")
  let labels = merge_labels(existing, discovered)
  let title =
    "Allow which licences? ("
    <> int.to_string(list.length(labels))
    <> " total, "
    <> int.to_string(list.length(only_new(existing, discovered)))
    <> " new)"
  case pick(title, labels, existing.allow, existing.deny) {
    Error(picker.Cancelled) -> {
      let reporter = progress.warn(reporter, "Update cancelled")
      let reporter = warn_cache(reporter, cache_warning)
      #(
        UpdateDiagnostic(exit_code: 130, output: "Update cancelled.\n"),
        reporter,
      )
    }
    Error(picker.NotInteractive) -> {
      let reporter = warn_cache(reporter, cache_warning)
      #(not_interactive(), reporter)
    }
    Ok(selection) -> {
      let initial =
        picker.new_state(title, labels, existing.allow, existing.deny)
        |> picker.state_selection
      // Retain overlapping rules: dropping the last allow rule widens reports.
      let picker.Selection(allow, deny) = case selection == initial {
        True -> picker.Selection(existing.allow, existing.deny)
        False -> selection
      }
      write_selection(
        existing,
        allow,
        deny,
        config_path,
        project_root,
        cache_warning,
        reporter,
      )
    }
  }
}

/// Write the chosen policy to disk and report success or failure.
fn write_selection(
  activation: config.Policy,
  allow: List(String),
  deny: List(String),
  config_path: Option(String),
  project_root: String,
  cache_warning: Option(String),
  reporter: progress.Reporter,
) -> #(UpdateResult, progress.Reporter) {
  let target = resolve_output_path(config_path, project_root)
  case write_policy(target, activation, allow, deny) {
    Error(error) -> {
      let message = write_error_message(error)
      let exit_code = case error {
        FileReadFailed(_, _) -> error.exit_code(error.Input(message))
        TomlEditFailed(_) -> error.exit_code(error.Config(message))
        InvalidPolicy(_) -> error.exit_code(error.Config(message))
        PolicyChanged(_) -> error.exit_code(error.Config(message))
        FileWriteFailed(_) -> error.exit_code(error.Input(message))
      }
      let reporter = progress.fail(reporter, message)
      let reporter = warn_cache(reporter, cache_warning)
      #(
        UpdateDiagnostic(
          exit_code: exit_code,
          output: "Error: " <> message <> "\n",
        ),
        reporter,
      )
    }
    Ok(_) -> {
      let reporter = progress.success(reporter, "Wrote " <> target)
      let reporter = case allow {
        [] ->
          progress.warn(
            reporter,
            "The saved policy has an empty allow list. Add allow rules before running check --checks=licences or check --checks=all.",
          )
        _ -> reporter
      }
      let reporter = warn_cache(reporter, cache_warning)
      #(
        UpdateResult(exit_code: 0, output: summary(target, allow, deny)),
        reporter,
      )
    }
  }
}

fn discover_licences(
  packages: List(manifest.Package),
  fetcher: fn(manifest.Package, progress.Reporter) ->
    #(Result(hex.PackageMetadata, notice.Error), progress.Reporter),
  reporter: progress.Reporter,
  collected: List(String),
  failed: Bool,
) -> #(List(String), Bool, progress.Reporter) {
  let outcomes =
    network.fetch(
      packages,
      fn(package) { package.name <> "@" <> package.version },
      fn(package) { fetcher(package, progress.fork(reporter)) },
    )
  let #(collected, failed, reporter) =
    list.fold(
      list.zip(packages, outcomes),
      #(collected, failed, reporter),
      fn(acc, pair) {
        let #(collected, failed, reporter) = acc
        let #(pkg, outcome) = pair
        let #(fetched, reporter) = case outcome {
          Ok(#(fetched, captured)) -> #(
            result.map_error(fetched, notice.describe_error),
            progress.merge(reporter, captured),
          )
          Error(reason) -> #(Error(reason), reporter)
        }
        case fetched {
          Error(reason) -> {
            let reporter =
              progress.fail(
                reporter,
                "Failed to fetch package metadata for "
                  <> pkg.name
                  <> "@"
                  <> pkg.version
                  <> ": "
                  <> reason,
              )
            #(collected, True, reporter)
          }
          Ok(metadata) -> {
            #(list.append(collected, metadata.licences), failed, reporter)
          }
        }
      },
    )
  #(list.unique(collected), failed, reporter)
}

fn load_existing_policy(
  config_path: Option(String),
  project_root: String,
) -> Result(config.Policy, config.Error) {
  let path = resolve_output_path(config_path, project_root)
  case simplifile.read(path) {
    Ok(contents) -> parse_existing_policy(contents)
    Error(simplifile.Enoent) -> {
      // Windows also reports Enoent when an existing ancestor is not a directory.
      case validate_policy_parent(path.dirname(path)) {
        Ok(Nil) -> Ok(empty_policy())
        Error(Nil) -> Error(config.FileReadError(path))
      }
    }
    Error(_) -> Error(config.FileReadError(path))
  }
}

fn validate_policy_parent(directory: String) -> Result(Nil, Nil) {
  case simplifile.file_info(directory) {
    Ok(info) ->
      case simplifile.file_info_type(info) == simplifile.Directory {
        True -> Ok(Nil)
        False -> Error(Nil)
      }
    Error(simplifile.Enoent) -> {
      let parent = path.dirname(directory)
      case parent == directory {
        True -> Error(Nil)
        False -> validate_policy_parent(parent)
      }
    }
    Error(_) -> Error(Nil)
  }
}

fn parse_existing_policy(
  contents: String,
) -> Result(config.Policy, config.Error) {
  case config.parse(contents) {
    Ok(policy) -> Ok(policy)
    Error(config.MissingPolicy) -> Ok(empty_policy())
    Error(error) -> Error(error)
  }
}

fn empty_policy() -> config.Policy {
  config.Policy(
    exceptions: [],
    allow: [],
    deny: [],
    vuln_severity: None,
    vuln_block_unknown: False,
  )
}

fn merge_labels(
  existing: config.Policy,
  discovered: List(String),
) -> List(String) {
  []
  |> list.append(existing.allow)
  |> list.append(existing.deny)
  |> list.append(discovered)
  // dict.from_list keeps the last value; retain the first configured spelling.
  |> list.reverse
  |> list.map(fn(label) { #(spdx_expression.matching_tokens(label), label) })
  |> dict.from_list
  |> dict.values
  |> list.sort(string.compare)
}

fn only_new(existing: config.Policy, discovered: List(String)) -> List(String) {
  let known =
    list.append(existing.allow, existing.deny)
    |> list.map(spdx_expression.matching_tokens)
  merge_labels(empty_policy(), discovered)
  |> list.filter(fn(label) {
    !list.contains(known, spdx_expression.matching_tokens(label))
  })
}

fn resolve_output_path(
  config_path: Option(String),
  project_root: String,
) -> String {
  case config_path {
    Some(path) -> path
    None -> project_root <> "/gleam.toml"
  }
}

type WriteError {
  TomlEditFailed(toml.Error)
  InvalidPolicy(config.Error)
  PolicyChanged(path: String)
  FileReadFailed(path: String, reason: simplifile.FileError)
  FileWriteFailed(path: String)
}

fn write_error_message(error: WriteError) -> String {
  case error {
    TomlEditFailed(e) -> toml.error_message(e)
    InvalidPolicy(e) -> error.message(error.from_config_error(e))
    PolicyChanged(path) ->
      "Policy conflict: allow or deny rules in "
      <> path
      <> " changed during selection; rerun update."
    FileReadFailed(path, reason) ->
      "Failed to read " <> path <> ": " <> simplifile.describe_error(reason)
    FileWriteFailed(path) -> "Failed to write " <> path
  }
}

fn write_policy(
  path: String,
  activation: config.Policy,
  allow: List(String),
  deny: List(String),
) -> Result(Nil, WriteError) {
  use existing <- result.try(case simplifile.read(from: path) {
    Ok(contents) -> Ok(contents)
    Error(simplifile.Enoent) -> Ok("")
    Error(reason) -> Error(FileReadFailed(path, reason))
  })
  use current <- result.try(
    parse_existing_policy(existing) |> result.map_error(InvalidPolicy),
  )
  use _ <- result.try(
    case current.allow == activation.allow && current.deny == activation.deny {
      True -> Ok(Nil)
      False -> Error(PolicyChanged(path))
    },
  )
  let section = ["tools", "licence_audit"]
  case toml.set_string_array(existing, section, "allow", allow) {
    Error(e) -> Error(TomlEditFailed(e))
    Ok(after_allow) ->
      case toml.set_string_array(after_allow, section, "deny", deny) {
        Error(e) -> Error(TomlEditFailed(e))
        Ok(after_both) ->
          case atomic_write(path, after_both) {
            Ok(_) -> Ok(Nil)
            Error(_) -> Error(FileWriteFailed(path))
          }
      }
  }
}

@external(erlang, "policy_file_ffi", "write")
fn atomic_write(path: String, contents: String) -> Result(Nil, Nil)

fn summary(path: String, allow: List(String), deny: List(String)) -> String {
  "Wrote "
  <> path
  <> " ("
  <> int.to_string(list.length(allow))
  <> " allowed, "
  <> int.to_string(list.length(deny))
  <> " denied).\n"
}

fn warn_cache(
  reporter: progress.Reporter,
  warning: Option(String),
) -> progress.Reporter {
  case warning {
    Some(message) -> progress.warn(reporter, message)
    None -> reporter
  }
}
