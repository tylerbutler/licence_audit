//// Workflow for the `update` subcommand: discover licences from the locked
//// manifest, review the current policy interactively or apply explicit edits,
//// then preview or write `[tools.licence_audit]` in the selected TOML file.

import gleam/dict
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import licence_audit/cache
import licence_audit/cli
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
  options: cli.UpdateOptions,
  source_clients: notice.Clients,
  reporter: progress.Reporter,
) -> #(UpdateResult, progress.Reporter) {
  run_with_terminal_check(
    manifest_path,
    project_root,
    options,
    source_clients,
    reporter,
    stdin_is_tty: fn() { tty.is_tty(tty.Stdin) },
    stdout_is_tty: fn() { tty.is_tty(tty.Stdout) },
  )
}

/// Check the interactive picker path before policy or metadata discovery.
pub fn run_with_terminal_check(
  manifest_path: String,
  project_root: String,
  options: cli.UpdateOptions,
  source_clients: notice.Clients,
  reporter: progress.Reporter,
  stdin_is_tty stdin_is_tty: fn() -> Bool,
  stdout_is_tty stdout_is_tty: fn() -> Bool,
) -> #(UpdateResult, progress.Reporter) {
  case headless(options) {
    True ->
      run_with_picker(
        manifest_path,
        project_root,
        options,
        source_clients,
        picker.pick,
        reporter,
      )
    False ->
      case stdin_is_tty(), stdout_is_tty() {
        True, True ->
          run_with_picker(
            manifest_path,
            project_root,
            options,
            source_clients,
            picker.pick,
            reporter,
          )
        _, _ -> #(not_interactive(), reporter)
      }
  }
}

fn headless(options: cli.UpdateOptions) -> Bool {
  option.is_some(options.allow)
  || option.is_some(options.deny)
  || options.dry_run
}

fn not_interactive() -> UpdateResult {
  UpdateDiagnostic(
    exit_code: 2,
    output: "Error: The update picker requires an interactive terminal on stdin and stdout\n",
  )
}

/// Run with an injected picker. Explicit edits and dry-run skip the picker.
pub fn run_with_picker(
  manifest_path: String,
  project_root: String,
  options: cli.UpdateOptions,
  source_clients: notice.Clients,
  pick: fn(String, List(String), List(String), List(String)) ->
    Result(picker.Selection, picker.PickerError),
  reporter: progress.Reporter,
) -> #(UpdateResult, progress.Reporter) {
  let reporter = progress.phase(reporter, "Starting licence policy update")

  let outcome = {
    use #(existing, proposed) <- result.try(
      load_existing_policy(options.config_path, project_root)
      |> result.try(fn(existing) {
        proposed_policy(existing, options.allow, options.deny)
        |> result.map(fn(proposed) { #(existing, proposed) })
      })
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

    let cache_mode = cache.mode_for(options.no_cache, options.cache_dir)
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
        case headless(options) {
          True ->
            write_selection(
              existing,
              proposed.allow,
              proposed.deny,
              options,
              project_root,
              cache_warning,
              Some(discovered),
              reporter,
            )
          False ->
            handle_selection(
              existing,
              discovered,
              options,
              project_root,
              cache_warning,
              pick,
              reporter,
            )
        }
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
  options: cli.UpdateOptions,
  project_root: String,
  cache_warning: Option(String),
  pick: fn(String, List(String), List(String), List(String)) ->
    Result(picker.Selection, picker.PickerError),
  reporter: progress.Reporter,
) -> #(UpdateResult, progress.Reporter) {
  let reporter = progress.detail(reporter, "Awaiting selection")
  let #(discovered, invalid) =
    list.partition(discovered, fn(label) {
      result.is_ok(spdx_expression.parse(label))
    })
  let labels = merge_labels(existing, discovered)
  let title =
    "Allow which licences? ("
    <> int.to_string(list.length(labels))
    <> " total, "
    <> int.to_string(list.length(only_new(existing, discovered)))
    <> " new)"
  let title = title <> invalid_label_message(invalid)
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
        options,
        project_root,
        cache_warning,
        None,
        reporter,
      )
    }
  }
}

/// Validate the edit, then preview or write it and report the outcome.
fn write_selection(
  activation: config.Policy,
  allow: List(String),
  deny: List(String),
  options: cli.UpdateOptions,
  project_root: String,
  cache_warning: Option(String),
  discovered: Option(List(String)),
  reporter: progress.Reporter,
) -> #(UpdateResult, progress.Reporter) {
  let target = resolve_output_path(options.config_path, project_root)
  case write_policy(target, activation, allow, deny, options.dry_run) {
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
      let reporter = case options.dry_run {
        True -> progress.success(reporter, "Policy preview ready")
        False -> progress.success(reporter, "Wrote " <> target)
      }
      let reporter = case allow, options.dry_run {
        [], False ->
          progress.warn(
            reporter,
            "The saved policy has an empty allow list. Add allow rules before running check --checks=licences or check --checks=all.",
          )
        _, _ -> reporter
      }
      let reporter = warn_cache(reporter, cache_warning)
      let proposed = config.Policy(..activation, allow: allow, deny: deny)
      let output = case discovered {
        None -> ""
        Some(labels) -> proposal_summary(proposed, labels)
      }
      let output =
        output
        <> case options.dry_run {
          True -> "Dry run: no policy file written.\n"
          False -> summary(target, allow, deny)
        }
      #(UpdateResult(exit_code: 0, output: output), reporter)
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

/// Replace supplied lists, preserve omitted lists and all other policy fields.
/// Validate the existing policy before applying edits; update cannot repair it.
pub fn proposed_policy(
  existing: config.Policy,
  allow: Option(List(String)),
  deny: Option(List(String)),
) -> Result(config.Policy, config.Error) {
  use existing <- result.try(config.validate(existing))
  config.Policy(
    ..existing,
    allow: option.unwrap(allow, existing.allow),
    deny: option.unwrap(deny, existing.deny),
  )
  |> config.validate
}

/// Report declarations in neither list, not enforcement findings from check.
pub fn uncovered_licences(
  proposed: config.Policy,
  discovered: List(String),
) -> List(String) {
  only_new(proposed, discovered)
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
      <> " changed during update; rerun update."
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
  dry_run: Bool,
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
  use _ <- result.try(
    proposed_policy(current, Some(allow), Some(deny))
    |> result.map_error(InvalidPolicy),
  )
  let section = ["tools", "licence_audit"]
  case toml.set_string_array(existing, section, "allow", allow) {
    Error(e) -> Error(TomlEditFailed(e))
    Ok(after_allow) ->
      case toml.set_string_array(after_allow, section, "deny", deny) {
        Error(e) -> Error(TomlEditFailed(e))
        Ok(after_both) -> {
          use _ <- result.try(
            config.parse(after_both) |> result.map_error(InvalidPolicy),
          )
          case dry_run {
            True -> Ok(Nil)
            False ->
              case atomic_write(path, after_both) {
                Ok(_) -> Ok(Nil)
                Error(_) -> Error(FileWriteFailed(path))
              }
          }
        }
      }
  }
}

fn invalid_label_message(invalid: List(String)) -> String {
  case invalid {
    [] -> ""
    _ ->
      "\nNot selectable (invalid SPDX expressions): "
      <> string.join(
        list.map(invalid, fn(label) { json.to_string(json.string(label)) }),
        ", ",
      )
      <> "\nUse a reviewed invalid-licence-expression exception for the exact package/version and raw label."
  }
}

fn proposal_summary(
  proposed: config.Policy,
  discovered: List(String),
) -> String {
  let discovered = discovered |> list.unique |> list.sort(string.compare)
  let invalid =
    list.filter(discovered, fn(label) {
      result.is_error(spdx_expression.parse(label))
    })
  "Discovered licences: "
  <> json.to_string(json.array(discovered, json.string))
  <> invalid_label_message(invalid)
  <> "\nUncovered licences (in neither list): "
  <> json.to_string(json.array(
    uncovered_licences(proposed, discovered),
    json.string,
  ))
  <> "\nProposed policy edit:\n[tools.licence_audit]\nallow = "
  <> json.to_string(json.array(proposed.allow, json.string))
  <> "\ndeny = "
  <> json.to_string(json.array(proposed.deny, json.string))
  <> "\n"
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
