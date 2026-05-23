//// Workflow for the `update` subcommand: discover licences from the locked
//// manifest, present an interactive picker preselected with the current
//// policy, then write the result back to `gleam.toml` under
//// `[tools.licence_audit]`.

import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import licence_audit/cache
import licence_audit/config
import licence_audit/error
import licence_audit/hex
import licence_audit/manifest
import licence_audit/picker
import licence_audit/progress
import licence_audit/toml
import simplifile

pub type UpdateResult {
  UpdateResult(exit_code: Int, output: String)
}

pub fn run(
  manifest_path: String,
  project_root: String,
  config_path: Option(String),
  ignore_config: Bool,
  no_cache: Bool,
  cache_path: Option(String),
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
  reporter: progress.Reporter,
) -> #(UpdateResult, progress.Reporter) {
  let reporter = progress.phase(reporter, "Starting licence policy update")

  let existing = load_existing_policy(config_path, project_root, ignore_config)

  let reporter = progress.detail(reporter, "Loading package manifest")
  case manifest.load(manifest_path) {
    Error(err) -> #(
      UpdateResult(
        exit_code: error.exit_code(error.from_manifest_error(err)),
        output: "Error: "
          <> error.message(error.from_manifest_error(err))
          <> "\n",
      ),
      reporter,
    )
    Ok(locked) -> {
      let reporter =
        progress.package_count(reporter, list.length(locked.packages))

      let cache_mode = case no_cache {
        True -> cache.Disabled
        False -> cache.Enabled(path: cache_path)
      }
      let cache_handle = cache.open(cache_mode)
      let cached_fetcher = cache.wrap(cache_handle, fetcher)

      let #(discovered, fetch_failed, reporter) =
        discover_licences(locked.packages, cached_fetcher, reporter, [], False)
      let cache_warning = cache.close(cache_handle)

      case fetch_failed {
        True -> {
          let reporter =
            progress.fail(reporter, "Could not gather all package licences")
          let reporter = warn_cache(reporter, cache_warning)
          #(
            UpdateResult(
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
            reporter,
          )
      }
    }
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
  case picker.pick(title, labels, existing.allow, existing.deny) {
    Error(picker.Cancelled) -> {
      let reporter = progress.warn(reporter, "Update cancelled")
      let reporter = warn_cache(reporter, cache_warning)
      #(UpdateResult(exit_code: 130, output: "Update cancelled.\n"), reporter)
    }
    Error(picker.NotInteractive) -> {
      let message =
        "The update picker requires an interactive terminal on stdin and stdout"
      let reporter = progress.fail(reporter, message)
      let reporter = warn_cache(reporter, cache_warning)
      #(
        UpdateResult(exit_code: 1, output: "Error: " <> message <> "\n"),
        reporter,
      )
    }
    Ok(picker.Selection(allow, deny)) ->
      write_selection(
        allow,
        deny,
        config_path,
        project_root,
        cache_warning,
        reporter,
      )
  }
}

/// Write the chosen policy to disk and report success or failure.
fn write_selection(
  allow: List(String),
  deny: List(String),
  config_path: Option(String),
  project_root: String,
  cache_warning: Option(String),
  reporter: progress.Reporter,
) -> #(UpdateResult, progress.Reporter) {
  let target = resolve_output_path(config_path, project_root)
  case write_policy(target, allow, deny) {
    Error(error) -> {
      let message = write_error_message(error)
      let reporter = progress.fail(reporter, message)
      let reporter = warn_cache(reporter, cache_warning)
      #(
        UpdateResult(exit_code: 1, output: "Error: " <> message <> "\n"),
        reporter,
      )
    }
    Ok(_) -> {
      let reporter = progress.success(reporter, "Wrote " <> target)
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
    #(Result(hex.PackageMetadata, hex.Error), progress.Reporter),
  reporter: progress.Reporter,
  collected: List(String),
  failed: Bool,
) -> #(List(String), Bool, progress.Reporter) {
  case packages {
    [] -> #(list.unique(collected), failed, reporter)
    [pkg, ..rest] -> {
      let #(result, reporter) = fetcher(pkg, reporter)
      case result {
        Error(_) -> discover_licences(rest, fetcher, reporter, collected, True)
        Ok(metadata) -> {
          let reporter =
            progress.detail(
              reporter,
              "Fetched package metadata for " <> pkg.name,
            )
          discover_licences(
            rest,
            fetcher,
            reporter,
            list.append(collected, metadata.licences),
            failed,
          )
        }
      }
    }
  }
}

fn load_existing_policy(
  config_path: Option(String),
  project_root: String,
  ignore_config: Bool,
) -> config.Policy {
  case ignore_config {
    True -> config.Policy(allow: [], deny: [], vuln_severity: None)
    False -> {
      let load_result =
        config.load(config.LoadOptions(
          config_path: config_path,
          project_root: project_root,
          allow_licences: [],
          deny_licences: [],
          vuln_severity: None,
          ignore_config: False,
          check: False,
        ))
      case load_result {
        Ok(policy) -> policy
        Error(_) -> config.Policy(allow: [], deny: [], vuln_severity: None)
      }
    }
  }
}

fn merge_labels(
  existing: config.Policy,
  discovered: List(String),
) -> List(String) {
  []
  |> list.append(existing.allow)
  |> list.append(existing.deny)
  |> list.append(discovered)
  |> list.unique
  |> list.sort(string.compare)
}

fn only_new(existing: config.Policy, discovered: List(String)) -> List(String) {
  let known = list.append(existing.allow, existing.deny)
  list.filter(discovered, fn(l) { !list.contains(known, l) })
  |> list.unique
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
  FileWriteFailed(path: String)
}

fn write_error_message(error: WriteError) -> String {
  case error {
    TomlEditFailed(e) -> toml.error_message(e)
    FileWriteFailed(path) -> "Failed to write " <> path
  }
}

fn write_policy(
  path: String,
  allow: List(String),
  deny: List(String),
) -> Result(Nil, WriteError) {
  let existing = case simplifile.read(from: path) {
    Ok(contents) -> contents
    Error(_) -> ""
  }
  let section = ["tools", "licence_audit"]
  case toml.set_string_array(existing, section, "allow", allow) {
    Error(e) -> Error(TomlEditFailed(e))
    Ok(after_allow) ->
      case toml.set_string_array(after_allow, section, "deny", deny) {
        Error(e) -> Error(TomlEditFailed(e))
        Ok(after_both) ->
          case simplifile.write(to: path, contents: after_both) {
            Ok(_) -> Ok(Nil)
            Error(_) -> Error(FileWriteFailed(path))
          }
      }
  }
}

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
