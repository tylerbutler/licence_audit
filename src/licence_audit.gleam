import gleam/bool
import gleam/dict
import gleam/int
import gleam/io
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import glint
import licence_audit/cache
import licence_audit/cli
import licence_audit/color
import licence_audit/config
import licence_audit/error
import licence_audit/gleam_toml
import licence_audit/hex
import licence_audit/manifest
import licence_audit/notice
import licence_audit/notice_cache
import licence_audit/notice_resolve
import licence_audit/osv
import licence_audit/policy
import licence_audit/progress
import licence_audit/report
import licence_audit/repository
import licence_audit/sbom
import licence_audit/sbom_json
import licence_audit/sbom_uuid
import licence_audit/toml
import licence_audit/update as update_cmd
import licence_audit/version
import simplifile

pub type RunResult {
  RunResult(exit_code: Int, output: String)
}

@external(erlang, "args_ffi", "arguments")
fn arguments() -> List(String)

type FetchResult {
  FetchResult(
    rows: List(report.Row),
    fetch_failed: Bool,
    policy_failed: Bool,
    reporter: progress.Reporter,
  )
}

pub fn main() -> Nil {
  case glint.execute(cli.app(), cli.normalize_args(arguments())) {
    Error(message) -> {
      io.println_error(message)
      halt(1)
    }
    Ok(glint.Help(help)) -> io.println(help)
    Ok(glint.Out(action)) -> handle_action(action)
  }
}

fn handle_action(action: cli.CliAction) -> Nil {
  case action {
    cli.RunAudit(options) -> {
      let palette = color.resolve(options.color)
      let command = case options.check {
        True -> "check"
        False -> "report"
      }
      let #(RunResult(exit_code, output), reporter) =
        run_options(
          options,
          hex.fetch_package_metadata_from_hex,
          progress.enabled(options.verbosity, command),
          palette,
        )
      io.print(output)
      let _ = progress.flush(reporter)
      halt(exit_code)
    }
    cli.UpdateConfig(options) -> {
      let #(update_cmd.UpdateResult(exit_code, output), reporter) =
        run_update_options(
          options,
          hex.fetch_package_metadata_from_hex,
          progress.enabled(options.verbosity, "update"),
        )
      io.print(output)
      let _ = progress.flush(reporter)
      halt(exit_code)
    }
    cli.InvalidUsage(message) -> {
      io.print_error("Error: " <> message <> "\n")
      halt(1)
    }
    cli.RunSbom(options) -> {
      let #(RunResult(exit_code, output), reporter) =
        run_sbom_options(
          options,
          hex.fetch_package_metadata_from_hex,
          osv.query_batch_from_osv,
          osv.fetch_vulnerability_from_osv,
          progress.enabled(options.verbosity, "sbom"),
        )
      io.print(output)
      let _ = progress.flush(reporter)
      halt(exit_code)
    }
    cli.RunVulns(options) -> {
      let palette = color.resolve(options.color)
      let #(RunResult(exit_code, output), reporter) =
        run_vulns_options(
          options,
          osv.query_batch_from_osv,
          osv.fetch_vulnerability_from_osv,
          progress.enabled(options.verbosity, "vulns"),
          palette,
        )
      io.print(output)
      let _ = progress.flush(reporter)
      halt(exit_code)
    }
    cli.RunNotices(options) -> {
      let #(RunResult(exit_code, output), reporter) =
        run_notices_options(
          options,
          hex.fetch_package_metadata_from_hex,
          notice.default_clients(),
          progress.enabled(options.verbosity, "notices"),
        )
      io.print(output)
      let _ = progress.flush(reporter)
      halt(exit_code)
    }
    cli.GenDocsCompleted -> Nil
  }
}

pub fn run(args: List(String)) -> RunResult {
  run_with(args, hex.fetch_package_metadata_from_hex)
}

fn library_args(args: List(String)) -> List(String) {
  use <- bool.guard(when: list.contains(args, "--no-cache"), return: args)
  list.append(args, ["--no-cache"])
}

pub fn run_with(
  args: List(String),
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
) -> RunResult {
  let #(result, _) =
    run_with_reporter(
      library_args(args),
      fetcher,
      osv.query_batch_from_osv,
      osv.fetch_vulnerability_from_osv,
      progress.disabled(),
      color.for_enabled(False),
    )
  result
}

pub fn run_with_clients(
  args: List(String),
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
  osv_batch_fetcher: fn(List(String)) -> Result(List(osv.BatchEntry), osv.Error),
  osv_detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
) -> RunResult {
  let #(result, _) =
    run_with_reporter(
      library_args(args),
      fetcher,
      osv_batch_fetcher,
      osv_detail_fetcher,
      progress.disabled(),
      color.for_enabled(False),
    )
  result
}

pub fn run_with_notice_clients(
  args: List(String),
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
  clients: notice.Clients,
) -> RunResult {
  let #(result, _) =
    run_with_reporter_and_notices(
      library_args(args),
      fetcher,
      osv.query_batch_from_osv,
      osv.fetch_vulnerability_from_osv,
      clients,
      progress.disabled(),
      color.for_enabled(False),
    )
  result
}

pub fn run_with_progress(
  args: List(String),
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
  verbosity: progress.Verbosity,
) -> #(RunResult, List(progress.Event)) {
  let #(result, reporter) =
    run_with_reporter(
      library_args(args),
      fetcher,
      osv.query_batch_from_osv,
      osv.fetch_vulnerability_from_osv,
      progress.capturing(verbosity, "report"),
      color.for_enabled(False),
    )
  #(result, progress.events(reporter))
}

/// Like `run_with_progress`, but with injectable OSV clients — needed to
/// assert on reporter events (e.g. deferred error messages) for `check
/// --vulns` scenarios that require canned batch/detail fetchers.
pub fn run_with_clients_and_progress(
  args: List(String),
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
  osv_batch_fetcher: fn(List(String)) -> Result(List(osv.BatchEntry), osv.Error),
  osv_detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  verbosity: progress.Verbosity,
) -> #(RunResult, List(progress.Event)) {
  let #(result, reporter) =
    run_with_reporter(
      library_args(args),
      fetcher,
      osv_batch_fetcher,
      osv_detail_fetcher,
      progress.capturing(verbosity, "report"),
      color.for_enabled(False),
    )
  #(result, progress.events(reporter))
}

pub fn run_with_notice_progress(
  args: List(String),
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
  clients: notice.Clients,
  verbosity: progress.Verbosity,
) -> #(RunResult, List(progress.Event)) {
  let #(result, reporter) =
    run_with_reporter_and_notices(
      library_args(args),
      fetcher,
      osv.query_batch_from_osv,
      osv.fetch_vulnerability_from_osv,
      clients,
      progress.capturing(verbosity, "notices"),
      color.for_enabled(False),
    )
  #(result, progress.events(reporter))
}

fn run_with_reporter(
  args: List(String),
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
  osv_batch_fetcher: fn(List(String)) -> Result(List(osv.BatchEntry), osv.Error),
  osv_detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  reporter: progress.Reporter,
  palette: color.Palette,
) -> #(RunResult, progress.Reporter) {
  run_with_reporter_and_notices(
    args,
    fetcher,
    osv_batch_fetcher,
    osv_detail_fetcher,
    notice.default_clients(),
    reporter,
    palette,
  )
}

fn run_with_reporter_and_notices(
  args: List(String),
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
  osv_batch_fetcher: fn(List(String)) -> Result(List(osv.BatchEntry), osv.Error),
  osv_detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  notice_clients: notice.Clients,
  reporter: progress.Reporter,
  palette: color.Palette,
) -> #(RunResult, progress.Reporter) {
  case glint.execute(cli.app(), cli.normalize_args(args)) {
    Ok(glint.Help(help)) -> #(RunResult(0, help <> "\n"), reporter)
    Ok(glint.Out(cli.RunAudit(options))) ->
      run_options_with_clients(
        options,
        fetcher,
        osv_batch_fetcher,
        osv_detail_fetcher,
        reporter,
        palette,
      )
    Ok(glint.Out(cli.UpdateConfig(options))) -> {
      let #(update_cmd.UpdateResult(exit_code, output), reporter) =
        run_update_options(options, fetcher, reporter)
      #(RunResult(exit_code, output), reporter)
    }
    Ok(glint.Out(cli.InvalidUsage(message))) -> #(
      RunResult(1, "Error: " <> message <> "\n"),
      reporter,
    )
    Ok(glint.Out(cli.RunSbom(options))) ->
      run_sbom_options(
        options,
        fetcher,
        osv_batch_fetcher,
        osv_detail_fetcher,
        reporter,
      )
    Ok(glint.Out(cli.RunVulns(options))) -> {
      let #(result, reporter) =
        run_vulns_options(
          options,
          osv_batch_fetcher,
          osv_detail_fetcher,
          reporter,
          palette,
        )
      #(result, reporter)
    }
    Ok(glint.Out(cli.RunNotices(options))) ->
      run_notices_options(options, fetcher, notice_clients, reporter)
    Ok(glint.Out(cli.GenDocsCompleted)) -> #(RunResult(0, ""), reporter)
    Error(message) -> #(RunResult(1, message <> "\n"), reporter)
  }
}

fn run_sbom_options(
  options: cli.SbomOptions,
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
  osv_batch_fetcher: fn(List(String)) -> Result(List(osv.BatchEntry), osv.Error),
  osv_detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  reporter: progress.Reporter,
) -> #(RunResult, progress.Reporter) {
  let manifest_path = option_value(options.manifest_path, "manifest.toml")
  let reporter = progress.phase(reporter, "Generating SBOM")
  let reporter = progress.detail(reporter, "Loading package manifest")

  case manifest.load_sbom(manifest_path) {
    Error(manifest_error) -> #(
      diagnostic(error.from_manifest_error(manifest_error)),
      reporter,
    )
    Ok(sbom_manifest) ->
      run_sbom_for_manifest(
        options,
        sbom_manifest,
        ".",
        fetcher,
        osv_batch_fetcher,
        osv_detail_fetcher,
        reporter,
      )
  }
}

fn run_notices_options(
  options: cli.NoticesOptions,
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
  clients: notice.Clients,
  reporter: progress.Reporter,
) -> #(RunResult, progress.Reporter) {
  let manifest_path = option_value(options.manifest_path, "manifest.toml")
  let project_root = project_root_for_manifest(manifest_path)
  let reporter = progress.phase(reporter, "Generating licence notices")
  let reporter = progress.detail(reporter, "Loading package manifest")

  let #(metadata_cache_mode, source_cache_mode) = case options.no_cache {
    True -> #(cache.Disabled, notice_cache.Disabled)
    False -> #(
      cache.Enabled(path: options.cache_path),
      // `--cache-path` overrides a single file and applies to the metadata
      // cache (as on every other command). The source cache keeps its own
      // version-namespaced filename at the default location (still relocatable
      // via XDG_CACHE_HOME) so format bumps invalidate it correctly.
      notice_cache.Enabled(path: None),
    )
  }
  let metadata_cache = cache.open(metadata_cache_mode)
  let source_cache = notice_cache.open(source_cache_mode)
  let cached_fetcher = fn(name: String, version: String) {
    cache.fetch_cached_quiet(metadata_cache, name, version, fetcher)
  }

  case manifest.load_sbom(manifest_path) {
    Error(manifest_error) -> {
      let _ = cache.close(metadata_cache)
      let _ = notice_cache.close(source_cache)
      #(diagnostic(error.from_manifest_error(manifest_error)), reporter)
    }
    Ok(sbom_manifest) -> {
      let reporter =
        progress.detail(
          reporter,
          "Loaded manifest with "
            <> int.to_string(list.length(sbom_manifest.entries))
            <> " total entries",
        )
      let scopes =
        manifest.sbom_scopes(
          sbom_manifest,
          resolve_prod_seed(project_root, sbom_manifest.root_requirements),
        )
      let selected =
        notice.selected_entries(
          sbom_manifest,
          scopes,
          include_dev: options.include_dev,
        )
      let reporter =
        progress.detail(
          reporter,
          "Selected "
            <> int.to_string(list.length(selected))
            <> " package(s) for notices (include_dev="
            <> bool.to_string(options.include_dev)
            <> ")",
        )
      let reporter = progress.package_count(reporter, list.length(selected))

      let metadata_for = fn(entry: manifest.SbomEntry) {
        notice_metadata_for_entry(entry, project_root, cached_fetcher)
      }
      case notice.packages_from_entries(selected, scopes, metadata_for) {
        Error(notice_error) -> {
          let _ = cache.close(metadata_cache)
          let _ = notice_cache.close(source_cache)
          #(
            diagnostic(error.Notices(notice.describe_error(notice_error))),
            reporter,
          )
        }
        Ok(packages) -> {
          let reporter =
            progress.detail(
              reporter,
              "Resolved metadata for "
                <> int.to_string(list.length(packages))
                <> " package(s)",
            )
          let #(run_result, reporter) =
            build_notice_entries(
              packages,
              project_root,
              manifest_path,
              options.output,
              source_cache,
              clients,
              reporter,
            )
          let metadata_warning = cache.close(metadata_cache)
          let source_warning = notice_cache.close(source_cache)
          let reporter = apply_cache_warning(reporter, metadata_warning)
          let reporter = apply_cache_warning(reporter, source_warning)
          #(run_result, reporter)
        }
      }
    }
  }
}

fn apply_cache_warning(
  reporter: progress.Reporter,
  warning: option.Option(String),
) -> progress.Reporter {
  case warning {
    Some(message) -> progress.defer_warn(reporter, message)
    None -> reporter
  }
}

fn build_notice_entries(
  packages: List(notice.NoticePackage),
  project_root: String,
  manifest_path: String,
  output: option.Option(String),
  source_cache: notice_cache.Cache,
  clients: notice.Clients,
  reporter: progress.Reporter,
) -> #(RunResult, progress.Reporter) {
  let reporter =
    list.fold(packages, reporter, fn(reporter, package) {
      progress.detail(
        reporter,
        "Fetching "
          <> package.name
          <> "@"
          <> package.version
          <> " from "
          <> describe_source(package.source),
      )
    })
  let #(result, warnings) =
    resolve_notice_entries(packages, project_root, source_cache, clients)
  let reporter =
    list.fold(warnings, reporter, fn(reporter, warning) {
      progress.defer_warn(reporter, warning)
    })

  case result {
    Error(notice_error) -> #(
      diagnostic(error.Notices(notice.describe_error(notice_error))),
      reporter,
    )
    Ok(entries) -> {
      let reporter =
        list.fold(entries, reporter, fn(reporter, entry) {
          progress.detail(
            reporter,
            "Found "
              <> int.to_string(list.length(entry.files))
              <> " licence file(s) for "
              <> entry.package.name,
          )
        })
      let reporter = progress.detail(reporter, "Rendering notices output")
      write_notice_output(
        notice.render(entries, manifest_path: manifest_path),
        output,
        reporter,
      )
    }
  }
}

/// Resolve every selected package's licence materials through the fallback
/// chain, aggregating packages that could not be resolved into a single
/// `MissingLicenceText` error and collecting all deferred warnings. A hard
/// error (fetch/checksum/SPDX-network failure) aborts and is returned directly.
fn resolve_notice_entries(
  packages: List(notice.NoticePackage),
  project_root: String,
  source_cache: notice_cache.Cache,
  clients: notice.Clients,
) -> #(Result(List(notice.NoticeEntry), notice.Error), List(String)) {
  resolve_notice_entries_loop(
    packages,
    project_root,
    source_cache,
    clients,
    [],
    [],
    [],
  )
}

fn resolve_notice_entries_loop(
  packages: List(notice.NoticePackage),
  project_root: String,
  source_cache: notice_cache.Cache,
  clients: notice.Clients,
  entries: List(notice.NoticeEntry),
  missing: List(String),
  warnings: List(String),
) -> #(Result(List(notice.NoticeEntry), notice.Error), List(String)) {
  case packages {
    [] -> finalize_notice_entries(entries, missing, warnings)
    [package, ..rest] -> {
      let source_package = package_for_source_read(package, project_root)
      case notice_resolve.resolve(source_cache, source_package, clients) {
        Error(error) -> #(Error(error), warnings)
        Ok(resolution) -> {
          let warnings = list.append(warnings, resolution.warnings)
          let #(entries, missing) =
            accumulate_notice_outcome(
              package,
              resolution.outcome,
              entries,
              missing,
            )
          resolve_notice_entries_loop(
            rest,
            project_root,
            source_cache,
            clients,
            entries,
            missing,
            warnings,
          )
        }
      }
    }
  }
}

fn finalize_notice_entries(
  entries: List(notice.NoticeEntry),
  missing: List(String),
  warnings: List(String),
) -> #(Result(List(notice.NoticeEntry), notice.Error), List(String)) {
  case list.reverse(missing) {
    [] -> #(Ok(list.reverse(entries)), warnings)
    missing_packages -> #(
      Error(notice.MissingLicenceText(missing_packages)),
      warnings,
    )
  }
}

fn accumulate_notice_outcome(
  package: notice.NoticePackage,
  outcome: notice_resolve.Outcome,
  entries: List(notice.NoticeEntry),
  missing: List(String),
) -> #(List(notice.NoticeEntry), List(String)) {
  case outcome {
    notice_resolve.Resolved(files) -> #(
      [notice.NoticeEntry(package: package, files: files), ..entries],
      missing,
    )
    notice_resolve.Missing -> #(entries, [package.name, ..missing])
  }
}

/// Resolve the metadata (declared licences + repository links) for a notices
/// package. Hex packages use the shared metadata cache; git and path packages
/// read their locally checked-out `gleam.toml`.
fn notice_metadata_for_entry(
  entry: manifest.SbomEntry,
  project_root: String,
  cached_fetcher: fn(String, String) -> Result(hex.PackageMetadata, hex.Error),
) -> Result(hex.PackageMetadata, notice.Error) {
  case entry.provenance {
    manifest.HexProvenance(_, _) ->
      case cached_fetcher(entry.name, entry.version) {
        Ok(metadata) -> Ok(metadata)
        Error(fetch_error) ->
          Error(notice.MetadataFailed(
            package: entry.name,
            reason: hex.describe_error(fetch_error),
          ))
      }
    manifest.GitProvenance(repo, _commit) -> {
      let repo_url = strip_git_suffix(repo)
      let path =
        project_root <> "/build/packages/" <> entry.name <> "/gleam.toml"
      case read_gleam_toml_metadata(path, repo_url) {
        Ok(metadata) -> Ok(metadata)
        Error(_) ->
          Ok(hex.PackageMetadata(
            licences: [],
            description: None,
            links: [#("Repository", repo_url)],
            publisher: None,
          ))
      }
    }
    manifest.PathProvenance(path) ->
      case
        read_path_gleam_toml_metadata(resolve_project_path(project_root, path))
      {
        Ok(metadata) -> Ok(metadata)
        Error(_) -> Ok(hex.licences_only([]))
      }
    manifest.UnknownProvenance(_) -> Ok(hex.licences_only([]))
  }
}

/// Read declared licences and links from a path dependency's `gleam.toml` at
/// `<dependency_root>/gleam.toml`.
fn read_path_gleam_toml_metadata(
  dependency_root: String,
) -> Result(hex.PackageMetadata, Nil) {
  use contents <- result.try(
    simplifile.read(from: dependency_root <> "/gleam.toml")
    |> result.replace_error(Nil),
  )
  use doc <- result.try(toml.parse(contents))
  let description = option.from_result(toml.get_string(doc, ["description"]))
  Ok(hex.PackageMetadata(
    licences: gleam_toml.declared_licences(doc),
    description: description,
    links: gleam_toml.links(doc),
    publisher: None,
  ))
}

fn describe_source(source: notice.PackageSource) -> String {
  case source {
    notice.HexPackage(_) -> "Hex"
    notice.GitPackage(repo, _url, _commit) ->
      "git " <> repository.describe(repo)
    notice.PathPackage(path) -> "local path " <> path
  }
}

fn package_for_source_read(
  package: notice.NoticePackage,
  project_root: String,
) -> notice.NoticePackage {
  case package.source {
    notice.PathPackage(path) ->
      notice.NoticePackage(
        ..package,
        source: notice.PathPackage(resolve_project_path(project_root, path)),
      )
    notice.HexPackage(_) | notice.GitPackage(_, _, _) -> package
  }
}

fn resolve_project_path(project_root: String, path: String) -> String {
  case string.starts_with(path, "/"), project_root {
    True, _ -> path
    False, "." -> path
    False, _ -> join_project_path(project_root, path)
  }
}

fn join_project_path(parent: String, child: String) -> String {
  case string.ends_with(parent, "/") {
    True -> parent <> child
    False -> parent <> "/" <> child
  }
}

fn project_root_for_manifest(manifest_path: String) -> String {
  case string.split(manifest_path, on: "/") |> list.reverse {
    [] -> "."
    [_] -> "."
    [_, ..directory_parts_reversed] -> {
      let directory =
        directory_parts_reversed
        |> list.reverse
        |> string.join("/")

      case directory, string.starts_with(manifest_path, "/") {
        "", True -> "/"
        "", False -> "."
        _, _ -> directory
      }
    }
  }
}

fn write_notice_output(
  text: String,
  output: option.Option(String),
  reporter: progress.Reporter,
) -> #(RunResult, progress.Reporter) {
  case output {
    None -> #(RunResult(0, text), reporter)
    Some(path) -> {
      let reporter = progress.detail(reporter, "Writing notices to " <> path)
      case simplifile.write(to: path, contents: text) {
        Ok(_) -> #(RunResult(0, ""), reporter)
        Error(reason) -> #(
          diagnostic(
            error.Notices(
              notice.describe_error(notice.OutputWriteFailed(
                path,
                simplifile.describe_error(reason),
              )),
            ),
          ),
          reporter,
        )
      }
    }
  }
}

/// Fetch package metadata, optionally query OSV for embedded vulnerabilities,
/// then render the SBOM for an already-loaded manifest.
fn run_sbom_for_manifest(
  options: cli.SbomOptions,
  sbom_manifest: manifest.SbomManifest,
  project_root: String,
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
  osv_batch_fetcher: fn(List(String)) -> Result(List(osv.BatchEntry), osv.Error),
  osv_detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  reporter: progress.Reporter,
) -> #(RunResult, progress.Reporter) {
  let cache_mode = case options.no_cache {
    True -> cache.Disabled
    False -> cache.Enabled(path: options.cache_path)
  }
  let cache_handle = cache.open(cache_mode)
  let cached_fetcher = cache.wrap(cache_handle, fetcher)

  let #(package_metadata, reporter) =
    fetch_package_metadata(
      sbom_manifest,
      project_root,
      cached_fetcher,
      options.offline,
      reporter,
    )
  let _ = cache.close(cache_handle)

  // Optionally query OSV and embed the results as a CycloneDX vulnerabilities
  // array. A failed OSV query fails the whole command, since the user
  // explicitly asked for vulnerabilities.
  let #(vulns_result, reporter) = case options.with_vulns {
    False -> #(Ok([]), reporter)
    True ->
      gather_embedded_vulnerabilities(
        sbom_manifest,
        osv_batch_fetcher,
        osv_detail_fetcher,
        reporter,
      )
  }

  case vulns_result {
    Error(osv_error) -> #(diagnostic(error.from_osv_error(osv_error)), reporter)
    Ok(vulnerabilities) ->
      render_sbom(
        options,
        sbom_manifest,
        project_root,
        package_metadata,
        vulnerabilities,
        reporter,
      )
  }
}

/// Build the `SbomInput` from a loaded manifest plus the gathered package
/// metadata and embedded vulnerabilities, render it, and write the output.
fn render_sbom(
  options: cli.SbomOptions,
  sbom_manifest: manifest.SbomManifest,
  project_root: String,
  package_metadata: dict.Dict(String, hex.PackageMetadata),
  vulnerabilities: List(sbom.EmbeddedVulnerability),
  reporter: progress.Reporter,
) -> #(RunResult, progress.Reporter) {
  let root = read_root_component(project_root)
  let scopes =
    manifest.sbom_scopes(
      sbom_manifest,
      resolve_prod_seed(project_root, sbom_manifest.root_requirements),
    )
  // In reproducible mode the serial number is derived from the content and the
  // timestamp comes from SOURCE_DATE_EPOCH, so the same dependency set always
  // renders byte-identical output.
  let serial_and_timestamp = case options.reproducible {
    True -> Ok(#(sbom.ContentDerivedSerial, sbom_uuid.reproducible_timestamp()))
    False ->
      sbom_uuid.serial_number()
      |> result.map(fn(serial) {
        #(sbom.FixedSerial(serial), sbom_uuid.timestamp_now())
      })
      |> result.replace_error(error.SbomSerialNumberFailed)
  }

  case serial_and_timestamp {
    Error(serial_error) -> #(diagnostic(serial_error), reporter)
    Ok(#(serial_number, timestamp)) -> {
      let input =
        sbom.SbomInput(
          manifest: sbom_manifest,
          root: root,
          tool_version: tool_version(),
          serial_number: serial_number,
          timestamp: timestamp,
          package_metadata: package_metadata,
          scopes: scopes,
          vulnerabilities: vulnerabilities,
        )

      case sbom.try_render(input) {
        Error(err) -> #(diagnostic(err), reporter)
        Ok(json_str) -> write_sbom_output(options.output, json_str, reporter)
      }
    }
  }
}

/// Query OSV for every component with a purl and map the results into
/// `sbom.EmbeddedVulnerability` values, one per unique advisory, each carrying
/// the component `bom-ref`s (purls) it affects. Returns the OSV error on a
/// failed batch query so the caller can fail the command.
fn gather_embedded_vulnerabilities(
  sbom_manifest: manifest.SbomManifest,
  batch_fetcher: fn(List(String)) -> Result(List(osv.BatchEntry), osv.Error),
  detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  reporter: progress.Reporter,
) -> #(Result(List(sbom.EmbeddedVulnerability), osv.Error), progress.Reporter) {
  let #(purl_pairs, _errors) = build_purl_pairs(sbom_manifest)
  let purls = list.map(purl_pairs, fn(pair) { pair.1 })
  case purls {
    [] -> #(Ok([]), reporter)
    _ -> {
      let reporter =
        progress.detail(
          reporter,
          "Querying OSV.dev for "
            <> int.to_string(list.length(purls))
            <> " packages",
        )
      case batch_fetcher(purls) {
        Error(osv_error) -> #(Error(osv_error), reporter)
        Ok(entries) -> {
          let id_to_refs = build_id_to_refs(purl_pairs, entries)
          let unique_ids = unique_vuln_ids(entries)
          // SBOM embedding tolerates detail failures the same way the plain
          // `vulns` report does; only the `check --vulns` gate blocks on them.
          let #(vulns, _detail_failures, reporter) =
            fetch_vulnerabilities(unique_ids, detail_fetcher, reporter, [])
          #(Ok(to_embedded_vulnerabilities(vulns, id_to_refs)), reporter)
        }
      }
    }
  }
}

/// Pair each fetched advisory with the component `bom-ref`s (purls) it affects.
fn to_embedded_vulnerabilities(
  vulns: List(osv.Vulnerability),
  id_to_refs: dict.Dict(String, List(String)),
) -> List(sbom.EmbeddedVulnerability) {
  list.map(vulns, fn(vuln) {
    let affects = case dict.get(id_to_refs, vuln.id) {
      Ok(refs) -> refs
      Error(_) -> []
    }
    sbom.EmbeddedVulnerability(vuln: vuln, affects: affects)
  })
}

/// Build a map from each OSV advisory id to the component `bom-ref`s (purls)
/// it affects. Batch entries align positionally with `purl_pairs` because
/// `osv.query_batch` preserves input order.
fn build_id_to_refs(
  purl_pairs: List(PurlPair),
  entries: List(osv.BatchEntry),
) -> dict.Dict(String, List(String)) {
  list.zip(purl_pairs, entries)
  |> list.fold(dict.new(), fn(acc, pair) {
    let #(#(_entry, purl), batch_entry) = pair
    list.fold(batch_entry.vuln_ids, acc, fn(inner, id) {
      let existing = case dict.get(inner, id) {
        Ok(refs) -> refs
        Error(_) -> []
      }
      case list.contains(existing, purl) {
        True -> inner
        False -> dict.insert(inner, id, list.append(existing, [purl]))
      }
    })
  })
}

fn fetch_package_metadata(
  manifest_value: manifest.SbomManifest,
  project_root: String,
  fetcher: fn(manifest.Package, progress.Reporter) ->
    #(Result(hex.PackageMetadata, hex.Error), progress.Reporter),
  offline: Bool,
  reporter: progress.Reporter,
) -> #(dict.Dict(String, hex.PackageMetadata), progress.Reporter) {
  list.fold(manifest_value.entries, #(dict.new(), reporter), fn(acc, entry) {
    let #(metadata_acc, rep) = acc
    case entry.provenance {
      // Hex packages are enriched from the registry API (network), skipped
      // silently in offline mode to preserve deterministic offline output.
      manifest.HexProvenance(_, _) ->
        case offline {
          True -> #(metadata_acc, rep)
          False -> fetch_hex_entry_metadata(entry, fetcher, metadata_acc, rep)
        }
      // Git packages have no Hex metadata; enrich them from their locally
      // checked-out source tree instead. This is filesystem-only, so it runs
      // in offline mode too.
      manifest.GitProvenance(repo, _commit) ->
        enrich_git_entry_metadata(entry, repo, project_root, metadata_acc, rep)
      manifest.PathProvenance(_) | manifest.UnknownProvenance(_) -> #(
        metadata_acc,
        rep,
      )
    }
  })
}

/// Fetch enrichment metadata for a single Hex entry, inserting it on success.
/// On failure the component is left unenriched and a deferred warning is
/// recorded so the dropped fields are visible rather than silent.
fn fetch_hex_entry_metadata(
  entry: manifest.SbomEntry,
  fetcher: fn(manifest.Package, progress.Reporter) ->
    #(Result(hex.PackageMetadata, hex.Error), progress.Reporter),
  metadata_acc: dict.Dict(String, hex.PackageMetadata),
  reporter: progress.Reporter,
) -> #(dict.Dict(String, hex.PackageMetadata), progress.Reporter) {
  let package =
    manifest.Package(
      name: entry.name,
      version: entry.version,
      source: manifest.Hex,
      kind: entry.kind,
      requirements: entry.requirements,
    )
  let #(result, reporter) = fetcher(package, reporter)
  case result {
    Ok(metadata) -> #(dict.insert(metadata_acc, entry.name, metadata), reporter)
    Error(error) -> {
      let reporter =
        progress.defer_warn(
          reporter,
          "No Hex metadata for "
            <> entry.name
            <> "@"
            <> entry.version
            <> " ("
            <> hex.describe_error(error)
            <> "); SBOM component will omit licences, description, publisher, and links",
        )
      #(metadata_acc, reporter)
    }
  }
}

/// Enrich a git-sourced entry from its locally checked-out `gleam.toml`
/// (`build/packages/<name>/gleam.toml`). Git packages have no Hex registry
/// metadata, but the manifest carries the repo URL and the source tree carries
/// description, licences, and links. The repository is always emitted as a
/// `vcs` link; the richer fields are added when the local gleam.toml is
/// readable, otherwise a warning records what was omitted.
fn enrich_git_entry_metadata(
  entry: manifest.SbomEntry,
  repo: String,
  project_root: String,
  metadata_acc: dict.Dict(String, hex.PackageMetadata),
  reporter: progress.Reporter,
) -> #(dict.Dict(String, hex.PackageMetadata), progress.Reporter) {
  let repo_url = strip_git_suffix(repo)
  let path = project_root <> "/build/packages/" <> entry.name <> "/gleam.toml"
  case read_gleam_toml_metadata(path, repo_url) {
    Ok(metadata) -> #(dict.insert(metadata_acc, entry.name, metadata), reporter)
    Error(_) -> {
      let metadata =
        hex.PackageMetadata(
          licences: [],
          description: None,
          links: [#("Repository", repo_url)],
          publisher: None,
        )
      let reporter =
        progress.defer_warn(
          reporter,
          "No local metadata for "
            <> entry.name
            <> "@"
            <> entry.version
            <> " ("
            <> path
            <> " unreadable); SBOM component will omit description and licences",
        )
      #(dict.insert(metadata_acc, entry.name, metadata), reporter)
    }
  }
}

fn read_gleam_toml_metadata(
  path: String,
  repo_url: String,
) -> Result(hex.PackageMetadata, Nil) {
  use contents <- result.try(
    simplifile.read(from: path) |> result.replace_error(Nil),
  )
  gleam_toml.package_metadata(contents, repo_url)
}

fn strip_git_suffix(url: String) -> String {
  gleam_toml.strip_git_suffix(url)
}

fn read_root_component(project_root: String) -> sbom.RootComponent {
  let path = project_root <> "/gleam.toml"
  case simplifile.read(from: path) {
    Error(_) -> default_root_component()
    Ok(contents) ->
      case toml.parse(contents) {
        Error(_) -> default_root_component()
        Ok(doc) -> {
          let name = result.unwrap(toml.get_string(doc, ["name"]), "project")
          let version =
            result.unwrap(toml.get_string(doc, ["version"]), "0.0.0")
          let description =
            option.from_result(toml.get_string(doc, ["description"]))
          let licences = case toml.get_array(doc, ["licences"]) {
            Ok(items) -> list.filter_map(items, toml.as_string)
            Error(_) -> []
          }
          let repository = case toml.get_table(doc, ["repository"]) {
            Ok(entry) -> repository_url(entry)
            Error(_) -> None
          }
          sbom.RootComponent(
            name:,
            version:,
            description:,
            licences:,
            repository:,
          )
        }
      }
  }
}

fn default_root_component() -> sbom.RootComponent {
  sbom.RootComponent(
    name: "project",
    version: "0.0.0",
    description: None,
    licences: [],
    repository: None,
  )
}

/// Build a source URL from a `gleam.toml` `repository` table. Only the
/// `{ type = "github", user, repo }` shape is recognised; anything else yields
/// `None` rather than a guessed URL.
fn repository_url(entry: toml.Entry) -> option.Option(String) {
  case
    repository_field(entry, "type"),
    repository_field(entry, "user"),
    repository_field(entry, "repo")
  {
    Some("github"), Some(user), Some(repo) ->
      Some("https://github.com/" <> user <> "/" <> repo)
    _, _, _ -> None
  }
}

fn repository_field(entry: toml.Entry, name: String) -> option.Option(String) {
  case toml.field(entry, name) {
    Ok(value) -> option.from_result(toml.as_string(value))
    Error(_) -> None
  }
}

fn tool_version() -> String {
  case version.build_version() {
    Ok(v) -> v
    Error(Nil) -> "unknown"
  }
}

fn write_sbom_output(
  output: option.Option(String),
  json_str: String,
  reporter: progress.Reporter,
) -> #(RunResult, progress.Reporter) {
  case sbom_json.pretty_print(json_str) {
    Error(reason) -> #(
      RunResult(
        2,
        "Error: failed to format SBOM JSON: "
          <> sbom_json.describe_error(reason)
          <> "\n",
      ),
      reporter,
    )
    Ok(pretty_json) ->
      case output {
        option.None -> #(RunResult(0, pretty_json <> "\n"), reporter)
        option.Some(path) ->
          case simplifile.write(to: path, contents: pretty_json <> "\n") {
            Ok(_) -> #(RunResult(0, ""), reporter)
            Error(reason) -> #(
              diagnostic(error.SbomWriteFailed(
                path: path,
                reason: simplifile.describe_error(reason),
              )),
              reporter,
            )
          }
      }
  }
}

fn run_options(
  options: cli.Options,
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
  reporter: progress.Reporter,
  palette: color.Palette,
) -> #(RunResult, progress.Reporter) {
  run_options_with_clients(
    options,
    fetcher,
    osv.query_batch_from_osv,
    osv.fetch_vulnerability_from_osv,
    reporter,
    palette,
  )
}

fn run_options_with_clients(
  options: cli.Options,
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
  osv_batch_fetcher: fn(List(String)) -> Result(List(osv.BatchEntry), osv.Error),
  osv_detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  reporter: progress.Reporter,
  palette: color.Palette,
) -> #(RunResult, progress.Reporter) {
  let manifest_path = option_value(options.manifest_path, "manifest.toml")
  let reporter = progress.phase(reporter, "Starting licence audit")
  let reporter = progress.detail(reporter, "Loading licence policy")

  case prepare_audit(options, manifest_path, ".", reporter) {
    Error(failure) -> failure
    Ok(#(config_policy, audit_policy, locked, sbom_manifest, scopes, reporter)) ->
      audit_locked(
        options,
        config_policy,
        audit_policy,
        locked,
        sbom_manifest,
        scopes,
        fetcher,
        osv_batch_fetcher,
        osv_detail_fetcher,
        reporter,
        palette,
      )
  }
}

/// Load the licence policy and package manifest for an audit run. On any
/// failure, short-circuits with a `#(RunResult, reporter)` diagnostic.
fn prepare_audit(
  options: cli.Options,
  manifest_path: String,
  project_root: String,
  reporter: progress.Reporter,
) -> Result(
  #(
    config.Policy,
    policy.Policy,
    manifest.LockedPackages,
    Option(manifest.SbomManifest),
    dict.Dict(String, manifest.Scope),
    progress.Reporter,
  ),
  #(RunResult, progress.Reporter),
) {
  use config_policy <- result.try(
    load_policy(options, project_root)
    |> result.map_error(fn(e) {
      #(diagnostic(error.from_config_error(e)), reporter)
    }),
  )
  use audit_policy <- result.try(
    policy.from_config(config_policy, check_mode: options.check)
    |> result.map_error(fn(e) {
      #(diagnostic(error.from_policy_error(e)), reporter)
    }),
  )
  let reporter = progress.detail(reporter, "Loading package manifest")
  use locked <- result.try(
    manifest.load(manifest_path)
    |> result.map_error(fn(e) {
      #(diagnostic(error.from_manifest_error(e)), reporter)
    }),
  )
  let sbom_manifest = case options.check && options.check_vulns {
    False -> None
    True ->
      Some(case manifest.load_sbom(manifest_path) {
        Ok(sbom_manifest) -> sbom_manifest
        Error(_) -> audit_sbom_fallback(locked)
      })
  }
  let scopes = compute_scopes(project_root, locked)
  Ok(#(config_policy, audit_policy, locked, sbom_manifest, scopes, reporter))
}

fn audit_sbom_fallback(
  locked: manifest.LockedPackages,
) -> manifest.SbomManifest {
  let hex_entries =
    list.map(locked.packages, fn(package) {
      manifest.SbomEntry(
        name: package.name,
        version: package.version,
        kind: package.kind,
        requirements: package.requirements,
        provenance: manifest.HexProvenance(
          outer_checksum: "",
          inner_checksum: None,
        ),
      )
    })
  let unsupported_entries =
    list.map(locked.skipped_packages, fn(package) {
      manifest.SbomEntry(
        name: package.name,
        version: package.version,
        kind: package.kind,
        requirements: package.requirements,
        provenance: manifest.UnknownProvenance(source: package.source),
      )
    })
  manifest.SbomManifest(
    entries: list.append(hex_entries, unsupported_entries),
    root_requirements: locked.direct_names,
  )
}

/// Run the audit over a loaded manifest: fetch licences, render the report,
/// optionally run the vulnerability gate, then compute the final result.
fn audit_locked(
  options: cli.Options,
  config_policy: config.Policy,
  audit_policy: policy.Policy,
  locked: manifest.LockedPackages,
  sbom_manifest: Option(manifest.SbomManifest),
  scopes: dict.Dict(String, manifest.Scope),
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
  osv_batch_fetcher: fn(List(String)) -> Result(List(osv.BatchEntry), osv.Error),
  osv_detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  reporter: progress.Reporter,
  palette: color.Palette,
) -> #(RunResult, progress.Reporter) {
  let reporter = progress.package_count(reporter, list.length(locked.packages))
  let evaluate_policy = policy.has_rules(audit_policy)
  let mode = case evaluate_policy {
    True -> report.Audit
    False -> report.Default
  }
  let cache_mode = case options.no_cache {
    True -> cache.Disabled
    False -> cache.Enabled(path: options.cache_path)
  }
  let cache_handle = cache.open(cache_mode)
  let cached_fetcher = cache.wrap(cache_handle, fetcher)
  let dep_paths = manifest.dep_paths(locked)
  let #(active_packages, active_skipped) = case options.prod_only {
    False -> #(locked.packages, locked.skipped_packages)
    True -> #(
      list.filter(locked.packages, fn(p) {
        scope_for(scopes, p.name) == manifest.Prod
      }),
      list.filter(locked.skipped_packages, fn(p) {
        scope_for(scopes, p.name) == manifest.Prod
      }),
    )
  }
  let active_sbom_entries = case sbom_manifest {
    None -> []
    Some(sbom_manifest) ->
      case options.prod_only {
        False -> sbom_manifest.entries
        True ->
          list.filter(sbom_manifest.entries, fn(entry) {
            scope_for(scopes, entry.name) == manifest.Prod
          })
      }
  }
  let result =
    fetch_packages(
      active_packages,
      cached_fetcher,
      audit_policy,
      evaluate_policy,
      dep_paths,
      scopes,
      reporter,
      [],
      False,
      False,
    )
  let cache_warning = cache.close(cache_handle)
  let skipped_rows = build_skipped_rows(active_skipped, dep_paths, scopes)
  let all_rows = list.append(result.rows, skipped_rows)
  let display_rows = case options.check && result.policy_failed {
    True -> report.filter_failing_trees(all_rows)
    False -> all_rows
  }
  let skipped_names = list.map(active_skipped, fn(pkg) { pkg.name })
  let licence_output =
    report.format(
      display_rows,
      report.Summary(skipped_names: skipped_names),
      mode,
      palette,
    )

  // Vulnerability gate: only when running `check` with --vulns.
  // Threshold resolution: CLI flag > config key > "high".
  let vuln_outcome = case options.check && options.check_vulns {
    False ->
      VulnGateOutcome(
        report_text: "",
        gate_failed: False,
        unknown_failed: False,
        query_failed: False,
        detail_incomplete: False,
        reporter: result.reporter,
      )
    True -> {
      let threshold =
        resolve_vuln_threshold(
          options.vuln_severity,
          config_policy.vuln_severity,
        )
      let block_unknown = config_policy.vuln_block_unknown
      run_vuln_check_for_audit(
        active_sbom_entries,
        threshold,
        block_unknown,
        osv_batch_fetcher,
        osv_detail_fetcher,
        result.reporter,
        palette,
      )
    }
  }

  let output = licence_output <> vuln_outcome.report_text

  let #(run_result, reporter) =
    finalize_audit(
      options.check,
      result.fetch_failed,
      vuln_outcome.query_failed,
      vuln_outcome.detail_incomplete,
      result.policy_failed,
      vuln_outcome.gate_failed,
      vuln_outcome.unknown_failed,
      output,
      vuln_outcome.reporter,
    )

  let reporter = case cache_warning {
    Some(message) -> progress.defer_warn(reporter, message)
    None -> reporter
  }
  #(run_result, reporter)
}

/// Compute the audit's exit code, output suffix, and deferred log message
/// from the gathered failure flags, in priority order.
fn finalize_audit(
  check: Bool,
  fetch_failed: Bool,
  vuln_query_failed: Bool,
  vuln_detail_incomplete: Bool,
  policy_failed: Bool,
  vuln_failed: Bool,
  vuln_unknown_failed: Bool,
  output: String,
  reporter: progress.Reporter,
) -> #(RunResult, progress.Reporter) {
  use <- bool.guard(when: check && fetch_failed, return: #(
    RunResult(2, output),
    progress.defer_error(
      reporter,
      "Licence audit failed: package metadata could not be fetched",
    ),
  ))
  use <- bool.guard(when: vuln_query_failed, return: #(
    RunResult(2, output),
    progress.defer_error(
      reporter,
      "Vulnerability check failed: OSV request failed",
    ),
  ))
  // The advisory-detail failure already deferred its own accurate message
  // (advisory IDs + reasons) in evaluate_vuln_gate. Don't attach a second,
  // generic message here — just carry the exit code.
  use <- bool.guard(when: vuln_detail_incomplete, return: #(
    RunResult(2, output),
    reporter,
  ))
  use <- bool.guard(when: check && policy_failed, return: #(
    RunResult(1, output <> error.message(error.AuditFailed) <> "\n"),
    progress.defer_error(
      reporter,
      "Licence audit failed: policy violations detected",
    ),
  ))
  use <- bool.guard(when: vuln_failed, return: #(
    RunResult(
      1,
      output
        <> case vuln_unknown_failed {
        True ->
          "Vulnerability check failed: one or more advisories met the severity threshold or the unknown-severity blocking rule.\n"
        False ->
          "Vulnerability check failed: one or more advisories at or above threshold severity.\n"
      },
    ),
    progress.defer_error(reporter, case vuln_unknown_failed {
      True ->
        "Vulnerability check failed: threshold or unknown-severity blockers detected"
      False -> "Vulnerability check failed: advisories at or above threshold"
    }),
  ))
  #(
    RunResult(0, output),
    progress.defer_success(reporter, "Licence audit completed"),
  )
}

fn fetch_packages(
  packages: List(manifest.Package),
  fetcher: fn(manifest.Package, progress.Reporter) ->
    #(Result(hex.PackageMetadata, hex.Error), progress.Reporter),
  audit_policy: policy.Policy,
  check_mode: Bool,
  paths: dict.Dict(String, List(String)),
  scopes: dict.Dict(String, manifest.Scope),
  reporter: progress.Reporter,
  rows: List(report.Row),
  fetch_failed: Bool,
  policy_failed: Bool,
) -> FetchResult {
  case packages {
    [] ->
      FetchResult(
        rows: list.reverse(rows),
        fetch_failed: fetch_failed,
        policy_failed: policy_failed,
        reporter: reporter,
      )
    [package, ..rest] -> {
      let path = case dict.get(paths, package.name) {
        Ok(p) -> p
        Error(_) -> [package.name]
      }
      let #(fetch_result, reporter) = fetcher(package, reporter)
      case fetch_result {
        Error(fetch_error) -> {
          let reporter =
            progress.fail(
              reporter,
              "Failed to fetch package metadata for " <> package.name,
            )
          let message = error.message(error.from_hex_error(fetch_error))
          fetch_packages(
            rest,
            fetcher,
            audit_policy,
            check_mode,
            paths,
            scopes,
            reporter,
            [
              report.Row(
                package: package.name,
                version: package.version,
                licences: [],
                status: report.Failed(message),
                kind: package.kind,
                scope: scope_for(scopes, package.name),
                path: path,
              ),
              ..rows
            ],
            True,
            policy_failed,
          )
        }
        Ok(metadata) -> {
          let status = status_for(check_mode, audit_policy, metadata.licences)
          fetch_packages(
            rest,
            fetcher,
            audit_policy,
            check_mode,
            paths,
            scopes,
            reporter,
            [
              report.Row(
                package: package.name,
                version: package.version,
                licences: metadata.licences,
                status: status,
                kind: package.kind,
                scope: scope_for(scopes, package.name),
                path: path,
              ),
              ..rows
            ],
            fetch_failed,
            policy_failed || is_policy_failure(status),
          )
        }
      }
    }
  }
}

/// Audit status for a package in `check` mode, or `NotChecked` otherwise.
fn status_for(
  check_mode: Bool,
  audit_policy: policy.Policy,
  licences: List(String),
) -> report.Status {
  case check_mode {
    True -> report.Checked(policy.audit(audit_policy, licences))
    False -> report.NotChecked
  }
}

fn load_policy(
  options: cli.Options,
  project_root: String,
) -> Result(config.Policy, config.Error) {
  config.load(config.LoadOptions(
    config_path: options.config_path,
    project_root: project_root,
    allow_licences: options.allow_licences,
    deny_licences: options.deny_licences,
    vuln_severity: options.vuln_severity,
    vuln_block_unknown: options.vuln_block_unknown,
    ignore_config: options.ignore_config,
    check: options.check,
  ))
}

fn build_skipped_rows(
  skipped: List(manifest.SkippedPackage),
  paths: dict.Dict(String, List(String)),
  scopes: dict.Dict(String, manifest.Scope),
) -> List(report.Row) {
  list.map(skipped, fn(pkg) {
    let path = case dict.get(paths, pkg.name) {
      Ok(p) -> p
      Error(_) -> [pkg.name]
    }
    report.Row(
      package: pkg.name,
      version: pkg.version,
      licences: [],
      status: report.Skipped(pkg.source),
      kind: pkg.kind,
      scope: scope_for(scopes, pkg.name),
      path: path,
    )
  })
}

fn compute_scopes(
  project_root: String,
  locked: manifest.LockedPackages,
) -> dict.Dict(String, manifest.Scope) {
  manifest.dep_scopes(
    locked,
    resolve_prod_seed(project_root, locked.direct_names),
  )
}

/// Production direct dependency names from `<project_root>/gleam.toml`, or
/// `all_direct` (so everything classifies as prod) when it is missing,
/// unreadable, or has no `[dependencies]` table.
fn resolve_prod_seed(
  project_root: String,
  all_direct: List(String),
) -> List(String) {
  case simplifile.read(from: project_root <> "/gleam.toml") {
    Ok(contents) ->
      case manifest.prod_direct_names(contents) {
        Ok(names) -> names
        Error(_) -> all_direct
      }
    Error(_) -> all_direct
  }
}

fn scope_for(
  scopes: dict.Dict(String, manifest.Scope),
  name: String,
) -> manifest.Scope {
  case dict.get(scopes, name) {
    Ok(scope) -> scope
    Error(_) -> manifest.Prod
  }
}

fn is_policy_failure(status: report.Status) -> Bool {
  case status {
    report.Checked(policy.Allowed) -> False
    report.Checked(policy.NoLicencesDeclared)
    | report.Checked(policy.DeniedLicence(_))
    | report.Checked(policy.UnallowedLicence(_)) -> True
    report.NotChecked | report.Failed(_) | report.Skipped(_) -> False
  }
}

fn diagnostic(audit_error: error.Error) -> RunResult {
  RunResult(
    error.exit_code(audit_error),
    "Error: " <> error.message(audit_error) <> "\n",
  )
}

fn option_value(value: option.Option(String), default: String) -> String {
  case value {
    Some(value) -> value
    None -> default
  }
}

@external(erlang, "erlang", "halt")
fn halt(code: Int) -> Nil

fn run_update_options(
  options: cli.UpdateOptions,
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
  reporter: progress.Reporter,
) -> #(update_cmd.UpdateResult, progress.Reporter) {
  let manifest_path = option_value(options.manifest_path, "manifest.toml")
  update_cmd.run(
    manifest_path,
    ".",
    options.config_path,
    options.ignore_config,
    options.no_cache,
    options.cache_path,
    fetcher,
    reporter,
  )
}

// --- Vulnerability checking ---------------------------------------------

fn run_vulns_options(
  options: cli.VulnsOptions,
  batch_fetcher: fn(List(String)) -> Result(List(osv.BatchEntry), osv.Error),
  detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  reporter: progress.Reporter,
  palette: color.Palette,
) -> #(RunResult, progress.Reporter) {
  let manifest_path = option_value(options.manifest_path, "manifest.toml")
  let reporter = progress.phase(reporter, "Checking for vulnerabilities")
  let reporter = progress.detail(reporter, "Loading package manifest")

  case manifest.load_sbom(manifest_path) {
    Error(manifest_error) -> #(
      diagnostic(error.from_manifest_error(manifest_error)),
      reporter,
    )
    Ok(sbom_manifest) -> {
      let scopes =
        manifest.sbom_scopes(
          sbom_manifest,
          resolve_prod_seed(".", sbom_manifest.root_requirements),
        )
      let #(purl_pairs, purl_errors) = build_purl_pairs(sbom_manifest)
      let purls = list.map(purl_pairs, fn(pair) { pair.1 })

      case purls {
        [] -> {
          let output = format_vulns_output([], purl_errors, scopes, palette)
          #(RunResult(0, output), reporter)
        }
        _ ->
          query_and_report_vulns(
            purls,
            purl_pairs,
            purl_errors,
            scopes,
            batch_fetcher,
            detail_fetcher,
            reporter,
            palette,
          )
      }
    }
  }
}

/// Query OSV for `purls`, fetch advisory details, and render the `vulns`
/// report. Returns a non-zero result only if the OSV batch request fails.
fn query_and_report_vulns(
  purls: List(String),
  purl_pairs: List(PurlPair),
  purl_errors: List(String),
  scopes: dict.Dict(String, manifest.Scope),
  batch_fetcher: fn(List(String)) -> Result(List(osv.BatchEntry), osv.Error),
  detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  reporter: progress.Reporter,
  palette: color.Palette,
) -> #(RunResult, progress.Reporter) {
  let reporter =
    progress.detail(
      reporter,
      "Querying OSV.dev for "
        <> int.to_string(list.length(purls))
        <> " packages",
    )
  case batch_fetcher(purls) {
    Error(osv_error) -> #(diagnostic(error.from_osv_error(osv_error)), reporter)
    Ok(entries) -> {
      let with_packages = merge_entries_with_packages(entries, purl_pairs)
      let #(rows, reporter) =
        fetch_vuln_details(with_packages, detail_fetcher, reporter, [])
      let output = format_vulns_output(rows, purl_errors, scopes, palette)
      #(RunResult(0, output), reporter)
    }
  }
}

/// A package/purl pair we successfully built a purl for.
type PurlPair =
  #(manifest.SbomEntry, String)

/// A package with its associated OSV batch result.
type VulnPair =
  #(manifest.SbomEntry, List(String))

/// A finished row for the vulns report: package + per-vuln details.
type VulnRow {
  VulnRow(package: manifest.SbomEntry, vulnerabilities: List(osv.Vulnerability))
}

/// An advisory whose detail lookup failed, with a human-readable reason.
/// The `vulns` report tolerates these (placeholder + warning); the
/// `check --vulns` gate cannot, since it can't evaluate severity for an
/// advisory it never fetched.
type DetailFailure {
  DetailFailure(id: String, reason: String)
}

/// Result of running the `check --vulns` gate. `query_failed` and
/// `detail_incomplete` are kept distinct because each already deferred its
/// own accurate error message before returning — `finalize_audit` must not
/// attach a second, generic message on top of either.
type VulnGateOutcome {
  VulnGateOutcome(
    report_text: String,
    gate_failed: Bool,
    unknown_failed: Bool,
    query_failed: Bool,
    detail_incomplete: Bool,
    reporter: progress.Reporter,
  )
}

fn build_purl_pairs(
  sbom_manifest: manifest.SbomManifest,
) -> #(List(PurlPair), List(String)) {
  list.fold(sbom_manifest.entries, #([], []), fn(acc, entry) {
    let #(pairs, errors) = acc
    case sbom.purl_for(entry) {
      Ok(purl) -> #([#(entry, purl), ..pairs], errors)
      // Skip path / unsupported sources silently — same packages SBOM
      // generation rejects, but `vulns` should still report what it can.
      Error(_) -> #(pairs, [entry.name, ..errors])
    }
  })
  |> fn(folded) {
    let #(pairs, errors) = folded
    #(list.reverse(pairs), list.reverse(errors))
  }
}

fn merge_entries_with_packages(
  entries: List(osv.BatchEntry),
  pairs: List(PurlPair),
) -> List(VulnPair) {
  list.map2(pairs, entries, fn(pair, entry) {
    let #(pkg, _purl) = pair
    #(pkg, entry.vuln_ids)
  })
}

fn fetch_vuln_details(
  pending: List(VulnPair),
  detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  reporter: progress.Reporter,
  acc: List(VulnRow),
) -> #(List(VulnRow), progress.Reporter) {
  case pending {
    [] -> #(list.reverse(acc), reporter)
    [#(pkg, ids), ..rest] -> {
      case ids {
        [] ->
          fetch_vuln_details(rest, detail_fetcher, reporter, [
            VulnRow(package: pkg, vulnerabilities: []),
            ..acc
          ])
        _ -> {
          let reporter =
            progress.detail(reporter, "Fetching OSV details for " <> pkg.name)
          // The plain `vulns` report tolerates detail failures via the
          // existing placeholder + warning; only the `check --vulns` gate
          // treats them as blocking (see query_vuln_gate).
          let #(vulns, _detail_failures, reporter) =
            fetch_vulnerabilities(ids, detail_fetcher, reporter, [])
          fetch_vuln_details(rest, detail_fetcher, reporter, [
            VulnRow(package: pkg, vulnerabilities: vulns),
            ..acc
          ])
        }
      }
    }
  }
}

fn fetch_vulnerabilities(
  ids: List(String),
  detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  reporter: progress.Reporter,
  acc: List(osv.Vulnerability),
) -> #(List(osv.Vulnerability), List(DetailFailure), progress.Reporter) {
  fetch_vulnerabilities_loop(ids, detail_fetcher, reporter, acc, [])
}

fn fetch_vulnerabilities_loop(
  ids: List(String),
  detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  reporter: progress.Reporter,
  acc: List(osv.Vulnerability),
  failures: List(DetailFailure),
) -> #(List(osv.Vulnerability), List(DetailFailure), progress.Reporter) {
  case ids {
    [] -> #(list.reverse(acc), list.reverse(failures), reporter)
    [id, ..rest] -> {
      case detail_fetcher(id) {
        Ok(vuln) ->
          fetch_vulnerabilities_loop(
            rest,
            detail_fetcher,
            reporter,
            [vuln, ..acc],
            failures,
          )
        Error(err) -> {
          let reporter =
            progress.defer_warn(
              reporter,
              "Failed to fetch OSV details for " <> id,
            )
          let failure =
            DetailFailure(
              id: id,
              reason: error.message(error.from_osv_error(err)),
            )
          fetch_vulnerabilities_loop(
            rest,
            detail_fetcher,
            reporter,
            [placeholder_vulnerability(id), ..acc],
            [failure, ..failures],
          )
        }
      }
    }
  }
}

fn placeholder_vulnerability(id: String) -> osv.Vulnerability {
  // Fall back to bare ID with unknown severity so the report still shows the
  // user something actionable when an individual detail fetch fails.
  osv.Vulnerability(
    id: id,
    summary: "(details unavailable)",
    severity: osv.UnknownSeverity,
    scores: [],
  )
}

fn format_vulns_output(
  rows: List(VulnRow),
  unsupported_packages: List(String),
  scopes: dict.Dict(String, manifest.Scope),
  palette: color.Palette,
) -> String {
  let affected = list.filter(rows, fn(row) { row.vulnerabilities != [] })
  let clean_count = list.length(rows) - list.length(affected)

  let summary =
    "Checked "
    <> int.to_string(list.length(rows))
    <> " packages: "
    <> int.to_string(list.length(affected))
    <> " with vulnerabilities, "
    <> int.to_string(clean_count)
    <> " clean."
    <> case unsupported_packages {
      [] -> ""
      pkgs ->
        " Skipped "
        <> int.to_string(list.length(pkgs))
        <> " unsupported source(s): "
        <> string.join(pkgs, with: ", ")
    }

  let document = case affected {
    [] ->
      string.join(
        ["No known vulnerabilities reported by OSV.dev.", summary],
        with: "\n",
      )
    _ -> {
      let body =
        list.map(affected, fn(row) { format_vuln_row(row, scopes, palette) })
        |> string.join(with: "\n")
      color.boxed(palette, "Vulnerabilities · OSV.dev", body) <> "\n" <> summary
    }
  }

  document <> "\n"
}

fn format_vuln_row(
  row: VulnRow,
  scopes: dict.Dict(String, manifest.Scope),
  palette: color.Palette,
) -> String {
  let scope = case dict.get(scopes, row.package.name) {
    Ok(scope) -> scope
    Error(_) -> manifest.Prod
  }
  let pkg_line =
    color.bold(palette, row.package.name <> " " <> row.package.version)
    <> "  "
    <> color.dim(palette, "[" <> manifest.scope_label(scope) <> "]")
  let vuln_lines =
    list.map(row.vulnerabilities, fn(vuln) {
      let severity_text = color.severity(palette, severity_label(vuln.severity))
      "  "
      <> severity_text
      <> "  "
      <> vuln.id
      <> case vuln.summary {
        "" -> ""
        s -> "  " <> color.dim(palette, truncate(s, 80))
      }
    })
    |> string.join(with: "\n")
  pkg_line <> "\n" <> vuln_lines
}

fn severity_label(severity: osv.Severity) -> color.SeverityLabel {
  case severity {
    osv.Critical -> color.CriticalSeverity
    osv.High -> color.HighSeverity
    osv.Medium -> color.MediumSeverity
    osv.Low -> color.LowSeverity
    osv.UnknownSeverity -> color.UnknownSeverityLabel
  }
}

fn truncate(s: String, max: Int) -> String {
  use <- bool.guard(when: string.length(s) <= max, return: s)
  string.slice(s, 0, max - 1) <> "…"
}

// --- Vulnerability gate for `check --vulns` -----------------------------

fn resolve_vuln_threshold(
  cli_value: option.Option(String),
  config_value: option.Option(String),
) -> osv.Severity {
  let raw = case cli_value {
    Some(value) -> value
    None ->
      case config_value {
        Some(value) -> value
        None -> "high"
      }
  }
  case osv.parse_severity_label(raw) {
    osv.UnknownSeverity -> osv.High
    severity -> severity
  }
}

fn run_vuln_check_for_audit(
  packages: List(manifest.SbomEntry),
  threshold: osv.Severity,
  block_unknown: Bool,
  batch_fetcher: fn(List(String)) -> Result(List(osv.BatchEntry), osv.Error),
  detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  reporter: progress.Reporter,
  palette: color.Palette,
) -> VulnGateOutcome {
  let #(purl_pairs, unsupported_packages) =
    build_purl_pairs(
      manifest.SbomManifest(entries: packages, root_requirements: []),
    )
  let purls = list.map(purl_pairs, fn(pair) { pair.1 })

  case purls {
    [] ->
      VulnGateOutcome(
        report_text: format_unsupported_sources(unsupported_packages),
        gate_failed: False,
        unknown_failed: False,
        query_failed: False,
        detail_incomplete: False,
        reporter: reporter,
      )
    _ ->
      query_vuln_gate(
        purls,
        purl_pairs,
        unsupported_packages,
        threshold,
        block_unknown,
        batch_fetcher,
        detail_fetcher,
        reporter,
        palette,
      )
  }
}

/// Query OSV and evaluate the `check --vulns` gate.
fn query_vuln_gate(
  purls: List(String),
  purl_pairs: List(PurlPair),
  unsupported_packages: List(String),
  threshold: osv.Severity,
  block_unknown: Bool,
  batch_fetcher: fn(List(String)) -> Result(List(osv.BatchEntry), osv.Error),
  detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  reporter: progress.Reporter,
  palette: color.Palette,
) -> VulnGateOutcome {
  let reporter =
    progress.detail(
      reporter,
      "Querying OSV.dev for "
        <> int.to_string(list.length(purls))
        <> " packages",
    )
  case batch_fetcher(purls) {
    Error(_) -> {
      let reporter =
        progress.defer_error(
          reporter,
          "Vulnerability check failed: OSV request failed",
        )
      VulnGateOutcome(
        report_text: "\nVulnerability check failed: OSV request failed.\n",
        gate_failed: False,
        unknown_failed: False,
        query_failed: True,
        detail_incomplete: False,
        reporter: reporter,
      )
    }
    Ok(entries) ->
      evaluate_vuln_gate(
        entries,
        purl_pairs,
        unsupported_packages,
        threshold,
        block_unknown,
        detail_fetcher,
        reporter,
        palette,
      )
  }
}

/// Fetch advisory details for a resolved OSV batch and evaluate the gate.
/// A failed advisory detail lookup means the gate can't evaluate that
/// advisory's severity — never treat it as an implicit pass (unknown
/// severity is non-blocking by default). Fail the check outright so the
/// failure surfaces regardless of threshold or --vuln-block-unknown.
fn evaluate_vuln_gate(
  entries: List(osv.BatchEntry),
  purl_pairs: List(PurlPair),
  unsupported_packages: List(String),
  threshold: osv.Severity,
  block_unknown: Bool,
  detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  reporter: progress.Reporter,
  palette: color.Palette,
) -> VulnGateOutcome {
  let id_to_pkg = build_id_to_package_index(purl_pairs, entries)
  let unique_ids = unique_vuln_ids(entries)
  let #(vulns, detail_failures, reporter) =
    fetch_vulnerabilities(unique_ids, detail_fetcher, reporter, [])
  case detail_failures {
    [] -> {
      let triggering =
        list.filter(vulns, fn(vuln) {
          advisory_blocks(vuln.severity, threshold, block_unknown)
        })
      let unknown_failed =
        list.any(triggering, fn(vuln) { vuln.severity == osv.UnknownSeverity })
      let report_text =
        format_vuln_gate_output(
          vulns,
          triggering,
          threshold,
          block_unknown,
          id_to_pkg,
          unsupported_packages,
          palette,
        )
      VulnGateOutcome(
        report_text: report_text,
        gate_failed: triggering != [],
        unknown_failed: unknown_failed,
        query_failed: False,
        detail_incomplete: False,
        reporter: reporter,
      )
    }
    _ -> {
      // Defer the specific advisory IDs/reasons here — this is the only
      // error message for this outcome. finalize_audit must not attach its
      // own generic "OSV request failed" message on top of this one.
      let reporter =
        progress.defer_error(
          reporter,
          "Vulnerability check incomplete: failed to fetch OSV advisory details for "
            <> int.to_string(list.length(detail_failures))
            <> " advisory/advisories",
        )
      VulnGateOutcome(
        report_text: format_vuln_detail_failures_output(detail_failures),
        gate_failed: False,
        unknown_failed: False,
        query_failed: False,
        detail_incomplete: True,
        reporter: reporter,
      )
    }
  }
}

fn format_vuln_detail_failures_output(failures: List(DetailFailure)) -> String {
  let lines =
    list.map(failures, fn(failure) {
      "  " <> failure.id <> ": " <> failure.reason
    })
    |> string.join(with: "\n")
  "\nVulnerability check incomplete: failed to fetch OSV advisory details for "
  <> int.to_string(list.length(failures))
  <> " advisory/advisories. The gate cannot confirm these are safe, so the check fails:\n"
  <> lines
  <> "\n"
}

fn build_id_to_package_index(
  packages: List(PurlPair),
  entries: List(osv.BatchEntry),
) -> dict.Dict(String, List(String)) {
  // Build a map from each OSV ID to the list of package names that purl
  // matched, so reports can attribute findings back to packages even after
  // we deduplicate detail fetches across IDs.
  let pairs = list.zip(packages, entries)
  list.fold(pairs, dict.new(), fn(acc, pair) {
    let #(#(pkg, _purl), entry) = pair
    let label = pkg.name <> "@" <> pkg.version
    list.fold(entry.vuln_ids, acc, fn(inner, id) {
      let existing = case dict.get(inner, id) {
        Ok(v) -> v
        Error(_) -> []
      }
      dict.insert(inner, id, list.append(existing, [label]))
    })
  })
}

fn unique_vuln_ids(entries: List(osv.BatchEntry)) -> List(String) {
  let seen =
    list.fold(entries, dict.new(), fn(acc, entry) {
      list.fold(entry.vuln_ids, acc, fn(inner, id) {
        dict.insert(inner, id, Nil)
      })
    })
  dict.keys(seen)
}

fn advisory_blocks(
  actual: osv.Severity,
  threshold: osv.Severity,
  block_unknown: Bool,
) -> Bool {
  case actual {
    osv.UnknownSeverity -> block_unknown
    osv.Low | osv.Medium | osv.High | osv.Critical ->
      severity_rank(actual) >= severity_rank(threshold)
  }
}

fn severity_rank(severity: osv.Severity) -> Int {
  case severity {
    osv.UnknownSeverity -> 0
    osv.Low -> 1
    osv.Medium -> 2
    osv.High -> 3
    osv.Critical -> 4
  }
}

fn format_vuln_gate_output(
  all_vulns: List(osv.Vulnerability),
  triggering: List(osv.Vulnerability),
  threshold: osv.Severity,
  block_unknown: Bool,
  id_to_pkg: dict.Dict(String, List(String)),
  unsupported_packages: List(String),
  palette: color.Palette,
) -> String {
  case all_vulns {
    [] ->
      "\nNo known vulnerabilities reported by OSV.dev.\n"
      <> format_unsupported_sources(unsupported_packages)
    _ -> {
      let lines =
        list.map(all_vulns, fn(vuln) {
          let label = case dict.get(id_to_pkg, vuln.id) {
            Ok(pkgs) -> string.join(pkgs, with: ", ")
            Error(_) -> "(unknown)"
          }
          let marker = case
            advisory_blocks(vuln.severity, threshold, block_unknown)
          {
            True -> color.red(palette, "✗")
            False -> color.dim(palette, "·")
          }
          marker
          <> "  "
          <> color.severity(palette, severity_label(vuln.severity))
          <> "  "
          <> vuln.id
          <> "  "
          <> color.dim(palette, label)
        })
        |> string.join(with: "\n")
      let trigger_count = int.to_string(list.length(triggering))
      let total_count = int.to_string(list.length(all_vulns))
      let unknown_triggered =
        list.any(triggering, fn(vuln) { vuln.severity == osv.UnknownSeverity })
      let summary = case unknown_triggered {
        True ->
          trigger_count
          <> " blocking advisory/advisories: known severity at or above "
          <> osv.severity_to_string(threshold)
          <> " or unknown severity (of "
          <> total_count
          <> " total reported)."
        False ->
          trigger_count
          <> " advisory/advisories at or above "
          <> osv.severity_to_string(threshold)
          <> " (of "
          <> total_count
          <> " total reported)."
      }

      let title =
        "Vulnerability check · threshold: "
        <> osv.severity_to_string(threshold)
        <> case block_unknown {
          True -> " · unknown: block"
          False -> ""
        }

      "\n"
      <> color.boxed(palette, title, lines)
      <> "\n"
      <> summary
      <> "\n"
      <> format_unsupported_sources(unsupported_packages)
    }
  }
}

fn format_unsupported_sources(packages: List(String)) -> String {
  case packages {
    [] -> ""
    _ ->
      "Skipped "
      <> int.to_string(list.length(packages))
      <> " unsupported source(s): "
      <> string.join(packages, with: ", ")
      <> "\n"
  }
}
