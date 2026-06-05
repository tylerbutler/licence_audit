import argv
import gleam/bool
import gleam/dict
import gleam/int
import gleam/io
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import glint
import licence_audit/cache
import licence_audit/cli
import licence_audit/color
import licence_audit/config
import licence_audit/error
import licence_audit/hex
import licence_audit/manifest
import licence_audit/osv
import licence_audit/policy
import licence_audit/progress
import licence_audit/report
import licence_audit/sbom
import licence_audit/sbom_json
import licence_audit/sbom_uuid
import licence_audit/toml
import licence_audit/update as update_cmd
import simplifile

pub type RunResult {
  RunResult(exit_code: Int, output: String)
}

type FetchResult {
  FetchResult(
    rows: List(report.Row),
    fetch_failed: Bool,
    policy_failed: Bool,
    reporter: progress.Reporter,
  )
}

pub fn main() -> Nil {
  case glint.execute(cli.app(), cli.normalize_args(argv.load().arguments)) {
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
      let #(update_cmd.UpdateResult(exit_code, output), _) =
        run_update_options(
          options,
          hex.fetch_package_metadata_from_hex,
          progress.enabled(options.verbosity, "update"),
        )
      io.print(output)
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
    cli.GenDocsCompleted -> Nil
  }
}

pub fn run(args: List(String)) -> RunResult {
  run_with(args, hex.fetch_package_metadata_from_hex)
}

pub fn run_with(
  args: List(String),
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
) -> RunResult {
  let #(result, _) =
    run_with_reporter(
      list.append(args, ["--no-cache"]),
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
      list.append(args, ["--no-cache"]),
      fetcher,
      osv_batch_fetcher,
      osv_detail_fetcher,
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
      list.append(args, ["--no-cache"]),
      fetcher,
      osv.query_batch_from_osv,
      osv.fetch_vulnerability_from_osv,
      progress.capturing(verbosity, "report"),
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
  let project_root = option_value(options.project_root, ".")
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
        project_root,
        fetcher,
        osv_batch_fetcher,
        osv_detail_fetcher,
        reporter,
      )
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

  let #(package_metadata, reporter) = case options.offline {
    True -> #(dict.new(), reporter)
    False -> fetch_package_metadata(sbom_manifest, cached_fetcher, reporter)
  }
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
  let #(serial_number, timestamp) = case options.reproducible {
    True -> #(sbom.ContentDerivedSerial, sbom_uuid.reproducible_timestamp())
    False -> #(
      sbom.FixedSerial(sbom_uuid.serial_number()),
      sbom_uuid.timestamp_now(),
    )
  }

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
          let #(vulns, reporter) =
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
  fetcher: fn(manifest.Package, progress.Reporter) ->
    #(Result(hex.PackageMetadata, hex.Error), progress.Reporter),
  reporter: progress.Reporter,
) -> #(dict.Dict(String, hex.PackageMetadata), progress.Reporter) {
  list.fold(manifest_value.entries, #(dict.new(), reporter), fn(acc, entry) {
    let #(metadata_acc, rep) = acc
    case entry.provenance {
      manifest.HexProvenance(_, _) -> {
        let package =
          manifest.Package(
            name: entry.name,
            version: entry.version,
            source: manifest.Hex,
            kind: entry.kind,
            requirements: entry.requirements,
          )
        let #(result, rep) = fetcher(package, rep)
        case result {
          Ok(metadata) -> #(
            dict.insert(metadata_acc, entry.name, metadata),
            rep,
          )
          Error(_) -> #(metadata_acc, rep)
        }
      }
      _ -> #(metadata_acc, rep)
    }
  })
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
  case simplifile.read(from: "gleam.toml") {
    Error(_) -> "unknown"
    Ok(contents) ->
      case toml.parse(contents) {
        Error(_) -> "unknown"
        Ok(doc) ->
          case toml.get_string(doc, ["version"]) {
            Ok(v) -> v
            Error(_) -> "unknown"
          }
      }
  }
}

fn write_sbom_output(
  output: option.Option(String),
  json_str: String,
  reporter: progress.Reporter,
) -> #(RunResult, progress.Reporter) {
  case output {
    option.None ->
      case sbom_json.pretty_print(json_str) {
        Ok(pretty_json) -> #(RunResult(0, pretty_json <> "\n"), reporter)
        Error(reason) -> #(
          RunResult(
            2,
            "Error: failed to format SBOM JSON: "
              <> sbom_json.describe_error(reason)
              <> "\n",
          ),
          reporter,
        )
      }
    option.Some(path) ->
      case simplifile.write(to: path, contents: json_str <> "\n") {
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
  let project_root = option_value(options.project_root, ".")
  let reporter = progress.phase(reporter, "Starting licence audit")
  let reporter = progress.detail(reporter, "Loading licence policy")

  case prepare_audit(options, manifest_path, project_root, reporter) {
    Error(failure) -> failure
    Ok(#(config_policy, audit_policy, locked, scopes, reporter)) ->
      audit_locked(
        options,
        config_policy,
        audit_policy,
        locked,
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
  let scopes = compute_scopes(project_root, locked)
  Ok(#(config_policy, audit_policy, locked, scopes, reporter))
}

/// Run the audit over a loaded manifest: fetch licences, render the report,
/// optionally run the vulnerability gate, then compute the final result.
fn audit_locked(
  options: cli.Options,
  config_policy: config.Policy,
  audit_policy: policy.Policy,
  locked: manifest.LockedPackages,
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
  let skipped_names = list.map(locked.skipped_packages, fn(pkg) { pkg.name })
  let licence_output =
    report.format(
      display_rows,
      report.Summary(skipped_names: skipped_names),
      mode,
      palette,
    )

  // Vulnerability gate: only when running `check` with --vulns.
  // Threshold resolution: CLI flag > config key > "high".
  let #(vulns_output, vuln_failed, vuln_query_failed, vuln_reporter) = case
    options.check && options.check_vulns
  {
    False -> #("", False, False, result.reporter)
    True -> {
      let threshold =
        resolve_vuln_threshold(
          options.vuln_severity,
          config_policy.vuln_severity,
        )
      run_vuln_check_for_audit(
        locked.packages,
        threshold,
        osv_batch_fetcher,
        osv_detail_fetcher,
        result.reporter,
        palette,
      )
    }
  }

  let output = licence_output <> vulns_output

  let #(run_result, reporter) =
    finalize_audit(
      options.check,
      result.fetch_failed,
      vuln_query_failed,
      result.policy_failed,
      vuln_failed,
      output,
      vuln_reporter,
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
  policy_failed: Bool,
  vuln_failed: Bool,
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
        <> "Vulnerability check failed: one or more advisories at or above threshold severity.\n",
    ),
    progress.defer_error(
      reporter,
      "Vulnerability check failed: advisories at or above threshold",
    ),
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
    report.Checked(_) -> True
    _ -> False
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
  let project_root = option_value(options.project_root, ".")
  update_cmd.run(
    manifest_path,
    project_root,
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
  let project_root = option_value(options.project_root, ".")
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
          resolve_prod_seed(project_root, sbom_manifest.root_requirements),
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
          let #(vulns, reporter) =
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
) -> #(List(osv.Vulnerability), progress.Reporter) {
  case ids {
    [] -> #(list.reverse(acc), reporter)
    [id, ..rest] -> {
      case detail_fetcher(id) {
        Ok(vuln) ->
          fetch_vulnerabilities(rest, detail_fetcher, reporter, [vuln, ..acc])
        Error(_) -> {
          let reporter =
            progress.defer_warn(
              reporter,
              "Failed to fetch OSV details for " <> id,
            )
          fetch_vulnerabilities(rest, detail_fetcher, reporter, [
            placeholder_vulnerability(id),
            ..acc
          ])
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
      string.join(
        [
          "Vulnerabilities reported by OSV.dev:",
          horizontal_rule(),
          body,
          horizontal_rule(),
          summary,
        ],
        with: "\n",
      )
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
    "● "
    <> row.package.name
    <> " "
    <> row.package.version
    <> "  ["
    <> manifest.scope_label(scope)
    <> "]"
  let vuln_lines =
    list.map(row.vulnerabilities, fn(vuln) {
      let severity_text = color.severity(palette, severity_label(vuln.severity))
      "    "
      <> severity_text
      <> "  "
      <> vuln.id
      <> case vuln.summary {
        "" -> ""
        s -> "  " <> truncate(s, 80)
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
  packages: List(manifest.Package),
  threshold: osv.Severity,
  batch_fetcher: fn(List(String)) -> Result(List(osv.BatchEntry), osv.Error),
  detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  reporter: progress.Reporter,
  palette: color.Palette,
) -> #(String, Bool, Bool, progress.Reporter) {
  let purl_pairs =
    list.map(packages, fn(pkg) {
      #(pkg, "pkg:hex/" <> pkg.name <> "@" <> pkg.version)
    })
  let purls = list.map(purl_pairs, fn(pair) { pair.1 })

  case purls {
    [] -> #("", False, False, reporter)
    _ ->
      query_vuln_gate(
        purls,
        packages,
        threshold,
        batch_fetcher,
        detail_fetcher,
        reporter,
        palette,
      )
  }
}

/// Query OSV and evaluate the `check --vulns` gate. Returns
/// `#(report_text, gate_failed, query_failed, reporter)`.
fn query_vuln_gate(
  purls: List(String),
  packages: List(manifest.Package),
  threshold: osv.Severity,
  batch_fetcher: fn(List(String)) -> Result(List(osv.BatchEntry), osv.Error),
  detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  reporter: progress.Reporter,
  palette: color.Palette,
) -> #(String, Bool, Bool, progress.Reporter) {
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
      #(
        "\nVulnerability check failed: OSV request failed.\n",
        False,
        True,
        reporter,
      )
    }
    Ok(entries) -> {
      let id_to_pkg = build_id_to_package_index(packages, entries)
      let unique_ids = unique_vuln_ids(entries)
      let #(vulns, reporter) =
        fetch_vulnerabilities(unique_ids, detail_fetcher, reporter, [])
      let triggering =
        list.filter(vulns, fn(vuln) {
          severity_meets_or_exceeds(vuln.severity, threshold)
        })
      let report_text =
        format_vuln_gate_output(
          vulns,
          triggering,
          threshold,
          id_to_pkg,
          palette,
        )
      #(report_text, triggering != [], False, reporter)
    }
  }
}

fn build_id_to_package_index(
  packages: List(manifest.Package),
  entries: List(osv.BatchEntry),
) -> dict.Dict(String, List(String)) {
  // Build a map from each OSV ID to the list of package names that purl
  // matched, so reports can attribute findings back to packages even after
  // we deduplicate detail fetches across IDs.
  let pairs = list.zip(packages, entries)
  list.fold(pairs, dict.new(), fn(acc, pair) {
    let #(pkg, entry) = pair
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

fn severity_meets_or_exceeds(
  actual: osv.Severity,
  threshold: osv.Severity,
) -> Bool {
  severity_rank(actual) >= severity_rank(threshold)
  && actual != osv.UnknownSeverity
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
  id_to_pkg: dict.Dict(String, List(String)),
  palette: color.Palette,
) -> String {
  case all_vulns {
    [] -> "\nNo known vulnerabilities reported by OSV.dev.\n"
    _ -> {
      let lines =
        list.map(all_vulns, fn(vuln) {
          let label = case dict.get(id_to_pkg, vuln.id) {
            Ok(pkgs) -> string.join(pkgs, with: ", ")
            Error(_) -> "(unknown)"
          }
          let marker = case
            severity_meets_or_exceeds(vuln.severity, threshold)
          {
            True -> "✗"
            False -> "·"
          }
          marker
          <> "  "
          <> color.severity(palette, severity_label(vuln.severity))
          <> "  "
          <> vuln.id
          <> "  "
          <> label
        })
        |> string.join(with: "\n")
      let summary =
        int.to_string(list.length(triggering))
        <> " advisory/advisories at or above "
        <> osv.severity_to_string(threshold)
        <> " (of "
        <> int.to_string(list.length(all_vulns))
        <> " total reported)."

      "\n"
      <> string.join(
        [
          "Vulnerability check (threshold: "
            <> osv.severity_to_string(threshold)
            <> ")",
          horizontal_rule(),
          lines,
          horizontal_rule(),
          summary,
        ],
        with: "\n",
      )
      <> "\n"
    }
  }
}

fn horizontal_rule() -> String {
  string.repeat("─", 72)
}
