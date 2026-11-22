import gleam/bool
import gleam/dict
import gleam/int
import gleam/io
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/time/timestamp
import licence_audit/cache
import licence_audit/cli
import licence_audit/color
import licence_audit/config
import licence_audit/error
import licence_audit/exception
import licence_audit/hex
import licence_audit/httpc_adaptive
import licence_audit/internal/vendor/glint
import licence_audit/manifest
import licence_audit/network
import licence_audit/notice
import licence_audit/notice_command
import licence_audit/osv
import licence_audit/path
import licence_audit/policy
import licence_audit/progress
import licence_audit/report
import licence_audit/sbom
import licence_audit/sbom_command
import licence_audit/update as update_cmd
import licence_audit/version
import tty

pub type RunResult {
  RunResult(exit_code: Int, output: String)
}

type ActionResult {
  Report(result: RunResult)
  Diagnostic(result: RunResult)
}

fn report_result(exit_code: Int, output: String) -> ActionResult {
  Report(RunResult(exit_code, output))
}

pub type Clients {
  Clients(
    fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
    publication_fetcher: fn(String, String) ->
      Result(hex.Publication, hex.Error),
    osv_batch_fetcher: fn(List(String)) ->
      Result(List(osv.BatchEntry), osv.Error),
    osv_detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
    notice_clients: notice.Clients,
  )
}

pub fn default_clients() -> Clients {
  Clients(
    fetcher: hex.fetch_package_metadata_from_hex,
    publication_fetcher: hex.fetch_publication_from_hex,
    osv_batch_fetcher: osv.query_batch_from_osv,
    osv_detail_fetcher: osv.fetch_vulnerability_from_osv,
    notice_clients: notice.default_clients(),
  )
}

@external(erlang, "args_ffi", "arguments")
fn arguments() -> List(String)

@external(erlang, "runtime_ffi", "start")
fn start_runtime() -> Result(Nil, error.Error)

@external(erlang, "runtime_ffi", "run")
fn run_cli(action: fn() -> Nil) -> Result(Nil, error.Error)

type FetchResult {
  FetchResult(
    rows: List(report.Row),
    fetch_failed: Bool,
    reporter: progress.Reporter,
  )
}

pub fn main() -> Nil {
  case run_cli(main_action) {
    Ok(Nil) -> Nil
    Error(runtime_error) -> {
      let result = diagnostic(runtime_error)
      io.print_error(result.result.output)
      halt(result.result.exit_code)
    }
  }
}

fn main_action() -> Nil {
  case
    cli.execute(
      arguments(),
      tty.detect_color_level(tty.Stdout),
      tty.detect_color_level(tty.Stderr),
    )
  {
    Error(message) -> {
      io.println_error(message)
      halt(2)
    }
    Ok(glint.Help(help)) -> io.println(help)
    Ok(glint.Out(action)) ->
      case action {
        cli.ShowVersion | cli.InvalidUsage(_) -> handle_action(action)
        _ ->
          case start_runtime() {
            Ok(Nil) -> handle_action(action)
            Error(startup_error) -> {
              let result = diagnostic(startup_error)
              let RunResult(exit_code, output) = result.result
              io.print_error(output)
              halt(exit_code)
            }
          }
      }
  }
}

fn handle_action(action: cli.CliAction) -> Nil {
  let #(result, reporter) =
    execute_action(
      action,
      default_clients(),
      reporter_for_action(action),
      palette_for_action(action),
    )
  let RunResult(exit_code, output) = result.result
  case result {
    Diagnostic(_) -> {
      io.print_error(output)
    }
    Report(_) -> {
      io.print(output)
    }
  }
  let _ = progress.flush(apply_http_warning(reporter))
  halt(exit_code)
}

fn reporter_for_action(action: cli.CliAction) -> progress.Reporter {
  case action {
    cli.RunReport(options) ->
      progress.enabled(options.verbosity, "report", options.color)
    cli.RunAudit(options) ->
      progress.enabled(options.verbosity, "check", options.color)
    cli.UpdateConfig(options) ->
      progress.enabled(options.verbosity, "update", options.color)
    cli.RunSbom(options) ->
      progress.enabled(options.verbosity, "sbom", options.color)
    cli.RunVulns(options) ->
      progress.enabled(options.verbosity, "vulns", options.color)
    cli.RunNotices(options) ->
      progress.enabled(options.verbosity, "notices", options.color)
    cli.ShowVersion | cli.InvalidUsage(_) -> progress.disabled()
  }
}

fn palette_for_action(action: cli.CliAction) -> color.Palette {
  case action {
    cli.RunReport(options) -> color.resolve(options.color)
    cli.RunAudit(options) -> color.resolve(options.color)
    cli.RunVulns(options) -> color.resolve(options.color)
    _ -> color.for_enabled(False)
  }
}

fn apply_http_warning(reporter: progress.Reporter) -> progress.Reporter {
  case httpc_adaptive.take_warning() {
    Some(message) -> progress.defer_warn(reporter, message)
    None -> reporter
  }
}

pub fn run(args: List(String)) -> RunResult {
  let #(result, _) =
    run_configured(args, default_clients(), progress.disabled())
  result
}

fn without_cache(action: cli.CliAction) -> cli.CliAction {
  case action {
    cli.RunReport(options) ->
      cli.RunReport(cli.ReportOptions(..options, no_cache: True))
    cli.RunAudit(options) ->
      cli.RunAudit(cli.Options(..options, no_cache: True))
    cli.UpdateConfig(options) ->
      cli.UpdateConfig(cli.UpdateOptions(..options, no_cache: True))
    cli.RunSbom(options) ->
      cli.RunSbom(cli.SbomOptions(..options, no_cache: True))
    cli.RunNotices(options) ->
      cli.RunNotices(cli.NoticesOptions(..options, no_cache: True))
    cli.RunVulns(_) | cli.ShowVersion | cli.InvalidUsage(_) -> action
  }
}

pub fn run_configured(
  args: List(String),
  clients: Clients,
  reporter: progress.Reporter,
) -> #(RunResult, List(progress.Event)) {
  run_configured_with_cache(args, clients, reporter, bypass_cache: True)
}

/// Execute CLI options with injected clients, including their cache settings.
/// Embedded entry points above still bypass disk storage.
pub fn run_cli_configured(
  args: List(String),
  clients: Clients,
  reporter: progress.Reporter,
) -> #(RunResult, List(progress.Event)) {
  run_configured_with_cache(args, clients, reporter, bypass_cache: False)
}

fn run_configured_with_cache(
  args: List(String),
  clients: Clients,
  reporter: progress.Reporter,
  bypass_cache bypass_cache: Bool,
) -> #(RunResult, List(progress.Event)) {
  let #(result, reporter) = case
    glint.execute(cli.app(), cli.normalize_args(args))
  {
    Ok(glint.Help(help)) -> #(report_result(0, help <> "\n"), reporter)
    Ok(glint.Out(action)) -> {
      let action = case bypass_cache {
        True -> without_cache(action)
        False -> action
      }
      execute_action(action, clients, reporter, color.for_enabled(False))
    }
    Error(message) -> #(Diagnostic(RunResult(2, message <> "\n")), reporter)
  }
  #(result.result, progress.events(reporter))
}

fn execute_action(
  action: cli.CliAction,
  clients: Clients,
  reporter: progress.Reporter,
  palette: color.Palette,
) -> #(ActionResult, progress.Reporter) {
  network.with_command(fn() {
    httpc_adaptive.reset_retry_state()
    let outcome = case action {
      cli.RunReport(options) ->
        run_options_with_clients(
          cli.Options(
            manifest_path: options.manifest_path,
            config_path: options.config_path,
            ignore_config: options.ignore_config,
            check: False,
            verbosity: options.verbosity,
            color: options.color,
            no_cache: options.no_cache,
            cache_dir: options.cache_dir,
            checks: cli.Licences,
            vuln_severity: None,
            vuln_block_unknown: None,
            scope: options.scope,
          ),
          clients,
          reporter,
          palette,
        )
      cli.RunAudit(options) ->
        run_options_with_clients(options, clients, reporter, palette)
      cli.UpdateConfig(options) -> {
        let #(result, reporter) = run_update_options(options, clients, reporter)
        let run_result = RunResult(result.exit_code, result.output)
        #(
          case result {
            update_cmd.UpdateResult(..) -> Report(run_result)
            update_cmd.UpdateDiagnostic(..) -> Diagnostic(run_result)
          },
          reporter,
        )
      }
      cli.InvalidUsage(message) -> #(
        Diagnostic(RunResult(2, "Error: " <> message <> "\n")),
        reporter,
      )
      cli.RunSbom(options) -> run_sbom_options(options, clients, reporter)
      cli.RunVulns(options) -> {
        let #(result, reporter) =
          run_vulns_options(options, clients, reporter, palette)
        #(result, reporter)
      }
      cli.RunNotices(options) ->
        run_notices_options(options, clients.notice_clients, reporter)
      cli.ShowVersion -> #(report_result(0, tool_version() <> "\n"), reporter)
    }
    let #(result, reporter) = outcome
    #(result, apply_http_warning(reporter))
  })
}

fn run_sbom_options(
  options: cli.SbomOptions,
  clients: Clients,
  reporter: progress.Reporter,
) -> #(ActionResult, progress.Reporter) {
  let #(result, reporter) =
    sbom_command.run(
      options,
      clients.fetcher,
      clients.publication_fetcher,
      clients.osv_batch_fetcher,
      fn(ids, reporter) {
        fetch_sbom_advisories(ids, clients.osv_detail_fetcher, reporter)
      },
      clients.notice_clients,
      reporter,
    )
  case result {
    Ok(output) -> #(report_result(0, output), reporter)
    Error(reason) -> #(diagnostic(reason), reporter)
  }
}

fn fetch_sbom_advisories(
  ids: List(String),
  detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  reporter: progress.Reporter,
) -> #(Result(List(osv.Vulnerability), error.Error), progress.Reporter) {
  let #(vulnerabilities, failures, reporter) =
    fetch_vulnerabilities(ids, detail_fetcher, reporter)
  case list.any(failures, fn(failure) { failure.runtime_failed }) {
    True -> #(
      Error(error.RuntimeException(
        format_vuln_detail_failures_output(failures)
        |> string.trim,
      )),
      reporter,
    )
    False -> #(Ok(vulnerabilities), reporter)
  }
}

fn run_notices_options(
  options: cli.NoticesOptions,
  clients: notice.Clients,
  reporter: progress.Reporter,
) -> #(ActionResult, progress.Reporter) {
  let #(result, reporter) = notice_command.run(options, clients, reporter)
  case result {
    Ok(output) -> #(report_result(0, output), reporter)
    Error(reason) -> #(diagnostic(reason), reporter)
  }
}

fn tool_version() -> String {
  case version.build_version() {
    Ok(v) -> v
    Error(Nil) -> "unknown"
  }
}

fn run_options_with_clients(
  options: cli.Options,
  clients: Clients,
  reporter: progress.Reporter,
  palette: color.Palette,
) -> #(ActionResult, progress.Reporter) {
  use <- bool.lazy_guard(
    when: options.check && options.checks == cli.Vulnerabilities,
    return: fn() {
      run_vulnerability_check(options, clients, reporter, palette)
    },
  )
  let manifest_path = option.unwrap(options.manifest_path, "manifest.toml")
  let manifest_path = manifest.resolve_path(manifest_path)
  let project_root = path.dirname(manifest_path)
  let reporter = progress.phase(reporter, "Starting licence audit")
  let reporter = progress.detail(reporter, "Loading licence policy")

  case prepare_audit(options, manifest_path, project_root, reporter) {
    Error(failure) -> failure
    Ok(#(
      config_policy,
      audit_policy,
      locked,
      sbom_manifest,
      prod_seed,
      scopes,
      reporter,
    )) ->
      audit_locked(
        options,
        config_policy,
        audit_policy,
        locked,
        sbom_manifest,
        prod_seed,
        scopes,
        clients,
        reporter,
        palette,
      )
  }
}

/// Load the licence policy and package manifest for an audit run. On any
/// failure, short-circuits with a diagnostic.
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
    List(String),
    dict.Dict(String, manifest.Scope),
    progress.Reporter,
  ),
  #(ActionResult, progress.Reporter),
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
  use sbom_manifest <- result.try(
    case options.check && options.checks == cli.AllChecks {
      False -> Ok(None)
      True ->
        manifest.load_vulns(manifest_path)
        |> result.map(Some)
        |> result.map_error(fn(e) {
          #(diagnostic(error.from_manifest_error(e)), reporter)
        })
    },
  )
  use prod_seed <- result.try(
    manifest.resolve_prod_seed(project_root, locked.direct_names)
    |> result.map_error(error.from_manifest_error)
    |> result.map_error(fn(scope_error) { #(diagnostic(scope_error), reporter) }),
  )
  let scopes = manifest.dep_scopes(locked, prod_seed)
  Ok(#(
    config_policy,
    audit_policy,
    locked,
    sbom_manifest,
    prod_seed,
    scopes,
    reporter,
  ))
}

/// Run the audit over a loaded manifest: fetch licences, render the report,
/// optionally run the vulnerability gate, then compute the final result.
fn audit_locked(
  options: cli.Options,
  config_policy: config.Policy,
  audit_policy: policy.Policy,
  locked: manifest.LockedPackages,
  sbom_manifest: Option(manifest.SbomManifest),
  prod_seed: List(String),
  scopes: dict.Dict(String, manifest.Scope),
  clients: Clients,
  reporter: progress.Reporter,
  palette: color.Palette,
) -> #(ActionResult, progress.Reporter) {
  let today = exception.utc_date(timestamp.system_time())
  let reporter = progress.package_count(reporter, list.length(locked.packages))
  let evaluate_policy = policy.has_rules(audit_policy)
  let mode = case evaluate_policy {
    True -> report.Audit
    False -> report.Default
  }
  let cache_mode = cache.mode_for(options.no_cache, options.cache_dir)
  let cache_handle = cache.open(cache_mode)
  let cached_fetcher =
    cache.wrap_locked(cache_handle, fn(name, version, checksum) {
      notice.hex_metadata_from_locked_source(
        name,
        version,
        checksum,
        clients.notice_clients.fetch_hex_tarball,
      )
    })
  let dep_paths = case options.scope {
    cli.All -> manifest.dep_paths(locked)
    cli.Prod -> manifest.dep_paths_from(locked, prod_seed)
  }
  let #(active_packages, active_skipped) = case options.scope {
    cli.All -> #(locked.packages, locked.skipped_packages)
    cli.Prod -> #(
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
      case options.scope {
        cli.All -> sbom_manifest.entries
        cli.Prod ->
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
      dep_paths,
      scopes,
      reporter,
      [],
      False,
    )
  let cache_warning = cache.close(cache_handle)
  let outcome = {
    use reviewed_rows <- result.try(
      review_licence_rows(
        result.rows,
        audit_policy,
        config_policy.exceptions,
        today,
      )
      |> result.map_error(fn(review_error) {
        #(diagnostic(review_error), result.reporter)
      }),
    )
    let policy_failed =
      list.any(reviewed_rows, fn(row) { report.is_failure(row.status) })
    let skipped_rows = build_skipped_rows(active_skipped, dep_paths, scopes)
    let all_rows = list.append(reviewed_rows, skipped_rows)
    let display_rows = case options.check && policy_failed {
      True -> report.filter_failing_trees(all_rows)
      False -> all_rows
    }
    let skipped_names = list.map(active_skipped, fn(pkg) { pkg.name })
    let summary = report.Summary(skipped_names: skipped_names)
    let licence_output =
      report.format_with_counts(
        display_rows,
        summary,
        report.counts(all_rows, summary),
        mode,
        palette,
      )
      <> case options.check {
        True -> report.format_findings(all_rows, palette)
        False -> ""
      }

    // Vulnerability gate: combined checks also retain the licence findings.
    // Threshold resolution: CLI flag > config key > "high".
    let vuln_outcome = case options.check && options.checks == cli.AllChecks {
      False ->
        VulnGateOutcome(
          status: Ok(GateNotEvaluated),
          report_text: "",
          queries: [],
          occurrences: [],
          detail_failures: [],
          unsupported_packages: [],
          coverage: exception.NotEvaluated("vulnerability scan disabled"),
          reporter: result.reporter,
        )
      True ->
        run_vuln_check_for_audit(
          active_sbom_entries,
          options,
          config_policy,
          clients,
          result.reporter,
          palette,
          today,
        )
    }

    use _ <- result.try(
      vuln_outcome.status
      |> result.map_error(fn(review_error) {
        #(diagnostic(review_error), vuln_outcome.reporter)
      }),
    )
    let excluded_licences =
      locked.packages
      |> list.filter(fn(pkg) {
        options.scope == cli.Prod && scope_for(scopes, pkg.name) == manifest.Dev
      })
      |> list.map(fn(pkg) {
        #(
          "pkg:hex/" <> string.lowercase(pkg.name) <> "@" <> pkg.version,
          "excluded by --scope=prod",
        )
      })
    let licence_coverage = case evaluate_policy {
      False -> exception.NotEvaluated("licence policy not configured")
      True ->
        exception.Evaluated(
          all_rows
            |> list.flat_map(fn(row) { report.decisions(row.status) })
            |> exception.matched,
          list.append(
            excluded_licences,
            all_rows
              |> list.filter_map(fn(row) {
                case row.status {
                  report.Failed(_) ->
                    Ok(#(
                      "pkg:hex/"
                        <> string.lowercase(row.package)
                        <> "@"
                        <> row.version,
                      "licence metadata unavailable",
                    ))
                  _ -> Error(Nil)
                }
              }),
          ),
        )
    }
    let excluded_vulns = case sbom_manifest {
      None -> []
      Some(manifest) ->
        manifest.entries
        |> list.filter(fn(entry) {
          options.scope == cli.Prod
          && scope_for(scopes, entry.name) == manifest.Dev
        })
        |> list.filter_map(fn(entry) {
          sbom.purl_for(entry)
          |> result.map(fn(purl) { #(purl, "excluded by --scope=prod") })
        })
    }
    let vuln_coverage = case vuln_outcome.coverage {
      exception.NotEvaluated(_) -> vuln_outcome.coverage
      exception.Evaluated(matched, unavailable) ->
        exception.Evaluated(matched, list.append(unavailable, excluded_vulns))
    }
    let output =
      licence_output
      <> vuln_outcome.report_text
      <> exception.summary(
        config_policy.exceptions,
        today,
        licence_coverage,
        vuln_coverage,
      )
      <> case
        options.check
        && !result.fetch_failed
        && case vuln_outcome.status {
          Ok(GateNotEvaluated) | Ok(GateEvaluated(_, CheckComplete)) -> True
          Ok(GateUnavailable(_))
          | Ok(GateEvaluated(_, CheckIncomplete))
          | Error(_) -> False
        }
        && !policy_failed
      {
        True -> "Licence check passed.\n"
        False -> ""
      }

    let licence_outcome =
      LicenceGateOutcome(
        verdict: case options.check, policy_failed {
          False, _ -> LicencesNotEnforced
          True, False -> LicencesPassed
          True, True -> LicencesBlocked
        },
        completeness: case result.fetch_failed {
          True -> CheckIncomplete
          False -> CheckComplete
        },
        rows: all_rows,
        coverage: licence_coverage,
      )
    let #(run_result, reporter) =
      finalize_audit(
        licence_outcome,
        VulnGateOutcome(..vuln_outcome, coverage: vuln_coverage),
        output,
        "Licence audit completed",
      )

    let reporter = case cache_warning {
      Some(message) -> progress.defer_warn(reporter, message)
      None -> reporter
    }
    Ok(#(run_result, reporter))
  }
  case outcome {
    Ok(outcome) | Error(outcome) -> outcome
  }
}

/// Compute the audit's exit code, output suffix, and deferred log message
/// from the independent findings and completeness states, in priority order.
fn finalize_audit(
  licences: LicenceGateOutcome,
  vulnerabilities: VulnGateOutcome,
  output: String,
  completion_message: String,
) -> #(ActionResult, progress.Reporter) {
  let reporter = vulnerabilities.reporter
  let outcome = {
    use status <- result.try(
      vulnerabilities.status
      |> result.map_error(fn(review_error) {
        #(diagnostic(review_error), reporter)
      }),
    )
    use <- bool.guard(
      when: licences.completeness == CheckIncomplete,
      return: Error(#(
        report_result(2, output),
        progress.defer_error(
          reporter,
          "Licence audit failed: package metadata could not be fetched",
        ),
      )),
    )
    use verdict <- result.try(case status {
      GateUnavailable(_) | GateEvaluated(_, CheckIncomplete) ->
        Error(#(report_result(2, output), reporter))
      GateNotEvaluated -> Ok(NoBlockingAdvisories)
      GateEvaluated(verdict, CheckComplete) -> Ok(verdict)
    })
    use <- bool.guard(
      when: licences.verdict == LicencesBlocked,
      return: Error(#(
        report_result(1, output <> error.message(error.AuditFailed) <> "\n"),
        reporter,
      )),
    )
    Ok(case verdict {
      BlockingKnownSeverity -> #(
        report_result(
          1,
          output
            <> "Vulnerability check failed: one or more advisories at or above threshold severity.\n",
        ),
        reporter,
      )
      BlockingUnknownSeverity -> #(
        report_result(
          1,
          output
            <> "Vulnerability check failed: one or more advisories met the severity threshold or the unknown-severity blocking rule.\n",
        ),
        reporter,
      )
      NoBlockingAdvisories -> #(
        report_result(0, output),
        progress.defer_success(reporter, completion_message),
      )
    })
  }
  case outcome {
    Ok(outcome) | Error(outcome) -> outcome
  }
}

fn fetch_packages(
  packages: List(manifest.Package),
  fetcher: fn(manifest.Package, progress.Reporter) ->
    #(Result(hex.PackageMetadata, notice.Error), progress.Reporter),
  audit_policy: policy.Policy,
  paths: dict.Dict(String, List(String)),
  scopes: dict.Dict(String, manifest.Scope),
  reporter: progress.Reporter,
  rows: List(report.Row),
  fetch_failed: Bool,
) -> FetchResult {
  let outcomes =
    network.fetch(
      packages,
      fn(package) { package.name <> "@" <> package.version },
      fn(package) { fetcher(package, progress.fork(reporter)) },
    )
  let result =
    list.fold(
      list.zip(packages, outcomes),
      FetchResult(rows, fetch_failed, reporter),
      fn(acc, pair) {
        let #(package, outcome) = pair
        let path = case dict.get(paths, package.name) {
          Ok(p) -> p
          Error(_) -> [package.name]
        }
        let #(fetch_result, reporter) = case outcome {
          Ok(#(fetched, captured)) -> #(
            result.map_error(fetched, notice.describe_error),
            progress.merge(acc.reporter, captured),
          )
          Error(reason) -> #(Error(reason), acc.reporter)
        }
        case fetch_result {
          Error(message) -> {
            let reporter =
              progress.fail(
                reporter,
                "Failed to fetch package metadata for "
                  <> package.name
                  <> "@"
                  <> package.version
                  <> ": "
                  <> message,
              )
            FetchResult(
              rows: [
                report.Row(
                  package: package.name,
                  version: package.version,
                  licences: [],
                  status: report.Failed(message),
                  scope: scope_for(scopes, package.name),
                  path: path,
                ),
                ..acc.rows
              ],
              fetch_failed: True,
              reporter: reporter,
            )
          }
          Ok(metadata) -> {
            let status = status_for(audit_policy, metadata.licences)
            FetchResult(
              rows: [
                report.Row(
                  package: package.name,
                  version: package.version,
                  licences: metadata.licences,
                  status: status,
                  scope: scope_for(scopes, package.name),
                  path: path,
                ),
                ..acc.rows
              ],
              fetch_failed: acc.fetch_failed,
              reporter: reporter,
            )
          }
        }
      },
    )
  FetchResult(..result, rows: list.reverse(result.rows))
}

/// Classify package licences when a policy is configured.
fn status_for(
  audit_policy: policy.Policy,
  licences: List(String),
) -> report.Status {
  case policy.has_rules(audit_policy) {
    True -> report.Checked(policy.audit(audit_policy, licences))
    False -> report.NotChecked
  }
}

fn load_policy(
  options: cli.Options,
  project_root: String,
) -> Result(config.Policy, config.Error) {
  let load_options =
    config.LoadOptions(
      config_path: options.config_path,
      project_root: project_root,
      allow_licences: [],
      deny_licences: [],
      vuln_severity: options.vuln_severity,
      vuln_block_unknown: options.vuln_block_unknown,
      ignore_config: options.ignore_config,
      check: options.check,
    )
  case options.checks {
    cli.Vulnerabilities -> config.load_vulns(load_options)
    cli.Licences | cli.AllChecks -> config.load(load_options)
  }
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
      scope: scope_for(scopes, pkg.name),
      path: path,
    )
  })
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

fn review_licence_rows(
  rows: List(report.Row),
  audit_policy: policy.Policy,
  exceptions: List(exception.Exception),
  today: String,
) -> Result(List(report.Row), error.Error) {
  use <- bool.guard(when: exceptions == [], return: Ok(rows))
  use _ <- result.try(
    exception.validate_identities(
      exceptions,
      list.map(rows, fn(row) {
        "pkg:hex/" <> string.lowercase(row.package) <> "@" <> row.version
      }),
    )
    |> result.map_error(error.from_exception_error),
  )
  list.try_map(rows, fn(row) {
    case row.status {
      report.Checked(_) ->
        review_licence_row(row, audit_policy, exceptions, today)
      _ -> Ok(row)
    }
  })
}

fn review_licence_row(
  row: report.Row,
  audit_policy: policy.Policy,
  exceptions: List(exception.Exception),
  today: String,
) -> Result(report.Row, error.Error) {
  use findings <- result.try(
    policy.findings(audit_policy, row.licences, fn(_) { False })
    |> list.try_map(fn(finding) {
      use decision <- result.try(
        exception.decide(
          exceptions,
          "pkg:hex/" <> string.lowercase(row.package) <> "@" <> row.version,
          finding,
          [],
          today,
        )
        |> result.map_error(error.from_exception_error),
      )
      Ok(#(finding, decision))
    }),
  )
  let selected =
    policy.findings(audit_policy, row.licences, fn(finding) {
      list.any(findings, fn(reviewed) {
        reviewed.0 == finding && exception.accepted(reviewed.1)
      })
    })
  let findings =
    list.filter(findings, fn(reviewed) { list.contains(selected, reviewed.0) })
  case exception.matched(list.map(findings, fn(finding) { finding.1 })) {
    [] -> Ok(row)
    _ -> Ok(report.Row(..row, status: report.Reviewed(findings)))
  }
}

fn diagnostic(audit_error: error.Error) -> ActionResult {
  Diagnostic(RunResult(
    error.exit_code(audit_error),
    "Error: " <> error.message(audit_error) <> "\n",
  ))
}

// Returning from main cannot set the CLI exit status or stop OTP applications.
@external(erlang, "erlang", "halt")
fn halt(code: Int) -> Nil

fn run_update_options(
  options: cli.UpdateOptions,
  clients: Clients,
  reporter: progress.Reporter,
) -> #(update_cmd.UpdateResult, progress.Reporter) {
  let manifest_path = option.unwrap(options.manifest_path, "manifest.toml")
  let manifest_path = manifest.resolve_path(manifest_path)
  let project_root = path.dirname(manifest_path)
  update_cmd.run(
    manifest_path,
    project_root,
    options,
    clients.notice_clients,
    reporter,
  )
}

// --- Vulnerability checking ---------------------------------------------

fn run_vulnerability_check(
  options: cli.Options,
  clients: Clients,
  reporter: progress.Reporter,
  palette: color.Palette,
) -> #(ActionResult, progress.Reporter) {
  let manifest_path = option.unwrap(options.manifest_path, "manifest.toml")
  let manifest_path = manifest.resolve_path(manifest_path)
  let project_root = path.dirname(manifest_path)
  let today = exception.utc_date(timestamp.system_time())
  let reporter = progress.phase(reporter, "Checking for vulnerabilities")
  let outcome = {
    use configuration <- result.try(
      load_policy(options, project_root)
      |> result.map_error(fn(config_error) {
        #(diagnostic(error.from_config_error(config_error)), reporter)
      }),
    )
    use locked <- result.try(
      manifest.load_vulns(manifest_path)
      |> result.map_error(fn(manifest_error) {
        #(diagnostic(error.from_manifest_error(manifest_error)), reporter)
      }),
    )
    use prod_seed <- result.try(
      manifest.resolve_prod_seed(project_root, locked.root_requirements)
      |> result.map_error(error.from_manifest_error)
      |> result.map_error(fn(scope_error) {
        #(diagnostic(scope_error), reporter)
      }),
    )
    let scopes = manifest.sbom_scopes(locked, prod_seed)
    let #(all_pairs, _) = build_purl_pairs(locked)
    use _ <- result.try(
      validate_exception_identities(configuration.exceptions, all_pairs)
      |> result.map_error(fn(review_error) {
        #(diagnostic(review_error), reporter)
      }),
    )
    let active =
      list.filter(locked.entries, fn(entry) {
        options.scope == cli.All
        || scope_for(scopes, entry.name) == manifest.Prod
      })
    let excluded =
      all_pairs
      |> list.filter(fn(pair) {
        options.scope == cli.Prod
        && scope_for(scopes, pair.0.name) == manifest.Dev
      })
      |> list.map(fn(pair) { #(pair.1, "excluded by --scope=prod") })
    let gate =
      run_vuln_check_for_audit(
        active,
        options,
        configuration,
        clients,
        reporter,
        palette,
        today,
      )
    use _ <- result.try(
      gate.status
      |> result.map_error(fn(review_error) {
        #(diagnostic(review_error), gate.reporter)
      }),
    )
    let output =
      gate.report_text
      <> exception.summary(
        configuration.exceptions,
        today,
        exception.NotEvaluated("licence scan disabled"),
        with_excluded_vulns(gate.coverage, excluded),
      )
    Ok(finalize_audit(
      LicenceGateOutcome(
        verdict: LicencesNotEnforced,
        completeness: CheckComplete,
        rows: [],
        coverage: exception.NotEvaluated("licence scan disabled"),
      ),
      VulnGateOutcome(
        ..gate,
        coverage: with_excluded_vulns(gate.coverage, excluded),
      ),
      output,
      "Vulnerability check completed",
    ))
  }
  case outcome {
    Ok(outcome) | Error(outcome) -> outcome
  }
}

fn run_vulns_options(
  options: cli.VulnsOptions,
  clients: Clients,
  reporter: progress.Reporter,
  palette: color.Palette,
) -> #(ActionResult, progress.Reporter) {
  let manifest_path = option.unwrap(options.manifest_path, "manifest.toml")
  let manifest_path = manifest.resolve_path(manifest_path)
  let project_root = path.dirname(manifest_path)
  let today = exception.utc_date(timestamp.system_time())
  let outcome = {
    use config_policy <- result.try(
      config.load(config.LoadOptions(
        config_path: options.config_path,
        project_root: project_root,
        allow_licences: [],
        deny_licences: [],
        vuln_severity: None,
        vuln_block_unknown: None,
        ignore_config: options.ignore_config,
        check: False,
      ))
      |> result.map_error(fn(config_error) {
        #(diagnostic(error.from_config_error(config_error)), reporter)
      }),
    )
    let reporter = progress.phase(reporter, "Checking for vulnerabilities")
    let reporter = progress.detail(reporter, "Loading package manifest")

    use sbom_manifest <- result.try(
      manifest.load_vulns(manifest_path)
      |> result.map_error(fn(manifest_error) {
        #(diagnostic(error.from_manifest_error(manifest_error)), reporter)
      }),
    )
    use prod_seed <- result.try(
      manifest.resolve_prod_seed(project_root, sbom_manifest.root_requirements)
      |> result.map_error(error.from_manifest_error)
      |> result.map_error(fn(scope_error) {
        #(diagnostic(scope_error), reporter)
      }),
    )
    let scopes = manifest.sbom_scopes(sbom_manifest, prod_seed)
    let #(all_purl_pairs, _) = build_purl_pairs(sbom_manifest)
    let active_entries =
      list.filter(sbom_manifest.entries, fn(entry) {
        options.scope == cli.All
        || scope_for(scopes, entry.name) == manifest.Prod
      })
    let #(purl_pairs, purl_errors) =
      build_purl_pairs(
        manifest.SbomManifest(..sbom_manifest, entries: active_entries),
      )
    let excluded =
      all_purl_pairs
      |> list.filter(fn(pair) {
        options.scope == cli.Prod
        && scope_for(scopes, pair.0.name) == manifest.Dev
      })
      |> list.map(fn(pair) { #(pair.1, "excluded by --scope=prod") })
    let purls = list.map(purl_pairs, fn(pair) { pair.1 })

    use _ <- result.try(
      validate_exception_identities(config_policy.exceptions, all_purl_pairs)
      |> result.map_error(fn(review_error) {
        #(diagnostic(review_error), reporter)
      }),
    )
    Ok(case purls {
      [] -> {
        let output =
          format_vulns_output([], purl_errors, scopes, palette)
          <> exception.summary(
            config_policy.exceptions,
            today,
            exception.NotEvaluated("licence scan disabled"),
            exception.Evaluated([], excluded),
          )
        #(report_result(0, output), reporter)
      }
      _ ->
        query_and_report_vulns(
          purls,
          purl_pairs,
          purl_errors,
          scopes,
          clients,
          reporter,
          palette,
          config_policy,
          today,
          excluded,
        )
    })
  }
  case outcome {
    Ok(outcome) | Error(outcome) -> outcome
  }
}

/// Query OSV for `purls`, fetch advisory details, and render the `vulns`
/// report. Batch errors and incomplete workers return a runtime error.
fn query_and_report_vulns(
  purls: List(String),
  purl_pairs: List(PurlPair),
  purl_errors: List(String),
  scopes: dict.Dict(String, manifest.Scope),
  clients: Clients,
  reporter: progress.Reporter,
  palette: color.Palette,
  configuration: config.Policy,
  today: String,
  excluded: List(#(String, String)),
) -> #(ActionResult, progress.Reporter) {
  let reporter =
    progress.detail(
      reporter,
      "Querying OSV.dev for "
        <> int.to_string(list.length(purls))
        <> " packages",
    )
  case clients.osv_batch_fetcher(purls) {
    Error(osv_error) -> {
      let failure = diagnostic(error.from_osv_error(osv_error))
      #(
        Diagnostic(
          RunResult(
            ..failure.result,
            output: failure.result.output
              <> exception.summary(
                configuration.exceptions,
                today,
                exception.NotEvaluated("licence scan disabled"),
                with_excluded_vulns(
                  unavailable_vulns(purl_pairs, "OSV request failed"),
                  excluded,
                ),
              ),
          ),
        ),
        reporter,
      )
    }
    Ok(entries) -> {
      let with_packages = merge_entries_with_packages(entries, purl_pairs)
      let #(rows, reporter) =
        fetch_vuln_details(with_packages, clients.osv_detail_fetcher, reporter)
      use <- bool.lazy_guard(
        when: list.any(rows, fn(row) {
          list.any(row.failures, fn(failure) { failure.runtime_failed })
        }),
        return: fn() {
          #(
            diagnostic(error.RuntimeException(
              rows
              |> list.flat_map(fn(row) { row.failures })
              |> format_vuln_detail_failures_output
              |> string.trim,
            )),
            reporter,
          )
        },
      )
      case review_vuln_rows(rows, configuration.exceptions, today) {
        Error(review_error) -> #(diagnostic(review_error), reporter)
        Ok(rows) -> {
          let output =
            format_vulns_output(rows, purl_errors, scopes, palette)
            <> exception.summary(
              configuration.exceptions,
              today,
              exception.NotEvaluated("licence scan disabled"),
              with_excluded_vulns(vuln_row_coverage(rows), excluded),
            )
          #(report_result(0, output), reporter)
        }
      }
    }
  }
}

fn with_excluded_vulns(
  coverage: exception.Coverage,
  excluded: List(#(String, String)),
) -> exception.Coverage {
  case coverage {
    exception.NotEvaluated(_) -> coverage
    exception.Evaluated(matched, unavailable) ->
      exception.Evaluated(matched, list.append(unavailable, excluded))
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
  VulnRow(
    package: manifest.SbomEntry,
    vulnerabilities: List(osv.Vulnerability),
    decisions: List(exception.Decision),
    failures: List(DetailFailure),
  )
}

type VulnOccurrence {
  VulnOccurrence(
    package: manifest.SbomEntry,
    vulnerability: osv.Vulnerability,
    decision: exception.Decision,
  )
}

/// An advisory whose detail lookup failed, with a human-readable reason.
/// Reports tolerate service errors with a placeholder and warning. Incomplete
/// workers fail the command; gates also fail when service errors hide severity.
type DetailFailure {
  DetailFailure(id: String, reason: String, runtime_failed: Bool)
}

type CheckCompleteness {
  CheckComplete
  CheckIncomplete
}

type LicenceVerdict {
  LicencesNotEnforced
  LicencesPassed
  LicencesBlocked
}

type LicenceGateOutcome {
  LicenceGateOutcome(
    verdict: LicenceVerdict,
    completeness: CheckCompleteness,
    rows: List(report.Row),
    coverage: exception.Coverage,
  )
}

type VulnVerdict {
  NoBlockingAdvisories
  BlockingKnownSeverity
  BlockingUnknownSeverity
}

type VulnGateStatus {
  GateNotEvaluated
  GateUnavailable(error.Error)
  GateEvaluated(verdict: VulnVerdict, completeness: CheckCompleteness)
}

/// Findings and coverage are retained independently of the final exit status.
type VulnGateOutcome {
  VulnGateOutcome(
    status: Result(VulnGateStatus, error.Error),
    report_text: String,
    queries: List(VulnPair),
    occurrences: List(VulnOccurrence),
    detail_failures: List(DetailFailure),
    unsupported_packages: List(String),
    coverage: exception.Coverage,
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
      // Skip local and other sources with no supported OSV identity.
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
) -> #(List(VulnRow), progress.Reporter) {
  let unique_ids = pending |> list.flat_map(fn(pair) { pair.1 }) |> list.unique
  let reporter =
    list.fold(pending, reporter, fn(reporter, pair) {
      case pair.1 {
        [] -> reporter
        [_, ..] ->
          progress.detail(reporter, "Fetching OSV details for " <> pair.0.name)
      }
    })
  let #(vulns, failures, reporter) =
    fetch_vulnerabilities(unique_ids, detail_fetcher, reporter)
  let details_by_id = dict.from_list(list.zip(unique_ids, vulns))
  let failures_by_id =
    dict.from_list(list.map(failures, fn(failure) { #(failure.id, failure) }))
  let rows =
    list.map(pending, fn(pair) {
      let #(package, ids) = pair
      VulnRow(
        package: package,
        vulnerabilities: list.filter_map(ids, dict.get(details_by_id, _)),
        decisions: [],
        failures: list.filter_map(ids, dict.get(failures_by_id, _)),
      )
    })
  #(rows, reporter)
}

fn fetch_vulnerabilities(
  ids: List(String),
  detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  reporter: progress.Reporter,
) -> #(List(osv.Vulnerability), List(DetailFailure), progress.Reporter) {
  let outcomes = network.fetch(ids, fn(id) { id }, detail_fetcher)
  let #(vulns, failures, reporter) =
    list.fold(list.zip(ids, outcomes), #([], [], reporter), fn(acc, pair) {
      let #(vulns, failures, reporter) = acc
      let #(id, outcome) = pair
      let outcome = case outcome {
        Ok(fetched) ->
          result.map_error(fetched, fn(err) {
            #(error.message(error.from_osv_error(err)), False)
          })
        Error(reason) -> Error(#(reason, True))
      }
      case outcome {
        Ok(vuln) -> #([vuln, ..vulns], failures, reporter)
        Error(#(reason, runtime_failed)) -> {
          let reporter =
            progress.defer_warn(
              reporter,
              "Failed to fetch OSV details for " <> id <> ": " <> reason,
            )
          let failure =
            DetailFailure(
              id: id,
              reason: reason,
              runtime_failed: runtime_failed,
            )
          #(
            [placeholder_vulnerability(id), ..vulns],
            [failure, ..failures],
            reporter,
          )
        }
      }
    })
  #(list.reverse(vulns), list.reverse(failures), reporter)
}

fn placeholder_vulnerability(id: String) -> osv.Vulnerability {
  // Fall back to bare ID with unknown severity so the report still shows the
  // user something actionable when an individual detail fetch fails.
  osv.Vulnerability(
    aliases: [],
    id: id,
    summary: "(details unavailable)",
    severity: osv.UnknownSeverity,
    scores: [],
    affected: [],
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
  let excepted_count =
    rows
    |> list.flat_map(fn(row) { row.decisions })
    |> list.filter(exception.accepted)
    |> list.length

  let summary =
    "Checked "
    <> int.to_string(list.length(rows))
    <> " packages: "
    <> int.to_string(list.length(affected))
    <> " with vulnerabilities, "
    <> int.to_string(clean_count)
    <> " clean."
    <> case excepted_count {
      0 -> ""
      count -> " " <> int.to_string(count) <> " excepted finding(s)."
    }
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
    list.map2(row.vulnerabilities, row.decisions, fn(vuln, decision) {
      let severity_text = color.severity(palette, vuln.severity)
      "  "
      <> severity_text
      <> "  "
      <> vuln.id
      <> case vuln.summary {
        "" -> ""
        s -> "  " <> color.dim(palette, truncate(s, 80))
      }
      <> case exception.decision_text(decision) {
        "" -> ""
        text -> " [" <> text <> "]"
      }
    })
    |> string.join(with: "\n")
  pkg_line <> "\n" <> vuln_lines
}

fn truncate(s: String, max: Int) -> String {
  use <- bool.guard(when: string.length(s) <= max, return: s)
  string.slice(s, 0, max - 1) <> "…"
}

// --- Vulnerability gate for selected checks -----------------------------

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
  let severity = osv.parse_severity_label(raw)
  case severity {
    osv.NoSeverity | osv.UnknownSeverity -> osv.High
    osv.Low | osv.Medium | osv.High | osv.Critical -> severity
  }
}

fn run_vuln_check_for_audit(
  packages: List(manifest.SbomEntry),
  options: cli.Options,
  configuration: config.Policy,
  clients: Clients,
  reporter: progress.Reporter,
  palette: color.Palette,
  today: String,
) -> VulnGateOutcome {
  let #(purl_pairs, unsupported_packages) =
    build_purl_pairs(
      manifest.SbomManifest(entries: packages, root_requirements: []),
    )
  let purls = list.map(purl_pairs, fn(pair) { pair.1 })

  case validate_exception_identities(configuration.exceptions, purl_pairs) {
    Error(review_error) ->
      VulnGateOutcome(
        status: Error(review_error),
        report_text: "",
        queries: [],
        occurrences: [],
        detail_failures: [],
        unsupported_packages: unsupported_packages,
        coverage: exception.NotEvaluated("ambiguous package identity"),
        reporter: reporter,
      )
    Ok(Nil) -> {
      case purls {
        [] ->
          VulnGateOutcome(
            status: Ok(GateEvaluated(NoBlockingAdvisories, CheckComplete)),
            report_text: format_unsupported_sources(unsupported_packages),
            queries: [],
            occurrences: [],
            detail_failures: [],
            unsupported_packages: unsupported_packages,
            coverage: exception.Evaluated([], []),
            reporter: reporter,
          )
        _ ->
          query_vuln_gate(
            purls,
            purl_pairs,
            unsupported_packages,
            options,
            configuration,
            clients,
            reporter,
            palette,
            today,
          )
      }
    }
  }
}

/// Query OSV and evaluate the vulnerability gate.
fn query_vuln_gate(
  purls: List(String),
  purl_pairs: List(PurlPair),
  unsupported_packages: List(String),
  options: cli.Options,
  configuration: config.Policy,
  clients: Clients,
  reporter: progress.Reporter,
  palette: color.Palette,
  today: String,
) -> VulnGateOutcome {
  let reporter =
    progress.detail(
      reporter,
      "Querying OSV.dev for "
        <> int.to_string(list.length(purls))
        <> " packages",
    )
  case clients.osv_batch_fetcher(purls) {
    Error(osv_error) -> {
      let reporter =
        progress.defer_error(
          reporter,
          "Vulnerability check failed: "
            <> error.message(error.from_osv_error(osv_error)),
        )
      VulnGateOutcome(
        status: Ok(GateUnavailable(error.from_osv_error(osv_error))),
        report_text: format_unsupported_sources(unsupported_packages),
        queries: [],
        occurrences: [],
        detail_failures: [],
        unsupported_packages: unsupported_packages,
        coverage: unavailable_vulns(purl_pairs, "OSV request failed"),
        reporter: reporter,
      )
    }
    Ok(entries) ->
      evaluate_vuln_gate(
        entries,
        purl_pairs,
        unsupported_packages,
        options,
        configuration,
        clients,
        reporter,
        palette,
        today,
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
  options: cli.Options,
  configuration: config.Policy,
  clients: Clients,
  reporter: progress.Reporter,
  palette: color.Palette,
  today: String,
) -> VulnGateOutcome {
  let threshold =
    resolve_vuln_threshold(options.vuln_severity, configuration.vuln_severity)
  let block_unknown = configuration.vuln_block_unknown
  let unique_ids = unique_vuln_ids(entries)
  let #(vulns, detail_failures, reporter) =
    fetch_vulnerabilities(unique_ids, clients.osv_detail_fetcher, reporter)
  let reporter = case detail_failures {
    [] -> reporter
    [_, ..] ->
      progress.defer_error(
        reporter,
        format_vuln_detail_failures_output(detail_failures)
          |> string.trim,
      )
  }
  // Failed lookups remain incomplete, but do not discard available findings.
  let available_entries =
    list.map(entries, fn(entry) {
      osv.BatchEntry(
        ..entry,
        vuln_ids: list.filter(entry.vuln_ids, fn(id) {
          !list.any(detail_failures, fn(failure) { failure.id == id })
        }),
      )
    })
  case
    review_vuln_occurrences(
      available_entries,
      purl_pairs,
      list.zip(unique_ids, vulns),
      configuration.exceptions,
      today,
    )
  {
    Error(review_error) ->
      VulnGateOutcome(
        status: Error(review_error),
        report_text: "",
        queries: merge_entries_with_packages(entries, purl_pairs),
        occurrences: [],
        detail_failures: detail_failures,
        unsupported_packages: unsupported_packages,
        coverage: exception.NotEvaluated("ambiguous advisory exceptions"),
        reporter: reporter,
      )
    Ok(occurrences) -> {
      let triggering =
        occurrences
        |> list.filter(fn(occurrence) {
          !exception.accepted(occurrence.decision)
          && advisory_blocks(
            occurrence.vulnerability.severity,
            threshold,
            block_unknown,
          )
        })
        |> list.map(fn(occurrence) { occurrence.vulnerability })
        |> list.unique
      let verdict = case triggering {
        [] -> NoBlockingAdvisories
        [_, ..] ->
          case
            list.any(triggering, fn(vuln) {
              vuln.severity == osv.UnknownSeverity
            })
          {
            True -> BlockingUnknownSeverity
            False -> BlockingKnownSeverity
          }
      }
      let report_text = case occurrences == [] && detail_failures != [] {
        True -> format_unsupported_sources(unsupported_packages)
        False ->
          format_vuln_gate_output(
            occurrences,
            triggering,
            threshold,
            block_unknown,
            configuration.exceptions != [],
            unsupported_packages,
            palette,
          )
      }
      let unavailable =
        purl_pairs
        |> list.zip(entries)
        |> list.filter_map(fn(pair) {
          let #(package, entry) = pair
          case
            list.any(entry.vuln_ids, fn(id) {
              list.any(detail_failures, fn(failure) { failure.id == id })
            })
          {
            True -> Ok(#(package.1, "OSV advisory details unavailable"))
            False -> Error(Nil)
          }
        })
      VulnGateOutcome(
        status: Ok(
          GateEvaluated(verdict, case detail_failures {
            [] -> CheckComplete
            [_, ..] -> CheckIncomplete
          }),
        ),
        report_text: report_text,
        queries: merge_entries_with_packages(entries, purl_pairs),
        occurrences: occurrences,
        detail_failures: detail_failures,
        unsupported_packages: unsupported_packages,
        coverage: exception.Evaluated(
          occurrences |> list.map(fn(o) { o.decision }) |> exception.matched,
          unavailable,
        ),
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

fn validate_exception_identities(
  exceptions: List(exception.Exception),
  pairs: List(PurlPair),
) -> Result(Nil, error.Error) {
  exception.validate_identities(
    exceptions,
    list.map(pairs, fn(pair) { pair.1 }),
  )
  |> result.map_error(error.from_exception_error)
}

fn unavailable_vulns(
  pairs: List(PurlPair),
  reason: String,
) -> exception.Coverage {
  exception.Evaluated([], list.map(pairs, fn(pair) { #(pair.1, reason) }))
}

fn review_vuln_rows(
  rows: List(VulnRow),
  exceptions: List(exception.Exception),
  today: String,
) -> Result(List(VulnRow), error.Error) {
  list.try_map(rows, fn(row) {
    use purl <- result.try(sbom.purl_for(row.package))
    let vulnerabilities =
      list.map(row.vulnerabilities, osv.for_package(_, purl))
    use decisions <- result.try(
      list.try_map(vulnerabilities, fn(vuln) {
        case list.any(row.failures, fn(failure) { failure.id == vuln.id }) {
          True -> Ok(exception.Unaccepted)
          False ->
            exception.decide(
              exceptions,
              purl,
              exception.Advisory(vuln.id),
              vuln.aliases,
              today,
            )
            |> result.map_error(error.from_exception_error)
        }
      }),
    )
    Ok(VulnRow(..row, vulnerabilities:, decisions:))
  })
}

fn vuln_row_coverage(rows: List(VulnRow)) -> exception.Coverage {
  let matched =
    rows |> list.flat_map(fn(row) { row.decisions }) |> exception.matched
  let unavailable =
    rows
    |> list.filter_map(fn(row) {
      case row.failures {
        [] -> Error(Nil)
        _ ->
          sbom.purl_for(row.package)
          |> result.map(fn(purl) { #(purl, "OSV advisory details unavailable") })
          |> result.replace_error(Nil)
      }
    })
  exception.Evaluated(matched, unavailable)
}

fn review_vuln_occurrences(
  entries: List(osv.BatchEntry),
  pairs: List(PurlPair),
  details: List(#(String, osv.Vulnerability)),
  exceptions: List(exception.Exception),
  today: String,
) -> Result(List(VulnOccurrence), error.Error) {
  use groups <- result.try(
    list.try_map(list.zip(pairs, entries), fn(pair) {
      let #(#(package, purl), entry) = pair
      list.try_map(entry.vuln_ids, fn(id) {
        use vuln <- result.try(
          list.key_find(details, id)
          |> result.replace_error(error.Config(
            "Missing fetched advisory " <> id,
          )),
        )
        let vuln = osv.for_package(vuln, purl)
        use decision <- result.try(
          exception.decide(
            exceptions,
            purl,
            exception.Advisory(vuln.id),
            vuln.aliases,
            today,
          )
          |> result.map_error(error.from_exception_error),
        )
        Ok(VulnOccurrence(package:, vulnerability: vuln, decision:))
      })
    }),
  )
  Ok(list.flatten(groups) |> list.unique)
}

fn format_vuln_gate_output(
  occurrences: List(VulnOccurrence),
  triggering: List(osv.Vulnerability),
  threshold: osv.Severity,
  block_unknown: Bool,
  reviews_enabled: Bool,
  unsupported: List(String),
  palette: color.Palette,
) -> String {
  use <- bool.guard(
    when: occurrences == [],
    return: "\nNo known vulnerabilities reported by OSV.dev.\n"
      <> format_unsupported_sources(unsupported),
  )
  let body =
    occurrences
    |> list.map(fn(occurrence) {
      let vuln = occurrence.vulnerability
      let marker = case exception.accepted(occurrence.decision) {
        True -> color.yellow(palette, "~")
        False ->
          case advisory_blocks(vuln.severity, threshold, block_unknown) {
            True -> color.red(palette, "✗")
            False -> color.dim(palette, "·")
          }
      }
      marker
      <> "  "
      <> color.severity(palette, vuln.severity)
      <> "  "
      <> vuln.id
      <> "  "
      <> occurrence.package.name
      <> "@"
      <> occurrence.package.version
      <> case exception.decision_text(occurrence.decision) {
        "" -> ""
        text -> " [" <> text <> "]"
      }
    })
    |> string.join("\n")
  let excepted =
    occurrences
    |> list.filter(fn(o) { exception.accepted(o.decision) })
    |> list.length
  let all_vulns =
    occurrences
    |> list.map(fn(occurrence) { occurrence.vulnerability.id })
    |> list.unique
  let trigger_count =
    triggering
    |> list.map(fn(vuln) { vuln.id })
    |> list.unique
    |> list.length
    |> int.to_string
  let summary = case reviews_enabled {
    True ->
      trigger_count
      <> " blocking advisory/advisories; "
      <> int.to_string(excepted)
      <> " excepted finding(s) of "
      <> int.to_string(list.length(occurrences))
      <> " package/advisory finding(s)."
    False -> {
      let total_count = int.to_string(list.length(all_vulns))
      case
        list.any(triggering, fn(vuln) { vuln.severity == osv.UnknownSeverity })
      {
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
    }
  }
  "\n"
  <> color.boxed(
    palette,
    "Vulnerability check · threshold: "
      <> osv.severity_to_string(threshold)
      <> case block_unknown {
      True -> " · unknown: block"
      False -> ""
    },
    body,
  )
  <> "\n"
  <> summary
  <> "\n"
  <> format_unsupported_sources(unsupported)
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
    osv.NoSeverity -> False
    osv.UnknownSeverity -> block_unknown
    osv.Low | osv.Medium | osv.High | osv.Critical ->
      osv.severity_rank(actual) >= osv.severity_rank(threshold)
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
