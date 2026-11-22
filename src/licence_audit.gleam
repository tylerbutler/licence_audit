import gleam/bool
import gleam/dict
import gleam/int
import gleam/io
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import licence_audit/audit_command.{
  type LicenceGateOutcome, LicenceGateOutcome, LicencesBlocked,
  LicencesNotEnforced, LicencesPassed,
}
import licence_audit/cli
import licence_audit/color
import licence_audit/config
import licence_audit/error
import licence_audit/exception
import licence_audit/hex
import licence_audit/httpc_adaptive
import licence_audit/internal/vendor/glint
import licence_audit/json_report
import licence_audit/manifest
import licence_audit/network
import licence_audit/notice
import licence_audit/notice_command
import licence_audit/osv
import licence_audit/path
import licence_audit/progress
import licence_audit/report
import licence_audit/sbom
import licence_audit/sbom_command
import licence_audit/update as update_cmd
import licence_audit/version
import licence_audit/vulnerability_command.{
  type VulnGateOutcome, type VulnOccurrence, type VulnRow,
  BlockingKnownSeverity, BlockingUnknownSeverity, CheckComplete, CheckIncomplete,
  GateEvaluated, GateNotEvaluated, GateUnavailable, NoBlockingAdvisories,
}
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

pub fn main() -> Nil {
  case
    run_cli(fn() {
      let args = arguments()
      case run_cli(fn() { main_action(args) }) {
        Ok(Nil) -> Nil
        Error(runtime_error) -> {
          let result = raw_failure(args, runtime_error)
          print_action_result(result)
          halt(result.result.exit_code)
        }
      }
    })
  {
    Ok(Nil) -> Nil
    Error(runtime_error) -> {
      let result = diagnostic(runtime_error)
      print_action_result(result)
      halt(result.result.exit_code)
    }
  }
}

fn main_action(args: List(String)) -> Nil {
  case
    cli.execute(
      args,
      tty.detect_color_level(tty.Stdout),
      tty.detect_color_level(tty.Stderr),
    )
  {
    Error(message) -> {
      let result = raw_failure(args, error.Usage(message))
      print_action_result(result)
      halt(result.result.exit_code)
    }
    Ok(glint.Help(help)) -> io.println(help)
    Ok(glint.Out(action)) ->
      case action {
        cli.ShowVersion | cli.InvalidUsage(_) -> handle_action(action)
        _ ->
          case start_runtime() {
            Ok(Nil) -> handle_action(action)
            Error(startup_error) -> {
              let result = raw_failure(args, startup_error)
              let exit_code = result.result.exit_code
              print_action_result(result)
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
  let exit_code = result.result.exit_code
  // Flush before the machine document so a logging failure cannot append one.
  case action_format(action) {
    cli.Json -> {
      let _ = progress.flush(apply_http_warning(reporter))
      print_action_result(result)
    }
    cli.Text -> {
      print_action_result(result)
      let _ = progress.flush(apply_http_warning(reporter))
      Nil
    }
  }
  halt(exit_code)
}

fn print_action_result(result: ActionResult) -> Nil {
  case result {
    Diagnostic(_) -> {
      io.print_error(result.result.output)
    }
    Report(_) -> {
      io.print(result.result.output)
    }
  }
}

fn action_format(action: cli.CliAction) -> cli.ReportFormat {
  case action {
    cli.RunReport(options) -> options.format
    cli.RunAudit(options) -> options.format
    cli.RunVulns(options) -> options.format
    cli.UpdateConfig(_)
    | cli.RunSbom(_)
    | cli.RunNotices(_)
    | cli.ShowVersion
    | cli.InvalidUsage(_) -> cli.Text
  }
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
    case cli.recognized_json_command(args) {
      Some(_) -> cli.execute(args, tty.NoColor, tty.NoColor)
      None -> glint.execute(cli.app(), cli.normalize_args(args))
    }
  {
    Ok(glint.Help(help)) -> #(report_result(0, help <> "\n"), reporter)
    Ok(glint.Out(action)) -> {
      let action = case bypass_cache {
        True -> without_cache(action)
        False -> action
      }
      execute_action(action, clients, reporter, color.for_enabled(False))
    }
    Error(message) -> #(raw_failure(args, error.Usage(message)), reporter)
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
            format: options.format,
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
    vulnerability_command.fetch_vulnerabilities(ids, detail_fetcher, reporter)
  case list.any(failures, fn(failure) { failure.runtime_failed }) {
    True -> #(
      Error(error.RuntimeException(
        vulnerability_command.format_vuln_detail_failures_output(failures)
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
  let #(outcome, reporter) =
    audit_command.run(
      options,
      clients.notice_clients,
      clients.osv_batch_fetcher,
      clients.osv_detail_fetcher,
      reporter,
    )
  case outcome {
    Error(failure) -> #(options_failure(options, failure), reporter)
    Ok(outcome) -> render_audit(options, outcome, palette)
  }
}

fn render_audit(
  options: cli.Options,
  outcome: audit_command.Outcome,
  palette: color.Palette,
) -> #(ActionResult, progress.Reporter) {
  let licences = outcome.licences
  let gate = outcome.vulnerabilities
  let reviewed = case outcome.review_failure {
    None -> Ok(Nil)
    Some(failure) ->
      Error(#(
          case options.format {
            cli.Text -> diagnostic(failure)
            cli.Json ->
              json_result(json_report.Document(
                ..empty_document(
                  case options.check {
                    True -> json_report.Check
                    False -> json_report.Report
                  },
                  checks_requested(options.checks),
                  failure,
                ),
                licences: Some(licence_json_result(licences)),
                exceptions: outcome.configuration.exceptions,
                today: outcome.today,
              ))
          },
          gate.reporter,
      ))
  }
  let rendered = {
    use _ <- result.try(reviewed)
    use _ <- result.try(
      case options.format {
        cli.Json -> Ok(Nil)
        cli.Text -> result.map(gate.status, fn(_) { Nil })
      }
      |> result.map_error(fn(failure) {
        #(diagnostic(failure), gate.reporter)
      }),
    )
    let policy_failed = licences.verdict == LicencesBlocked
    let display_rows = case options.check && policy_failed {
      True -> report.filter_failing_trees(licences.rows)
      False -> licences.rows
    }
    let skipped_names =
      licences.rows
      |> list.filter_map(fn(row) {
        case row.status {
          report.Skipped(_) -> Ok(row.package)
          _ -> Error(Nil)
        }
      })
    let summary = report.Summary(skipped_names)
    let output =
      report.format_with_counts(
        display_rows,
        summary,
        licences.counts,
        outcome.mode,
        palette,
      )
      <> case options.check {
        True -> report.format_findings(licences.rows, palette)
        False -> ""
      }
      <> render_vuln_gate(gate, palette)
      <> exception.summary(
        outcome.configuration.exceptions,
        outcome.today,
        licences.coverage,
        gate.coverage,
      )
      <> case
        options.check
        && licences.completeness == CheckComplete
        && case gate.status {
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
    let #(result, reporter) = case options.format {
      cli.Text ->
        finalize_audit(licences, gate, output, "Licence audit completed")
      cli.Json ->
        finalize_json_audit(
          options,
          Some(licences),
          gate,
          outcome.packages,
          outcome.configuration,
          outcome.today,
        )
    }
    Ok(#(
      result,
      case outcome.cache_warning {
        Some(message) -> progress.defer_warn(reporter, message)
        None -> reporter
      },
    ))
  }
  case rendered {
    Ok(result) | Error(result) -> result
  }
}

fn run_vulnerability_check(
  options: cli.Options,
  clients: Clients,
  reporter: progress.Reporter,
  palette: color.Palette,
) -> #(ActionResult, progress.Reporter) {
  let #(outcome, reporter) =
    vulnerability_command.run_check(
      options,
      clients.osv_batch_fetcher,
      clients.osv_detail_fetcher,
      reporter,
    )
  case outcome {
    Error(failure) -> #(options_failure(options, failure), reporter)
    Ok(outcome) -> {
      let gate = outcome.gate
      case options.format {
        cli.Json ->
          finalize_json_audit(
            options,
            None,
            gate,
            outcome.packages,
            outcome.configuration,
            outcome.today,
          )
        cli.Text ->
          case gate.status {
            Error(failure) -> #(diagnostic(failure), gate.reporter)
            Ok(_) ->
              finalize_audit(
                LicenceGateOutcome(
                  verdict: LicencesNotEnforced,
                  completeness: CheckComplete,
                  rows: [],
                  counts: report.counts([], report.Summary([])),
                  coverage: exception.NotEvaluated("licence scan disabled"),
                ),
                gate,
                render_vuln_gate(gate, palette)
                  <> exception.summary(
                    outcome.configuration.exceptions,
                    outcome.today,
                    exception.NotEvaluated("licence scan disabled"),
                    gate.coverage,
                  ),
                "Vulnerability check completed",
              )
          }
      }
    }
  }
}

fn run_vulns_options(
  options: cli.VulnsOptions,
  clients: Clients,
  reporter: progress.Reporter,
  palette: color.Palette,
) -> #(ActionResult, progress.Reporter) {
  let #(outcome, reporter) =
    vulnerability_command.run(
      options,
      clients.osv_batch_fetcher,
      clients.osv_detail_fetcher,
      reporter,
    )
  case outcome {
    Error(failure) -> #(vulns_failure(options, failure), reporter)
    Ok(scan) -> render_vulns(options.format, scan, reporter, palette)
  }
}

fn render_vulns(
  format: cli.ReportFormat,
  scan: vulnerability_command.ScanOutcome,
  reporter: progress.Reporter,
  palette: color.Palette,
) -> #(ActionResult, progress.Reporter) {
  let summary =
    exception.summary(
      scan.configuration.exceptions,
      scan.today,
      exception.NotEvaluated("licence scan disabled"),
      scan.coverage,
    )
  case format {
    cli.Json -> {
      let failure = case scan.status {
        vulnerability_command.EmptyScan -> error.Success
        vulnerability_command.BatchFailed(failure) -> failure
        vulnerability_command.DetailsFetched(Error(failure)) -> failure
        vulnerability_command.DetailsFetched(Ok(Nil)) ->
          case
            list.find(
              scan.rows |> list.flat_map(fn(row) { row.failures }),
              fn(failure) { failure.runtime_failed },
            )
          {
            Ok(failure) -> failure.failure
            Error(_) -> error.Success
          }
      }
      let complete =
        failure == error.Success
        && list.all(scan.rows, fn(row) { row.failures == [] })
      #(
        json_vulns_report(
          scan.rows,
          scan.packages,
          scan.skipped_packages,
          scan.queried_packages,
          scan.coverage,
          scan.configuration,
          scan.today,
          complete,
          failure,
        ),
        case failure {
          error.Success -> reporter
          _ -> progress.defer_error(reporter, error.message(failure))
        },
      )
    }
    cli.Text ->
      case scan.status {
        vulnerability_command.BatchFailed(failure) -> {
          let result = diagnostic(failure)
          #(
            Diagnostic(RunResult(..result.result, output: result.result.output <> summary)),
            reporter,
          )
        }
        vulnerability_command.EmptyScan
        | vulnerability_command.DetailsFetched(_) -> {
          let failures = scan.rows |> list.flat_map(fn(row) { row.failures })
          case list.any(failures, fn(failure) { failure.runtime_failed }) {
            True -> #(
              diagnostic(error.RuntimeException(
                vulnerability_command.format_vuln_detail_failures_output(failures)
                |> string.trim,
              )),
              reporter,
            )
            False ->
              case scan.status {
                vulnerability_command.DetailsFetched(Error(failure)) ->
                  #(diagnostic(failure), reporter)
                vulnerability_command.EmptyScan
                | vulnerability_command.DetailsFetched(Ok(Nil)) ->
                  #(
                    report_result(
                      0,
                      format_vulns_output(scan.rows, scan.skipped_packages, scan.scopes, palette) <> summary,
                    ),
                    reporter,
                  )
                vulnerability_command.BatchFailed(failure) ->
                  #(diagnostic(failure), reporter)
              }
          }
        }
      }
  }
}

fn render_vuln_gate(
  gate: VulnGateOutcome,
  palette: color.Palette,
) -> String {
  case gate.report {
    vulnerability_command.NoGateReport -> ""
    vulnerability_command.SkippedSourcesOnly ->
      format_unsupported_sources(gate.unsupported_packages)
    vulnerability_command.Findings(threshold, block_unknown, reviews_enabled) -> {
      let triggering =
        gate.occurrences
        |> list.filter(fn(occurrence) { occurrence.blocking == Some(True) })
        |> list.map(fn(occurrence) { occurrence.vulnerability })
        |> list.unique
      format_vuln_gate_output(
        gate.occurrences,
        triggering,
        threshold,
        block_unknown,
        reviews_enabled,
        gate.unsupported_packages,
        palette,
      )
    }
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

fn diagnostic(audit_error: error.Error) -> ActionResult {
  Diagnostic(RunResult(
    error.exit_code(audit_error),
    "Error: " <> error.message(audit_error) <> "\n",
  ))
}

fn json_result(document: json_report.Document) -> ActionResult {
  report_result(
    error.exit_code(document.outcome),
    json_report.to_string(document) <> "\n",
  )
}

fn checks_requested(checks: cli.Checks) -> List(json_report.CheckKind) {
  case checks {
    cli.Licences -> [json_report.Licences]
    cli.Vulnerabilities -> [json_report.Vulnerabilities]
    cli.AllChecks -> [json_report.Licences, json_report.Vulnerabilities]
  }
}

fn empty_document(
  command: json_report.Command,
  checks: List(json_report.CheckKind),
  failure: error.Error,
) -> json_report.Document {
  json_report.Document(
    command: command,
    checks_requested: checks,
    licences: None,
    vulnerabilities: None,
    exceptions: [],
    today: "",
    gate_verdict: case command {
      json_report.Check -> json_report.Undetermined
      json_report.Report | json_report.Vulns -> json_report.NotEnforced
    },
    complete: False,
    outcome: failure,
  )
}

fn raw_failure(args: List(String), failure: error.Error) -> ActionResult {
  case cli.recognized_json_command(args) {
    None ->
      case failure {
        error.Usage(message) -> Diagnostic(RunResult(2, message <> "\n"))
        _ -> diagnostic(failure)
      }
    Some(command) -> {
      let command = case command {
        "check" -> json_report.Check
        "vulns" -> json_report.Vulns
        _ -> json_report.Report
      }
      let checks = case cli.recognized_checks(args) {
        None -> []
        Some(checks) -> checks_requested(checks)
      }
      json_result(empty_document(command, checks, failure))
    }
  }
}

fn options_failure(options: cli.Options, failure: error.Error) -> ActionResult {
  case options.format {
    cli.Text -> diagnostic(failure)
    cli.Json ->
      json_result(empty_document(
        case options.check {
          True -> json_report.Check
          False -> json_report.Report
        },
        checks_requested(options.checks),
        failure,
      ))
  }
}

fn vulns_failure(
  options: cli.VulnsOptions,
  failure: error.Error,
) -> ActionResult {
  case options.format {
    cli.Text -> diagnostic(failure)
    cli.Json ->
      json_result(empty_document(
        json_report.Vulns,
        [json_report.Vulnerabilities],
        failure,
      ))
  }
}

fn licence_json_result(
  outcome: LicenceGateOutcome,
) -> json_report.LicenceResult {
  let skipped =
    outcome.rows
    |> list.filter_map(fn(row) {
      case row.status {
        report.Skipped(source) ->
          Ok(json_report.SkippedSource(row.package, source))
        report.NotChecked
        | report.Checked(_)
        | report.Reviewed(_)
        | report.Failed(_) -> Error(Nil)
      }
    })
  json_report.LicenceResult(
    rows: outcome.rows,
    counts: outcome.counts,
    skipped_sources: skipped,
    coverage: outcome.coverage,
    complete: outcome.completeness == CheckComplete,
  )
}

fn skipped_vulnerability_sources(
  packages: List(manifest.SbomEntry),
  skipped_names: List(String),
) -> List(json_report.SkippedSource) {
  packages
  |> list.filter(fn(package) { list.contains(skipped_names, package.name) })
  |> list.map(fn(package) {
    let source = case package.provenance {
      manifest.HexProvenance(..) -> "hex"
      manifest.GitProvenance(..) -> "git"
      manifest.PathProvenance(..) -> "path"
      manifest.UnknownProvenance(source) -> source
    }
    json_report.SkippedSource(package.name, source)
  })
}

fn vulnerability_gate_json(
  gate: VulnGateOutcome,
  packages: List(manifest.SbomEntry),
) -> Result(json_report.VulnerabilityResult, error.Error) {
  use rows <- result.try(
    list.try_map(gate.occurrences, fn(occurrence) {
      use purl <- result.try(sbom.purl_for(occurrence.package))
      Ok(json_report.VulnerabilityRow(
        package: occurrence.package.name,
        version: occurrence.package.version,
        purl: purl,
        result: json_report.Available(
          occurrence.vulnerability,
          occurrence.decision,
          occurrence.blocking,
        ),
      ))
    }),
  )
  use remaining <- result.try(
    list.try_map(gate.queries, fn(query) {
      use purl <- result.try(sbom.purl_for(query.0))
      list.try_map(query.1, fn(id) {
        case list.find(gate.detail_failures, fn(failure) { failure.id == id }) {
          Ok(failure) ->
            Ok(
              Some(json_report.VulnerabilityRow(
                package: query.0.name,
                version: query.0.version,
                purl: purl,
                result: json_report.Unavailable(id, failure.failure),
              )),
            )
          Error(_) ->
            case gate.status {
              Ok(_) -> Ok(None)
              Error(failure) -> {
                use advisory <- result.try(
                  list.key_find(gate.details, id)
                  |> result.replace_error(error.Decode(
                    "Missing fetched advisory " <> id,
                  )),
                )
                Ok(
                  Some(json_report.VulnerabilityRow(
                    package: query.0.name,
                    version: query.0.version,
                    purl: purl,
                    result: json_report.Unreviewed(
                      osv.for_package(advisory, purl),
                      failure,
                    ),
                  )),
                )
              }
            }
        }
      })
    }),
  )
  Ok(
    json_report.VulnerabilityResult(
      rows: list.append(
        rows,
        remaining
          |> list.flatten
          |> list.filter_map(fn(row) { option.to_result(row, Nil) }),
      ),
      queried_packages: list.length(gate.queries),
      skipped_sources: skipped_vulnerability_sources(
        packages,
        gate.unsupported_packages,
      ),
      coverage: gate.coverage,
      complete: case gate.status {
        Ok(GateEvaluated(_, CheckComplete)) -> True
        Ok(GateEvaluated(_, CheckIncomplete))
        | Ok(GateUnavailable(_))
        | Ok(GateNotEvaluated)
        | Error(_) -> False
      },
    ),
  )
}

fn gate_failure(
  licences: Option(LicenceGateOutcome),
  gate: VulnGateOutcome,
) -> error.Error {
  case gate.status {
    Error(failure) | Ok(GateUnavailable(failure)) -> failure
    Ok(GateNotEvaluated) | Ok(GateEvaluated(_, _)) ->
      case licences {
        Some(LicenceGateOutcome(completeness: CheckIncomplete, ..)) ->
          error.Hex("Package licence metadata unavailable")
        None | Some(LicenceGateOutcome(completeness: CheckComplete, ..)) ->
          case gate.detail_failures {
            [failure, ..] -> failure.failure
            [] ->
              case json_gate_verdict(licences, gate) {
                json_report.Failed -> error.AuditFailed
                json_report.Undetermined ->
                  error.Osv("Vulnerability check incomplete")
                json_report.NotEnforced | json_report.Passed -> error.Success
              }
          }
      }
  }
}

fn json_gate_verdict(
  licences: Option(LicenceGateOutcome),
  gate: VulnGateOutcome,
) -> json_report.GateVerdict {
  let licence_failed = case licences {
    Some(outcome) -> outcome.verdict == LicencesBlocked
    None -> False
  }
  case licence_failed, gate.status {
    True, _ -> json_report.Failed
    False, Ok(GateEvaluated(BlockingKnownSeverity, _))
    | False, Ok(GateEvaluated(BlockingUnknownSeverity, _))
    -> json_report.Failed
    False, Error(_)
    | False, Ok(GateUnavailable(_))
    | False, Ok(GateEvaluated(NoBlockingAdvisories, CheckIncomplete))
    -> json_report.Undetermined
    False, Ok(GateNotEvaluated)
    | False, Ok(GateEvaluated(NoBlockingAdvisories, CheckComplete))
    ->
      case licences {
        Some(outcome) if outcome.completeness == CheckIncomplete ->
          json_report.Undetermined
        Some(outcome) if outcome.verdict == LicencesPassed -> json_report.Passed
        Some(_) | None ->
          case gate.status {
            Ok(GateNotEvaluated) -> json_report.NotEnforced
            Ok(GateEvaluated(_, _)) -> json_report.Passed
            Ok(GateUnavailable(_)) | Error(_) -> json_report.Undetermined
          }
      }
  }
}

fn finalize_json_audit(
  options: cli.Options,
  licences: Option(LicenceGateOutcome),
  gate: VulnGateOutcome,
  packages: List(manifest.SbomEntry),
  configuration: config.Policy,
  today: String,
) -> #(ActionResult, progress.Reporter) {
  let document =
    json_report.Document(
      ..empty_document(
        case options.check {
          True -> json_report.Check
          False -> json_report.Report
        },
        checks_requested(options.checks),
        gate_failure(licences, gate),
      ),
      licences: option.map(licences, licence_json_result),
      exceptions: configuration.exceptions,
      today: today,
      gate_verdict: case options.check {
        True -> json_gate_verdict(licences, gate)
        False -> json_report.NotEnforced
      },
    )
  let document = case gate.scan_started {
    False -> document
    True ->
      case vulnerability_gate_json(gate, packages) {
        Ok(vulnerabilities) ->
          json_report.Document(
            ..document,
            vulnerabilities: Some(vulnerabilities),
          )
        Error(failure) -> json_report.Document(..document, outcome: failure)
      }
  }
  let complete =
    case document.licences {
      None -> True
      Some(result) -> result.complete
    }
    && case document.vulnerabilities {
      None -> gate.status == Ok(GateNotEvaluated)
      Some(result) -> result.complete
    }
  let reporter = case error.exit_code(document.outcome) {
    0 -> progress.defer_success(gate.reporter, "Check completed")
    1 -> gate.reporter
    _ -> progress.defer_error(gate.reporter, error.message(document.outcome))
  }
  #(json_result(json_report.Document(..document, complete: complete)), reporter)
}

fn json_vulns_report(
  rows: List(VulnRow),
  packages: List(manifest.SbomEntry),
  skipped: List(String),
  queried_packages: Int,
  coverage: exception.Coverage,
  configuration: config.Policy,
  today: String,
  complete: Bool,
  failure: error.Error,
) -> ActionResult {
  let document =
    json_report.Document(
      ..empty_document(
        json_report.Vulns,
        [json_report.Vulnerabilities],
        failure,
      ),
      exceptions: configuration.exceptions,
      today: today,
      complete: complete,
    )
  let encoded_rows =
    list.try_map(rows, fn(row) {
      use purl <- result.try(sbom.purl_for(row.package))
      Ok(
        list.index_map(row.vulnerabilities, fn(advisory, index) {
          let result = case
            list.find(row.failures, fn(failure) { failure.id == advisory.id })
          {
            Ok(failure) -> json_report.Unavailable(advisory.id, failure.failure)
            Error(_) ->
              case list.first(list.drop(row.decisions, index)) {
                Ok(decision) -> json_report.Available(advisory, decision, None)
                Error(_) ->
                  json_report.Unreviewed(
                    osv.for_package(advisory, purl),
                    case failure {
                      error.Success ->
                        error.Decode("Advisory exception decision unavailable")
                      _ -> failure
                    },
                  )
              }
          }
          json_report.VulnerabilityRow(
            package: row.package.name,
            version: row.package.version,
            purl: purl,
            result: result,
          )
        }),
      )
    })
  case encoded_rows {
    Error(failure) ->
      json_result(
        json_report.Document(..document, complete: False, outcome: failure),
      )
    Ok(rows) ->
      json_result(
        json_report.Document(
          ..document,
          vulnerabilities: Some(json_report.VulnerabilityResult(
            rows: list.flatten(rows),
            queried_packages: queried_packages,
            skipped_sources: skipped_vulnerability_sources(packages, skipped),
            coverage: coverage,
            complete: complete,
          )),
        ),
      )
  }
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
          case occurrence.blocking == Some(True) {
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
