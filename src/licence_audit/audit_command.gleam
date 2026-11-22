import gleam/bool
import gleam/dict
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/time/timestamp
import licence_audit/cache
import licence_audit/cli
import licence_audit/config
import licence_audit/error
import licence_audit/exception
import licence_audit/hex
import licence_audit/manifest
import licence_audit/network
import licence_audit/notice
import licence_audit/osv
import licence_audit/path
import licence_audit/policy
import licence_audit/progress
import licence_audit/report
import licence_audit/sbom
import licence_audit/vulnerability_command.{
  type CheckCompleteness, CheckComplete, CheckIncomplete,
}

pub type Outcome {
  Outcome(
    configuration: config.Policy,
    today: String,
    mode: report.Mode,
    licences: LicenceGateOutcome,
    vulnerabilities: vulnerability_command.VulnGateOutcome,
    packages: List(manifest.SbomEntry),
    review_failure: Option(error.Error),
    cache_warning: Option(String),
  )
}

pub fn run(
  options: cli.Options,
  source_clients: notice.Clients,
  batch_fetcher: fn(List(String)) -> Result(List(osv.BatchEntry), osv.Error),
  detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  reporter: progress.Reporter,
) -> #(Result(Outcome, error.Error), progress.Reporter) {
  let manifest_path =
    option.unwrap(options.manifest_path, "manifest.toml")
    |> manifest.resolve_path
  let project_root = path.dirname(manifest_path)
  let reporter = progress.phase(reporter, "Starting licence audit")
  let reporter = progress.detail(reporter, "Loading licence policy")
  let outcome = {
    use configuration <- result.try(
      vulnerability_command.load_policy(options, project_root)
      |> result.map_error(fn(failure) {
        #(error.from_config_error(failure), reporter)
      }),
    )
    use audit_policy <- result.try(
      policy.from_config(configuration, check_mode: options.check)
      |> result.map_error(fn(failure) {
        #(error.from_policy_error(failure), reporter)
      }),
    )
    let reporter = progress.detail(reporter, "Loading package manifest")
    use locked <- result.try(
      manifest.load(manifest_path)
      |> result.map_error(fn(failure) {
        #(error.from_manifest_error(failure), reporter)
      }),
    )
    use sbom_manifest <- result.try(
      case options.check && options.checks == cli.AllChecks {
        False -> Ok(None)
        True ->
          manifest.load_vulns(manifest_path)
          |> result.map(Some)
          |> result.map_error(fn(failure) {
            #(error.from_manifest_error(failure), reporter)
          })
      },
    )
    use prod_seed <- result.try(
      manifest.resolve_prod_seed(project_root, locked.direct_names)
      |> result.map_error(fn(failure) {
        #(error.from_manifest_error(failure), reporter)
      }),
    )
    Ok(scan(
      options,
      configuration,
      audit_policy,
      locked,
      sbom_manifest,
      prod_seed,
      source_clients,
      batch_fetcher,
      detail_fetcher,
      reporter,
    ))
  }
  case outcome {
    Error(#(failure, reporter)) -> #(Error(failure), reporter)
    Ok(outcome) -> #(Ok(outcome), outcome.vulnerabilities.reporter)
  }
}

fn scan(
  options: cli.Options,
  configuration: config.Policy,
  audit_policy: policy.Policy,
  locked: manifest.LockedPackages,
  sbom_manifest: Option(manifest.SbomManifest),
  prod_seed: List(String),
  source_clients: notice.Clients,
  batch_fetcher: fn(List(String)) -> Result(List(osv.BatchEntry), osv.Error),
  detail_fetcher: fn(String) -> Result(osv.Vulnerability, osv.Error),
  reporter: progress.Reporter,
) -> Outcome {
  let scopes = manifest.dep_scopes(locked, prod_seed)
  let today = exception.utc_date(timestamp.system_time())
  let reporter = progress.package_count(reporter, list.length(locked.packages))
  let evaluate_policy = policy.has_rules(audit_policy)
  let mode = case evaluate_policy {
    True -> report.Audit
    False -> report.Default
  }
  let cache_handle =
    cache.open(cache.mode_for(options.no_cache, options.cache_dir))
  let fetcher =
    cache.wrap_locked(cache_handle, fn(name, version, checksum) {
      notice.hex_metadata_from_locked_source(
        name,
        version,
        checksum,
        source_clients.fetch_hex_tarball,
      )
    })
  let dep_paths = case options.scope {
    cli.All -> manifest.dep_paths(locked)
    cli.Prod -> manifest.dep_paths_from(locked, prod_seed)
  }
  let #(active_packages, active_skipped) = case options.scope {
    cli.All -> #(locked.packages, locked.skipped_packages)
    cli.Prod -> #(
      list.filter(locked.packages, fn(package) {
        scope_for(scopes, package.name) == manifest.Prod
      }),
      list.filter(locked.skipped_packages, fn(package) {
        scope_for(scopes, package.name) == manifest.Prod
      }),
    )
  }
  let packages = case sbom_manifest {
    None -> []
    Some(locked) ->
      case options.scope {
        cli.All -> locked.entries
        cli.Prod ->
          list.filter(locked.entries, fn(entry) {
            scope_for(scopes, entry.name) == manifest.Prod
          })
      }
  }
  let fetched =
    fetch_packages(
      active_packages,
      fetcher,
      audit_policy,
      dep_paths,
      scopes,
      reporter,
      [],
      False,
    )
  let cache_warning = cache.close(cache_handle)
  let reviewed =
    review_licence_rows(
      fetched.rows,
      audit_policy,
      configuration.exceptions,
      today,
    )
  let skipped_rows = build_skipped_rows(active_skipped, dep_paths, scopes)
  case reviewed {
    Error(failure) ->
      Outcome(
        configuration: configuration,
        today: today,
        mode: mode,
        licences: LicenceGateOutcome(
          verdict: LicencesNotEnforced,
          completeness: CheckIncomplete,
          rows: list.append(fetched.rows, skipped_rows),
          counts: report.counts(
            list.append(fetched.rows, skipped_rows),
            report.Summary([]),
          ),
          coverage: exception.NotEvaluated("licence exception review failed"),
        ),
        vulnerabilities: vulnerability_command.not_evaluated(fetched.reporter),
        packages: packages,
        review_failure: Some(failure),
        cache_warning: cache_warning,
      )
    Ok(rows) -> {
      let rows = list.append(rows, skipped_rows)
      let policy_failed =
        list.any(rows, fn(row) { report.is_failure(row.status) })
      let gate = case options.check && options.checks == cli.AllChecks {
        False -> vulnerability_command.not_evaluated(fetched.reporter)
        True ->
          vulnerability_command.check(
            packages,
            options,
            configuration,
            batch_fetcher,
            detail_fetcher,
            fetched.reporter,
            today,
          )
      }
      let excluded_licences =
        locked.packages
        |> list.filter(fn(package) {
          options.scope == cli.Prod
          && scope_for(scopes, package.name) == manifest.Dev
        })
        |> list.map(fn(package) {
          #(
            sbom.hex_purl(package.name, package.version),
            "excluded by --scope=prod",
          )
        })
      let coverage = case evaluate_policy {
        False -> exception.NotEvaluated("licence policy not configured")
        True ->
          exception.Evaluated(
            rows
              |> list.flat_map(fn(row) { report.decisions(row.status) })
              |> exception.matched,
            list.append(
              excluded_licences,
              rows
                |> list.filter_map(fn(row) {
                  case row.status {
                    report.Failed(_) ->
                      Ok(#(
                        sbom.hex_purl(row.package, row.version),
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
        Some(locked) ->
          locked.entries
          |> list.filter(fn(entry) {
            options.scope == cli.Prod
            && scope_for(scopes, entry.name) == manifest.Dev
          })
          |> list.filter_map(fn(entry) {
            sbom.purl_for(entry)
            |> result.map(fn(purl) { #(purl, "excluded by --scope=prod") })
          })
      }
      Outcome(
        configuration: configuration,
        today: today,
        mode: mode,
        licences: LicenceGateOutcome(
          verdict: case options.check, policy_failed {
            False, _ -> LicencesNotEnforced
            True, False -> LicencesPassed
            True, True -> LicencesBlocked
          },
          completeness: case fetched.fetch_failed {
            True -> CheckIncomplete
            False -> CheckComplete
          },
          rows: rows,
          counts: report.counts(rows, report.Summary([])),
          coverage: coverage,
        ),
        vulnerabilities: vulnerability_command.VulnGateOutcome(
          ..gate,
          coverage: vulnerability_command.with_excluded_vulns(
            gate.coverage,
            excluded_vulns,
          ),
        ),
        packages: packages,
        review_failure: None,
        cache_warning: cache_warning,
      )
    }
  }
}

type FetchResult {
  FetchResult(
    rows: List(report.Row),
    fetch_failed: Bool,
    reporter: progress.Reporter,
  )
}

pub type LicenceVerdict {
  LicencesNotEnforced
  LicencesPassed
  LicencesBlocked
}

pub type LicenceGateOutcome {
  LicenceGateOutcome(
    verdict: LicenceVerdict,
    completeness: CheckCompleteness,
    rows: List(report.Row),
    counts: report.Counts,
    coverage: exception.Coverage,
  )
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

fn status_for(
  audit_policy: policy.Policy,
  licences: List(String),
) -> report.Status {
  case policy.has_rules(audit_policy) {
    True -> report.Checked(policy.audit(audit_policy, licences))
    False -> report.NotChecked
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
      list.map(rows, fn(row) { sbom.hex_purl(row.package, row.version) }),
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
          sbom.hex_purl(row.package, row.version),
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
