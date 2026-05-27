import argv
import glam/doc.{type Document}
import gleam/dict
import gleam/int
import gleam/io
import gleam/list
import gleam/option.{None, Some}
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
import licence_audit/update as update_cmd
import simplifile
import tom

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

const output_line_width = 100

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
      progress.configure(options.verbosity)
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
      progress.configure(options.verbosity)
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
      progress.configure(options.verbosity)
      let #(RunResult(exit_code, output), reporter) =
        run_sbom_options(
          options,
          hex.fetch_package_metadata_from_hex,
          progress.enabled(options.verbosity, "sbom"),
        )
      io.print(output)
      let _ = progress.flush(reporter)
      halt(exit_code)
    }
    cli.RunVulns(options) -> {
      progress.configure(options.verbosity)
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
      run_sbom_options(options, fetcher, reporter)
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
    Error(message) -> #(RunResult(1, message <> "\n"), reporter)
  }
}

fn run_sbom_options(
  options: cli.SbomOptions,
  fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
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
    Ok(sbom_manifest) -> {
      let cache_mode = case options.no_cache {
        True -> cache.Disabled
        False -> cache.Enabled(path: options.cache_path)
      }
      let cache_handle = cache.open(cache_mode)
      let cached_fetcher = cache.wrap(cache_handle, fetcher)

      let #(license_metadata, reporter) = case options.offline {
        True -> #(dict.new(), reporter)
        False -> fetch_license_metadata(sbom_manifest, cached_fetcher, reporter)
      }
      let _ = cache.close(cache_handle)

      let root = read_root_component(project_root)
      let input =
        sbom.SbomInput(
          manifest: sbom_manifest,
          root: root,
          tool_version: tool_version(),
          serial_number: sbom_uuid.serial_number(),
          timestamp: sbom_uuid.timestamp_now(),
          license_metadata: license_metadata,
        )

      case sbom.try_render(input) {
        Error(err) -> #(diagnostic(err), reporter)
        Ok(json_str) -> write_sbom_output(options.output, json_str, reporter)
      }
    }
  }
}

fn fetch_license_metadata(
  manifest_value: manifest.SbomManifest,
  fetcher: fn(manifest.Package, progress.Reporter) ->
    #(Result(hex.PackageMetadata, hex.Error), progress.Reporter),
  reporter: progress.Reporter,
) -> #(dict.Dict(String, List(String)), progress.Reporter) {
  list.fold(manifest_value.entries, #(dict.new(), reporter), fn(acc, entry) {
    let #(licenses_acc, rep) = acc
    case entry.provenance {
      manifest.HexProvenance(_) -> {
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
            dict.insert(licenses_acc, entry.name, metadata.licences),
            rep,
          )
          Error(_) -> #(licenses_acc, rep)
        }
      }
      _ -> #(licenses_acc, rep)
    }
  })
}

fn read_root_component(project_root: String) -> sbom.RootComponent {
  let path = project_root <> "/gleam.toml"
  case simplifile.read(from: path) {
    Error(_) -> sbom.RootComponent(name: "project", version: "0.0.0")
    Ok(contents) ->
      case tom.parse(contents) {
        Error(_) -> sbom.RootComponent(name: "project", version: "0.0.0")
        Ok(doc) -> {
          let name = case tom.get_string(doc, ["name"]) {
            Ok(v) -> v
            Error(_) -> "project"
          }
          let version = case tom.get_string(doc, ["version"]) {
            Ok(v) -> v
            Error(_) -> "0.0.0"
          }
          sbom.RootComponent(name: name, version: version)
        }
      }
  }
}

fn tool_version() -> String {
  case simplifile.read(from: "gleam.toml") {
    Error(_) -> "unknown"
    Ok(contents) ->
      case tom.parse(contents) {
        Error(_) -> "unknown"
        Ok(doc) ->
          case tom.get_string(doc, ["version"]) {
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
          RunResult(2, "Error: failed to format SBOM JSON: " <> reason <> "\n"),
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

  case load_policy(options, project_root) {
    Error(config_error) -> #(
      diagnostic(error.from_config_error(config_error)),
      reporter,
    )
    Ok(config_policy) -> {
      case policy.from_config(config_policy, check_mode: options.check) {
        Error(policy_error) -> #(
          diagnostic(error.from_policy_error(policy_error)),
          reporter,
        )
        Ok(audit_policy) -> {
          let reporter = progress.detail(reporter, "Loading package manifest")
          case manifest.load(manifest_path) {
            Error(manifest_error) -> #(
              diagnostic(error.from_manifest_error(manifest_error)),
              reporter,
            )
            Ok(locked) -> {
              let reporter =
                progress.package_count(reporter, list.length(locked.packages))
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
              let result =
                fetch_packages(
                  locked.packages,
                  cached_fetcher,
                  audit_policy,
                  evaluate_policy,
                  dep_paths,
                  reporter,
                  [],
                  False,
                  False,
                )
              let cache_warning = cache.close(cache_handle)
              let skipped_rows =
                build_skipped_rows(locked.skipped_packages, dep_paths)
              let all_rows = list.append(result.rows, skipped_rows)
              let display_rows = case options.check && result.policy_failed {
                True -> report.filter_failing_trees(all_rows)
                False -> all_rows
              }
              let licence_output =
                report.format(
                  display_rows,
                  report.Summary(skipped_non_hex: locked.skipped_non_hex),
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

              let #(run_result, reporter) = case
                options.check && result.fetch_failed
              {
                True -> {
                  let reporter =
                    progress.defer_error(
                      vuln_reporter,
                      "Licence audit failed: package metadata could not be fetched",
                    )
                  #(RunResult(2, output), reporter)
                }
                False -> {
                  case vuln_query_failed {
                    True -> {
                      let reporter =
                        progress.defer_error(
                          vuln_reporter,
                          "Vulnerability check failed: OSV request failed",
                        )
                      #(RunResult(2, output), reporter)
                    }
                    False -> {
                      case options.check && result.policy_failed {
                        True -> {
                          let reporter =
                            progress.defer_error(
                              vuln_reporter,
                              "Licence audit failed: policy violations detected",
                            )
                          #(
                            RunResult(
                              1,
                              output <> error.message(error.AuditFailed) <> "\n",
                            ),
                            reporter,
                          )
                        }
                        False -> {
                          case vuln_failed {
                            True -> {
                              let reporter =
                                progress.defer_error(
                                  vuln_reporter,
                                  "Vulnerability check failed: advisories at or above threshold",
                                )
                              #(
                                RunResult(
                                  1,
                                  output
                                    <> "Vulnerability check failed: one or more advisories at or above threshold severity.\n",
                                ),
                                reporter,
                              )
                            }
                            False -> {
                              let reporter =
                                progress.defer_success(
                                  vuln_reporter,
                                  "Licence audit completed",
                                )
                              #(RunResult(0, output), reporter)
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }

              let reporter = case cache_warning {
                Some(message) -> progress.defer_warn(reporter, message)
                None -> reporter
              }
              #(run_result, reporter)
            }
          }
        }
      }
    }
  }
}

fn fetch_packages(
  packages: List(manifest.Package),
  fetcher: fn(manifest.Package, progress.Reporter) ->
    #(Result(hex.PackageMetadata, hex.Error), progress.Reporter),
  audit_policy: policy.Policy,
  check_mode: Bool,
  paths: dict.Dict(String, List(String)),
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
            reporter,
            [
              report.Row(
                package: package.name,
                version: package.version,
                licences: [],
                status: report.Failed(message),
                kind: package.kind,
                path: path,
              ),
              ..rows
            ],
            True,
            policy_failed,
          )
        }
        Ok(metadata) -> {
          let reporter =
            progress.detail(
              reporter,
              "Fetched package metadata for " <> package.name,
            )
          let status = case check_mode {
            True ->
              report.Checked(policy.audit(audit_policy, metadata.licences))
            False -> report.NotChecked
          }
          fetch_packages(
            rest,
            fetcher,
            audit_policy,
            check_mode,
            paths,
            reporter,
            [
              report.Row(
                package: package.name,
                version: package.version,
                licences: metadata.licences,
                status: status,
                kind: package.kind,
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
      path: path,
    )
  })
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
  let reporter = progress.phase(reporter, "Checking for vulnerabilities")
  let reporter = progress.detail(reporter, "Loading package manifest")

  case manifest.load_sbom(manifest_path) {
    Error(manifest_error) -> #(
      diagnostic(error.from_manifest_error(manifest_error)),
      reporter,
    )
    Ok(sbom_manifest) -> {
      let #(purl_pairs, purl_errors) = build_purl_pairs(sbom_manifest)
      let purls = list.map(purl_pairs, fn(pair) { pair.1 })

      case purls {
        [] -> {
          let output = format_vulns_output([], purl_errors, palette)
          #(RunResult(0, output), reporter)
        }
        _ -> {
          let reporter =
            progress.detail(
              reporter,
              "Querying OSV.dev for "
                <> int.to_string(list.length(purls))
                <> " packages",
            )
          case batch_fetcher(purls) {
            Error(osv_error) -> #(
              diagnostic(error.from_osv_error(osv_error)),
              reporter,
            )
            Ok(entries) -> {
              let with_packages =
                merge_entries_with_packages(entries, purl_pairs)
              let #(rows, reporter) =
                fetch_vuln_details(with_packages, detail_fetcher, reporter, [])
              let output = format_vulns_output(rows, purl_errors, palette)
              #(RunResult(0, output), reporter)
            }
          }
        }
      }
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
            fetch_each_vuln(ids, detail_fetcher, reporter, [])
          fetch_vuln_details(rest, detail_fetcher, reporter, [
            VulnRow(package: pkg, vulnerabilities: vulns),
            ..acc
          ])
        }
      }
    }
  }
}

fn fetch_each_vuln(
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
          fetch_each_vuln(rest, detail_fetcher, reporter, [vuln, ..acc])
        Error(_) -> {
          // Fall back to bare ID with unknown severity so the report still
          // shows the user something actionable. A network blip on a single
          // detail fetch should not blank out the whole row.
          let reporter =
            progress.defer_warn(
              reporter,
              "Failed to fetch OSV details for " <> id,
            )
          let placeholder =
            osv.Vulnerability(
              id: id,
              summary: "(details unavailable)",
              severity: osv.UnknownSeverity,
            )
          fetch_each_vuln(rest, detail_fetcher, reporter, [placeholder, ..acc])
        }
      }
    }
  }
}

fn format_vulns_output(
  rows: List(VulnRow),
  unsupported_packages: List(String),
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

  let summary_doc = doc.from_string(summary)

  let document = case affected {
    [] ->
      doc.join(
        [
          doc.from_string("No known vulnerabilities reported by OSV.dev."),
          summary_doc,
        ],
        with: doc.line,
      )
    _ -> {
      let body_doc =
        list.map(affected, fn(row) { format_vuln_row(row, palette) })
        |> doc.join(with: doc.line)
      doc.join(
        [
          doc.from_string("Vulnerabilities reported by OSV.dev:"),
          horizontal_rule(),
          body_doc,
          horizontal_rule(),
          summary_doc,
        ],
        with: doc.line,
      )
    }
  }

  render_document(doc.append(to: document, doc: doc.line))
}

fn format_vuln_row(row: VulnRow, palette: color.Palette) -> Document {
  let pkg_line =
    doc.from_string("● " <> row.package.name <> " " <> row.package.version)
  let vuln_lines =
    list.map(row.vulnerabilities, fn(vuln) {
      let severity_text = color.severity(palette, severity_label(vuln.severity))
      doc.from_string(
        "    "
        <> severity_text
        <> "  "
        <> vuln.id
        <> case vuln.summary {
          "" -> ""
          s -> "  " <> truncate(s, 80)
        },
      )
    })
    |> doc.join(with: doc.line)
  doc.concat([pkg_line, doc.line, vuln_lines])
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
  case string.length(s) > max {
    True -> string.slice(s, 0, max - 1) <> "…"
    False -> s
  }
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
    _ -> {
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
            fetch_vuln_details_flat(unique_ids, detail_fetcher, reporter, [])
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

fn fetch_vuln_details_flat(
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
          fetch_vuln_details_flat(rest, detail_fetcher, reporter, [vuln, ..acc])
        Error(_) -> {
          let reporter =
            progress.defer_warn(
              reporter,
              "Failed to fetch OSV details for " <> id,
            )
          let placeholder =
            osv.Vulnerability(
              id: id,
              summary: "(details unavailable)",
              severity: osv.UnknownSeverity,
            )
          fetch_vuln_details_flat(rest, detail_fetcher, reporter, [
            placeholder,
            ..acc
          ])
        }
      }
    }
  }
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
    [] ->
      doc.concat([
        doc.line,
        doc.from_string("No known vulnerabilities reported by OSV.dev."),
        doc.line,
      ])
      |> render_document
    _ -> {
      let lines_doc =
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
          doc.from_string(
            marker
            <> "  "
            <> color.severity(palette, severity_to_color_label(vuln.severity))
            <> "  "
            <> vuln.id
            <> "  "
            <> label,
          )
        })
        |> doc.join(with: doc.line)
      let summary_doc =
        doc.from_string(
          int.to_string(list.length(triggering))
          <> " advisory/advisories at or above "
          <> osv.severity_to_string(threshold)
          <> " (of "
          <> int.to_string(list.length(all_vulns))
          <> " total reported).",
        )

      doc.concat([
        doc.line,
        doc.join(
          [
            doc.from_string(
              "Vulnerability check (threshold: "
              <> osv.severity_to_string(threshold)
              <> ")",
            ),
            horizontal_rule(),
            lines_doc,
            horizontal_rule(),
            summary_doc,
          ],
          with: doc.line,
        ),
        doc.line,
      ])
      |> render_document
    }
  }
}

fn horizontal_rule() -> Document {
  doc.from_string(string.repeat("─", 72))
}

fn render_document(document: Document) -> String {
  doc.to_string(document, output_line_width)
}

fn severity_to_color_label(severity: osv.Severity) -> color.SeverityLabel {
  case severity {
    osv.Critical -> color.CriticalSeverity
    osv.High -> color.HighSeverity
    osv.Medium -> color.MediumSeverity
    osv.Low -> color.LowSeverity
    osv.UnknownSeverity -> color.UnknownSeverityLabel
  }
}
