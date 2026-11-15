import gleam/list
import gleam/option.{type Option}
import gleam/string
import licence_audit/color
import licence_audit/internal/vendor/glint
import licence_audit/internal/vendor/glint/constraint
import licence_audit/progress

pub type DependencyScope {
  Prod
  All
}

pub type Checks {
  Licences
  Vulnerabilities
  AllChecks
}

pub type ReportOptions {
  ReportOptions(
    manifest_path: Option(String),
    config_path: Option(String),
    allow_licences: List(String),
    deny_licences: List(String),
    ignore_config: Bool,
    verbosity: progress.Verbosity,
    color: color.Mode,
    no_cache: Bool,
    cache_dir: Option(String),
    scope: DependencyScope,
  )
}

pub type Options {
  Options(
    manifest_path: Option(String),
    config_path: Option(String),
    allow_licences: List(String),
    deny_licences: List(String),
    ignore_config: Bool,
    check: Bool,
    verbosity: progress.Verbosity,
    color: color.Mode,
    no_cache: Bool,
    cache_dir: Option(String),
    checks: Checks,
    vuln_severity: Option(String),
    vuln_block_unknown: Bool,
    scope: DependencyScope,
  )
}

pub type UpdateOptions {
  UpdateOptions(
    manifest_path: Option(String),
    config_path: Option(String),
    ignore_config: Bool,
    verbosity: progress.Verbosity,
    color: color.Mode,
    no_cache: Bool,
    cache_dir: Option(String),
  )
}

pub type SbomOptions {
  SbomOptions(
    manifest_path: Option(String),
    verbosity: progress.Verbosity,
    color: color.Mode,
    no_cache: Bool,
    cache_dir: Option(String),
    output: Option(String),
    offline: Bool,
    reproducible: Bool,
    with_vulns: Bool,
    license_text: Bool,
  )
}

pub type VulnsOptions {
  VulnsOptions(
    manifest_path: Option(String),
    config_path: Option(String),
    ignore_config: Bool,
    verbosity: progress.Verbosity,
    color: color.Mode,
    scope: DependencyScope,
  )
}

pub type NoticesOptions {
  NoticesOptions(
    manifest_path: Option(String),
    config_path: Option(String),
    ignore_config: Bool,
    verbosity: progress.Verbosity,
    color: color.Mode,
    output: Option(String),
    scope: DependencyScope,
    no_cache: Bool,
    cache_dir: Option(String),
  )
}

pub type CliAction {
  RunReport(ReportOptions)
  RunAudit(Options)
  UpdateConfig(UpdateOptions)
  RunSbom(SbomOptions)
  RunVulns(VulnsOptions)
  RunNotices(NoticesOptions)
  ShowVersion
  InvalidUsage(String)
}

pub fn app() -> glint.Glint(CliAction) {
  glint.new()
  |> glint.with_name("licence_audit")
  |> glint.global_help(
    "Report locked dependency licences by default, or select a command. Use --help (alias: -h) for help.",
  )
  |> glint.pretty_help(glint.default_pretty_help())
  |> glint.add(at: [], do: root_command())
  |> glint.add(at: ["report"], do: report_command(fn(_) { False }))
  |> glint.add(at: ["check"], do: check_command())
  |> glint.add(at: ["update"], do: update_command())
  |> glint.add(at: ["sbom"], do: sbom_command())
  |> glint.add(at: ["vulns"], do: vulns_command())
  |> glint.add(at: ["notices"], do: notices_command())
}

pub fn normalize_args(args: List(String)) -> List(String) {
  list.map(args, fn(arg) {
    case arg {
      "-h" -> "--help"
      "-q" -> "--quiet"
      "-v" -> "--verbose"
      "--colour" -> "--color"
      other -> {
        case string.starts_with(other, "--colour=") {
          True ->
            "--color=" <> string.drop_start(other, string.length("--colour="))
          False -> other
        }
      }
    }
  })
}

fn root_command() -> glint.Command(CliAction) {
  use show_version <- glint.flag(version_flag())
  report_command(fn(flags) {
    let assert Ok(value) = show_version(flags)
    value
  })
}

const check_help =
  "Enforce selected checks: licences (default), vulns, or all. Licence checks require a licence policy. Vulnerability-only checks do not evaluate licence policy or fetch licence metadata."

fn report_command(
  show_version: fn(glint.Flags) -> Bool,
) -> glint.Command(CliAction) {
  use <- glint.command_help(
    "Report Hex package licences without enforcing policy findings. Operational failures exit 2. Use `check` to enforce a licence policy.",
  )
  use <- glint.unnamed_args(glint.EqArgs(0))
  use allow <- glint.flag(allow_flag())
  use deny <- glint.flag(deny_flag())
  use config <- glint.optional_flag(config_flag())
  use manifest <- glint.optional_flag(manifest_flag())
  use ignore_config <- glint.flag(ignore_config_flag())
  use quiet <- glint.flag(quiet_flag())
  use verbose <- glint.flag(verbose_flag())
  use color_flag <- glint.flag(color_flag())
  use no_cache <- glint.flag(no_cache_flag())
  use cache_dir <- glint.optional_flag(cache_dir_flag())
  use scope <- glint.flag(scope_flag("all"))
  use _, _, flags <- glint.command()

  let assert Ok(allow_licences) = allow(flags)
  let assert Ok(deny_licences) = deny(flags)
  let assert Ok(config_path) = config(flags)
  let assert Ok(manifest_path) = manifest(flags)
  let assert Ok(ignore_config) = ignore_config(flags)
  let assert Ok(quiet) = quiet(flags)
  let assert Ok(verbose) = verbose(flags)
  let assert Ok(color_value) = color_flag(flags)
  let assert Ok(no_cache) = no_cache(flags)
  let assert Ok(cache_dir_value) = cache_dir(flags)
  let assert Ok(scope_value) = scope(flags)
  case
    show_version(flags),
    verbosity(quiet, verbose),
    color.mode_from_string(color_value)
  {
    True, _, _ -> ShowVersion
    False, Error(verbosity_error), _ ->
      InvalidUsage(verbosity_error_message(verbosity_error))
    False, _, Error(color_error) ->
      InvalidUsage(color.mode_error_message(color_error))
    False, Ok(verbosity), Ok(color_mode) ->
      RunReport(ReportOptions(
        manifest_path: manifest_path,
        config_path: config_path,
        allow_licences: allow_licences,
        deny_licences: deny_licences,
        ignore_config: ignore_config,
        verbosity: verbosity,
        color: color_mode,
        no_cache: no_cache,
        cache_dir: cache_dir_value,
        scope: scope_from_string(scope_value),
      ))
  }
}

fn check_command() -> glint.Command(CliAction) {
  use <- glint.command_help(check_help)
  use <- glint.unnamed_args(glint.EqArgs(0))
  use allow <- glint.flag(allow_flag())
  use deny <- glint.flag(deny_flag())
  use config <- glint.optional_flag(config_flag())
  use manifest <- glint.optional_flag(manifest_flag())
  use ignore_config <- glint.flag(ignore_config_flag())
  use quiet <- glint.flag(quiet_flag())
  use verbose <- glint.flag(verbose_flag())
  use color_flag <- glint.flag(color_flag())
  use no_cache <- glint.flag(no_cache_flag())
  use cache_dir <- glint.optional_flag(cache_dir_flag())
  use scope <- glint.flag(scope_flag("all"))
  use checks <- glint.flag(checks_flag())
  use vuln_severity <- glint.optional_flag(vuln_severity_flag())
  use vuln_block_unknown <- glint.optional_flag(vuln_block_unknown_flag())
  use _, _, flags <- glint.command()

  let assert Ok(allow_licences) = allow(flags)
  let assert Ok(deny_licences) = deny(flags)
  let assert Ok(config_path) = config(flags)
  let assert Ok(manifest_path) = manifest(flags)
  let assert Ok(ignore_config) = ignore_config(flags)
  let assert Ok(quiet) = quiet(flags)
  let assert Ok(verbose) = verbose(flags)
  let assert Ok(color_value) = color_flag(flags)
  let assert Ok(no_cache) = no_cache(flags)
  let assert Ok(cache_dir_value) = cache_dir(flags)
  let assert Ok(scope_value) = scope(flags)
  let assert Ok(checks_value) = checks(flags)
  let assert Ok(vuln_severity_value) = vuln_severity(flags)
  let assert Ok(vuln_block_unknown_value) = vuln_block_unknown(flags)

  case
    verbosity(quiet, verbose),
    color.mode_from_string(color_value),
    checks_value == "licences"
    && {
      option.is_some(vuln_severity_value)
      || option.is_some(vuln_block_unknown_value)
    }
  {
    Error(verbosity_error), _, _ ->
      InvalidUsage(verbosity_error_message(verbosity_error))
    _, Error(color_error), _ ->
      InvalidUsage(color.mode_error_message(color_error))
    _, _, True ->
      InvalidUsage(
        "--vuln-severity and --vuln-block-unknown require --checks=vulns or --checks=all",
      )
    Ok(verbosity), Ok(color_mode), False ->
      RunAudit(Options(
        manifest_path: manifest_path,
        config_path: config_path,
        allow_licences: allow_licences,
        deny_licences: deny_licences,
        ignore_config: ignore_config,
        check: True,
        verbosity: verbosity,
        color: color_mode,
        no_cache: no_cache,
        cache_dir: cache_dir_value,
        checks: case checks_value {
          "vulns" -> Vulnerabilities
          "all" -> AllChecks
          _ -> Licences
        },
        vuln_severity: vuln_severity_value,
        vuln_block_unknown: option.unwrap(vuln_block_unknown_value, False),
        scope: scope_from_string(scope_value),
      ))
  }
}

fn allow_flag() -> glint.Flag(List(String)) {
  glint.strings_flag("allow")
  |> glint.flag_default([])
  |> glint.flag_help("Allow licences, comma-separated")
}

fn deny_flag() -> glint.Flag(List(String)) {
  glint.strings_flag("deny")
  |> glint.flag_default([])
  |> glint.flag_help("Deny licences, comma-separated")
}

fn config_flag() -> glint.Flag(String) {
  glint.string_flag("config")
  |> glint.flag_help("Read configuration from PATH")
}

fn manifest_flag() -> glint.Flag(String) {
  glint.string_flag("manifest")
  |> glint.flag_help("Read manifest from PATH")
}

fn ignore_config_flag() -> glint.Flag(Bool) {
  glint.bool_flag("ignore-config")
  |> glint.flag_default(False)
  |> glint.flag_help("Ignore configuration files")
}

fn quiet_flag() -> glint.Flag(Bool) {
  glint.bool_flag("quiet")
  |> glint.flag_default(False)
  |> glint.flag_help("Suppress progress output (alias: -q)")
}

fn verbose_flag() -> glint.Flag(Bool) {
  glint.bool_flag("verbose")
  |> glint.flag_default(False)
  |> glint.flag_help("Show detailed progress output (alias: -v)")
}

fn color_flag() -> glint.Flag(String) {
  glint.string_flag("color")
  |> glint.flag_default("auto")
  |> glint.flag_help(
    "Colorize output: auto|always|never (default auto; alias: --colour)",
  )
}

fn no_cache_flag() -> glint.Flag(Bool) {
  glint.bool_flag("no-cache")
  |> glint.flag_default(False)
  |> glint.flag_help("Bypass the on-disk caches")
}

fn version_flag() -> glint.Flag(Bool) {
  glint.bool_flag("version")
  |> glint.flag_default(False)
  |> glint.flag_help("Print the installed version")
}

fn scope_flag(default: String) -> glint.Flag(String) {
  glint.string_flag("scope")
  |> glint.flag_default(default)
  |> glint.flag_constraint(constraint.one_of(["prod", "all"]))
  |> glint.flag_help(
    "Dependency scope: prod|all (production only or all dependencies)",
  )
}

fn scope_from_string(value: String) -> DependencyScope {
  case value {
    "prod" -> Prod
    _ -> All
  }
}

fn cache_dir_flag() -> glint.Flag(String) {
  glint.string_flag("cache-dir")
  |> glint.flag_help(
    "Use DIR as the application cache root for all cache families",
  )
}

fn checks_flag() -> glint.Flag(String) {
  glint.string_flag("checks")
  |> glint.flag_default("licences")
  |> glint.flag_constraint(constraint.one_of(["licences", "vulns", "all"]))
  |> glint.flag_help(
    "Select checks: licences|vulns|all (default licences); licences and all require a licence policy",
  )
}

fn vuln_severity_flag() -> glint.Flag(String) {
  glint.string_flag("vuln-severity")
  |> glint.flag_constraint(
    constraint.one_of(["low", "medium", "high", "critical"]),
  )
  |> glint.flag_help(
    "Minimum blocking vulnerability severity: low|medium|high|critical (default high; requires --checks=vulns or --checks=all)",
  )
}

fn vuln_block_unknown_flag() -> glint.Flag(Bool) {
  glint.bool_flag("vuln-block-unknown")
  |> glint.flag_help(
    "Fail on advisories whose severity is unknown (default false; requires --checks=vulns or --checks=all)",
  )
}

type VerbosityError {
  ConflictingVerbosity
}

fn verbosity(
  quiet: Bool,
  verbose: Bool,
) -> Result(progress.Verbosity, VerbosityError) {
  case quiet, verbose {
    True, True -> Error(ConflictingVerbosity)
    True, False -> Ok(progress.Quiet)
    False, True -> Ok(progress.Verbose)
    False, False -> Ok(progress.Normal)
  }
}

fn verbosity_error_message(error: VerbosityError) -> String {
  let ConflictingVerbosity = error
  "--quiet and --verbose cannot be used together"
}

fn update_command() -> glint.Command(CliAction) {
  use <- glint.command_help(
    "Interactively review discovered licences and write an updated [tools.licence_audit] policy to gleam.toml.",
  )
  use <- glint.unnamed_args(glint.EqArgs(0))
  use config <- glint.optional_flag(config_flag())
  use manifest <- glint.optional_flag(manifest_flag())
  use ignore_config <- glint.flag(ignore_config_flag())
  use quiet <- glint.flag(quiet_flag())
  use verbose <- glint.flag(verbose_flag())
  use color_flag <- glint.flag(color_flag())
  use no_cache <- glint.flag(no_cache_flag())
  use cache_dir <- glint.optional_flag(cache_dir_flag())
  use _, _, flags <- glint.command()

  let assert Ok(config_path) = config(flags)
  let assert Ok(manifest_path) = manifest(flags)
  let assert Ok(ignore_config) = ignore_config(flags)
  let assert Ok(quiet) = quiet(flags)
  let assert Ok(verbose) = verbose(flags)
  let assert Ok(color_value) = color_flag(flags)
  let assert Ok(no_cache) = no_cache(flags)
  let assert Ok(cache_dir_value) = cache_dir(flags)
  case verbosity(quiet, verbose), color.mode_from_string(color_value) {
    Error(verbosity_error), _ ->
      InvalidUsage(verbosity_error_message(verbosity_error))
    _, Error(color_error) -> InvalidUsage(color.mode_error_message(color_error))
    Ok(verbosity), Ok(color_mode) ->
      UpdateConfig(UpdateOptions(
        manifest_path: manifest_path,
        config_path: config_path,
        ignore_config: ignore_config,
        verbosity: verbosity,
        color: color_mode,
        no_cache: no_cache,
        cache_dir: cache_dir_value,
      ))
  }
}

fn output_flag(help: String) -> glint.Flag(String) {
  glint.string_flag("output")
  |> glint.flag_help(help)
}

fn offline_flag() -> glint.Flag(Bool) {
  glint.bool_flag("offline")
  |> glint.flag_default(False)
  |> glint.flag_help(
    "Skip Hex metadata fetch; with --reproducible, skip Git enrichment too. Local path metadata is always required",
  )
}

fn reproducible_flag() -> glint.Flag(Bool) {
  glint.bool_flag("reproducible")
  |> glint.flag_default(False)
  |> glint.flag_help(
    "Reproducible output from locked archives (unless --offline) and current local path metadata; serialNumber is a content hash and timestamp comes from SOURCE_DATE_EPOCH (default 1970-01-01T00:00:00Z)",
  )
}

fn sbom_vulns_flag() -> glint.Flag(Bool) {
  glint.bool_flag("vulns")
  |> glint.flag_default(False)
  |> glint.flag_help(
    "Query OSV.dev and embed a CycloneDX vulnerabilities array (requires network; conflicts with --offline and --reproducible)",
  )
}

const sbom_help =
  "Generate a CycloneDX 1.6 JSON SBOM from manifest.toml. Does not evaluate licence policy. Includes all dependencies with their CycloneDX scope. JSON output stays plain in every color mode."

fn sbom_command() -> glint.Command(CliAction) {
  use <- glint.command_help(sbom_help)
  use <- glint.unnamed_args(glint.EqArgs(0))
  use manifest <- glint.optional_flag(manifest_flag())
  use quiet <- glint.flag(quiet_flag())
  use verbose <- glint.flag(verbose_flag())
  use color_flag <- glint.flag(color_flag())
  use no_cache <- glint.flag(no_cache_flag())
  use cache_dir <- glint.optional_flag(cache_dir_flag())
  use output <- glint.optional_flag(output_flag(
    "Write SBOM to PATH instead of stdout",
  ))
  use offline <- glint.flag(offline_flag())
  use reproducible <- glint.flag(reproducible_flag())
  use with_vulns <- glint.flag(sbom_vulns_flag())
  use license_text <- glint.flag(
    glint.bool_flag("license-text")
    |> glint.flag_default(False)
    |> glint.flag_help(
      "Embed canonical SPDX text for recognised licence IDs (requires network on cache miss; conflicts with --offline)",
    ),
  )
  use _, _, flags <- glint.command()

  let assert Ok(manifest_path) = manifest(flags)
  let assert Ok(quiet) = quiet(flags)
  let assert Ok(verbose) = verbose(flags)
  let assert Ok(color_value) = color_flag(flags)
  let assert Ok(no_cache) = no_cache(flags)
  let assert Ok(cache_dir_value) = cache_dir(flags)
  let assert Ok(output_value) = output(flags)
  let assert Ok(offline_value) = offline(flags)
  let assert Ok(reproducible_value) = reproducible(flags)
  let assert Ok(with_vulns_value) = with_vulns(flags)
  let assert Ok(license_text_value) = license_text(flags)

  case
    verbosity(quiet, verbose),
    offline_value && with_vulns_value,
    reproducible_value && with_vulns_value,
    offline_value && license_text_value,
    color.mode_from_string(color_value)
  {
    Error(verbosity_error), _, _, _, _ ->
      InvalidUsage(verbosity_error_message(verbosity_error))
    _, True, _, _, _ ->
      InvalidUsage(
        "--vulns requires network access and cannot be combined with --offline",
      )
    _, _, True, _, _ ->
      InvalidUsage(
        "--vulns uses mutable advisory data and cannot be combined with --reproducible",
      )
    _, _, _, True, _ ->
      InvalidUsage("--license-text cannot be combined with --offline")
    _, _, _, _, Error(color_error) ->
      InvalidUsage(color.mode_error_message(color_error))
    Ok(verbosity), False, False, False, Ok(color_mode) ->
      RunSbom(SbomOptions(
        manifest_path: manifest_path,
        verbosity: verbosity,
        color: color_mode,
        no_cache: no_cache,
        cache_dir: cache_dir_value,
        output: output_value,
        offline: offline_value,
        reproducible: reproducible_value,
        with_vulns: with_vulns_value,
        license_text: license_text_value,
      ))
  }
}

const notices_help =
  "Generate a release-ready `THIRD_PARTY_NOTICES`-style file from locked dependencies. The output inventories each product, includes its applicable licence text, and preserves package-specific NOTICE attribution. Products with identical licence text are grouped so the shared text is emitted once. Each package's own source archive is used first; when it ships no licence text the command falls back to the declared repository (GitHub, Codeberg, or GitLab, at an immutable tag commit) and then to canonical SPDX License List text. A transient repository failure is non-fatal: it warns and continues to the SPDX fallback. Output stays plain in every color mode. Configuration reads only notices include/exclude settings; a missing notices section means no filters."

fn notices_command() -> glint.Command(CliAction) {
  use <- glint.command_help(notices_help)
  use <- glint.unnamed_args(glint.EqArgs(0))
  use manifest <- glint.optional_flag(manifest_flag())
  use config <- glint.optional_flag(config_flag())
  use ignore_config <- glint.flag(ignore_config_flag())
  use quiet <- glint.flag(quiet_flag())
  use verbose <- glint.flag(verbose_flag())
  use color_flag <- glint.flag(color_flag())
  use output <- glint.optional_flag(output_flag(
    "Write notices to PATH instead of stdout",
  ))
  use scope <- glint.flag(scope_flag("prod"))
  use no_cache <- glint.flag(no_cache_flag())
  use cache_dir <- glint.optional_flag(cache_dir_flag())
  use _, _, flags <- glint.command()

  let assert Ok(manifest_path) = manifest(flags)
  let assert Ok(config_path) = config(flags)
  let assert Ok(ignore_config) = ignore_config(flags)
  let assert Ok(quiet) = quiet(flags)
  let assert Ok(verbose) = verbose(flags)
  let assert Ok(color_value) = color_flag(flags)
  let assert Ok(output_value) = output(flags)
  let assert Ok(scope_value) = scope(flags)
  let assert Ok(no_cache) = no_cache(flags)
  let assert Ok(cache_dir_value) = cache_dir(flags)

  case verbosity(quiet, verbose), color.mode_from_string(color_value) {
    Error(verbosity_error), _ ->
      InvalidUsage(verbosity_error_message(verbosity_error))
    _, Error(color_error) -> InvalidUsage(color.mode_error_message(color_error))
    Ok(verbosity), Ok(color_mode) ->
      RunNotices(NoticesOptions(
        manifest_path: manifest_path,
        config_path: config_path,
        ignore_config: ignore_config,
        verbosity: verbosity,
        color: color_mode,
        output: output_value,
        scope: scope_from_string(scope_value),
        no_cache: no_cache,
        cache_dir: cache_dir_value,
      ))
  }
}

const vulns_help =
  "Report known vulnerabilities for locked dependencies using the OSV.dev database. Does not evaluate licence policy. Includes dev dependencies unless --scope=prod is set. Queries OSV directly and uses no on-disk cache."

fn vulns_command() -> glint.Command(CliAction) {
  use <- glint.command_help(vulns_help)
  use <- glint.unnamed_args(glint.EqArgs(0))
  use manifest <- glint.optional_flag(manifest_flag())
  use config <- glint.optional_flag(config_flag())
  use ignore_config <- glint.flag(ignore_config_flag())
  use quiet <- glint.flag(quiet_flag())
  use verbose <- glint.flag(verbose_flag())
  use color_flag <- glint.flag(color_flag())
  use scope <- glint.flag(scope_flag("all"))
  use _, _, flags <- glint.command()

  let assert Ok(manifest_path) = manifest(flags)
  let assert Ok(config_path) = config(flags)
  let assert Ok(ignore_config) = ignore_config(flags)
  let assert Ok(quiet) = quiet(flags)
  let assert Ok(verbose) = verbose(flags)
  let assert Ok(color_value) = color_flag(flags)
  let assert Ok(scope_value) = scope(flags)

  case verbosity(quiet, verbose), color.mode_from_string(color_value) {
    Error(verbosity_error), _ ->
      InvalidUsage(verbosity_error_message(verbosity_error))
    _, Error(color_error) -> InvalidUsage(color.mode_error_message(color_error))
    Ok(verbosity), Ok(color_mode) ->
      RunVulns(VulnsOptions(
        manifest_path: manifest_path,
        config_path: config_path,
        ignore_config: ignore_config,
        verbosity: verbosity,
        color: color_mode,
        scope: scope_from_string(scope_value),
      ))
  }
}
