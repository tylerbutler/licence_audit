import gleam/bool
import gleam/list
import gleam/option.{type Option, None, Some}
import glint
import glint/constraint
import licence_audit/color
import licence_audit/progress

const absent_string_flag = "__licence_audit_absent_string_flag__"

pub type Options {
  Options(
    manifest_path: Option(String),
    project_root: Option(String),
    config_path: Option(String),
    allow_licences: List(String),
    deny_licences: List(String),
    ignore_config: Bool,
    check: Bool,
    verbosity: progress.Verbosity,
    color: color.Mode,
    no_cache: Bool,
    cache_path: Option(String),
    check_vulns: Bool,
    vuln_severity: Option(String),
  )
}

pub type UpdateOptions {
  UpdateOptions(
    manifest_path: Option(String),
    project_root: Option(String),
    config_path: Option(String),
    ignore_config: Bool,
    verbosity: progress.Verbosity,
    color: color.Mode,
    no_cache: Bool,
    cache_path: Option(String),
  )
}

pub type SbomOptions {
  SbomOptions(
    manifest_path: Option(String),
    project_root: Option(String),
    verbosity: progress.Verbosity,
    no_cache: Bool,
    cache_path: Option(String),
    output: Option(String),
    offline: Bool,
  )
}

pub type VulnsOptions {
  VulnsOptions(
    manifest_path: Option(String),
    project_root: Option(String),
    verbosity: progress.Verbosity,
    color: color.Mode,
  )
}

pub type CliAction {
  RunAudit(Options)
  UpdateConfig(UpdateOptions)
  RunSbom(SbomOptions)
  RunVulns(VulnsOptions)
  InvalidUsage(String)
}

pub fn app() -> glint.Glint(CliAction) {
  glint.new()
  |> glint.with_name("licence_audit")
  |> glint.global_help("Audit locked Hex package licences.")
  |> glint.pretty_help(glint.default_pretty_help())
  |> glint.add(at: [], do: audit_command(check_mode: False, help: root_help))
  |> glint.add(at: ["check"], do: check_command())
  |> glint.add(at: ["update"], do: update_command())
  |> glint.add(at: ["sbom"], do: sbom_command())
  |> glint.add(at: ["vulns"], do: vulns_command())
}

pub fn normalize_args(args: List(String)) -> List(String) {
  list.map(args, fn(arg) {
    case arg {
      "-h" -> "--help"
      other -> other
    }
  })
}

const root_help = "Report Hex package licence metadata. Use the `check` subcommand to enforce a licence policy."

const check_help = "Report Hex package licence metadata and enforce the configured licence policy, exiting non-zero on violations."

fn audit_command(
  check_mode check_mode: Bool,
  help help: String,
) -> glint.Command(CliAction) {
  use <- glint.command_help(help)
  use <- glint.unnamed_args(glint.EqArgs(0))
  use allow <- glint.flag(allow_flag())
  use deny <- glint.flag(deny_flag())
  use config <- glint.flag(config_flag())
  use manifest <- glint.flag(manifest_flag())
  use ignore_config <- glint.flag(ignore_config_flag())
  use quiet <- glint.flag(quiet_flag())
  use verbose <- glint.flag(verbose_flag())
  use color_flag <- glint.flag(color_flag())
  use no_cache <- glint.flag(no_cache_flag())
  use cache_path <- glint.flag(cache_path_flag())
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
  let assert Ok(cache_path_value) = cache_path(flags)
  case verbosity(quiet, verbose), color.mode_from_string(color_value) {
    Error(verbosity_error), _ ->
      InvalidUsage(verbosity_error_message(verbosity_error))
    _, Error(color_error) -> InvalidUsage(color.mode_error_message(color_error))
    Ok(verbosity), Ok(color_mode) ->
      RunAudit(Options(
        manifest_path: optional_string(manifest_path),
        project_root: None,
        config_path: optional_string(config_path),
        allow_licences: allow_licences,
        deny_licences: deny_licences,
        ignore_config: ignore_config,
        check: check_mode,
        verbosity: verbosity,
        color: color_mode,
        no_cache: no_cache,
        cache_path: optional_string(cache_path_value),
        check_vulns: False,
        vuln_severity: None,
      ))
  }
}

fn check_command() -> glint.Command(CliAction) {
  use <- glint.command_help(check_help)
  use <- glint.unnamed_args(glint.EqArgs(0))
  use allow <- glint.flag(allow_flag())
  use deny <- glint.flag(deny_flag())
  use config <- glint.flag(config_flag())
  use manifest <- glint.flag(manifest_flag())
  use ignore_config <- glint.flag(ignore_config_flag())
  use quiet <- glint.flag(quiet_flag())
  use verbose <- glint.flag(verbose_flag())
  use color_flag <- glint.flag(color_flag())
  use no_cache <- glint.flag(no_cache_flag())
  use cache_path <- glint.flag(cache_path_flag())
  use check_vulns <- glint.flag(check_vulns_flag())
  use vuln_severity <- glint.flag(vuln_severity_flag())
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
  let assert Ok(cache_path_value) = cache_path(flags)
  let assert Ok(check_vulns_value) = check_vulns(flags)
  let assert Ok(vuln_severity_value) = vuln_severity(flags)

  case verbosity(quiet, verbose), color.mode_from_string(color_value) {
    Error(verbosity_error), _ ->
      InvalidUsage(verbosity_error_message(verbosity_error))
    _, Error(color_error) -> InvalidUsage(color.mode_error_message(color_error))
    Ok(verbosity), Ok(color_mode) ->
      RunAudit(Options(
        manifest_path: optional_string(manifest_path),
        project_root: None,
        config_path: optional_string(config_path),
        allow_licences: allow_licences,
        deny_licences: deny_licences,
        ignore_config: ignore_config,
        check: True,
        verbosity: verbosity,
        color: color_mode,
        no_cache: no_cache,
        cache_path: optional_string(cache_path_value),
        check_vulns: check_vulns_value,
        vuln_severity: optional_string(vuln_severity_value),
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
  |> glint.flag_default(absent_string_flag)
  |> glint.flag_help("Read configuration from PATH")
}

fn manifest_flag() -> glint.Flag(String) {
  glint.string_flag("manifest")
  |> glint.flag_default(absent_string_flag)
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
  |> glint.flag_help("Suppress progress output")
}

fn verbose_flag() -> glint.Flag(Bool) {
  glint.bool_flag("verbose")
  |> glint.flag_default(False)
  |> glint.flag_help("Show detailed progress output")
}

fn color_flag() -> glint.Flag(String) {
  glint.string_flag("color")
  |> glint.flag_default("auto")
  |> glint.flag_help("Colorize output: auto|always|never (default auto)")
}

fn no_cache_flag() -> glint.Flag(Bool) {
  glint.bool_flag("no-cache")
  |> glint.flag_default(False)
  |> glint.flag_help("Bypass the on-disk licence metadata cache")
}

fn cache_path_flag() -> glint.Flag(String) {
  glint.string_flag("cache-path")
  |> glint.flag_default(absent_string_flag)
  |> glint.flag_help("Override the licence metadata cache file location")
}

fn check_vulns_flag() -> glint.Flag(Bool) {
  glint.bool_flag("vulns")
  |> glint.flag_default(False)
  |> glint.flag_help(
    "When used with `check`, also query OSV.dev and fail on vulnerabilities at or above --vuln-severity",
  )
}

fn vuln_severity_flag() -> glint.Flag(String) {
  glint.string_flag("vuln-severity")
  |> glint.flag_default(absent_string_flag)
  |> glint.flag_constraint(fn(value) {
    case value == absent_string_flag {
      True -> Ok(value)
      False -> constraint.one_of(["low", "medium", "high", "critical"])(value)
    }
  })
  |> glint.flag_help(
    "Minimum severity that triggers `check --vulns` failure: low|medium|high|critical (default high)",
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

fn optional_string(value: String) -> Option(String) {
  use <- bool.guard(when: value == absent_string_flag, return: None)
  Some(value)
}

fn update_command() -> glint.Command(CliAction) {
  use <- glint.command_help(
    "Interactively review discovered licences and write an updated [tools.licence_audit] policy to gleam.toml.",
  )
  use <- glint.unnamed_args(glint.EqArgs(0))
  use config <- glint.flag(config_flag())
  use manifest <- glint.flag(manifest_flag())
  use ignore_config <- glint.flag(ignore_config_flag())
  use quiet <- glint.flag(quiet_flag())
  use verbose <- glint.flag(verbose_flag())
  use color_flag <- glint.flag(color_flag())
  use no_cache <- glint.flag(no_cache_flag())
  use cache_path <- glint.flag(cache_path_flag())
  use _, _, flags <- glint.command()

  let assert Ok(config_path) = config(flags)
  let assert Ok(manifest_path) = manifest(flags)
  let assert Ok(ignore_config) = ignore_config(flags)
  let assert Ok(quiet) = quiet(flags)
  let assert Ok(verbose) = verbose(flags)
  let assert Ok(color_value) = color_flag(flags)
  let assert Ok(no_cache) = no_cache(flags)
  let assert Ok(cache_path_value) = cache_path(flags)

  case verbosity(quiet, verbose), color.mode_from_string(color_value) {
    Error(verbosity_error), _ ->
      InvalidUsage(verbosity_error_message(verbosity_error))
    _, Error(color_error) -> InvalidUsage(color.mode_error_message(color_error))
    Ok(verbosity), Ok(color_mode) ->
      UpdateConfig(UpdateOptions(
        manifest_path: optional_string(manifest_path),
        project_root: None,
        config_path: optional_string(config_path),
        ignore_config: ignore_config,
        verbosity: verbosity,
        color: color_mode,
        no_cache: no_cache,
        cache_path: optional_string(cache_path_value),
      ))
  }
}

fn output_flag() -> glint.Flag(String) {
  glint.string_flag("output")
  |> glint.flag_default(absent_string_flag)
  |> glint.flag_help("Write SBOM to PATH instead of stdout")
}

fn offline_flag() -> glint.Flag(Bool) {
  glint.bool_flag("offline")
  |> glint.flag_default(False)
  |> glint.flag_help("Skip Hex metadata fetch; omit license fields")
}

const sbom_help = "Generate a CycloneDX 1.5 JSON SBOM from manifest.toml. Does not evaluate licence policy."

fn sbom_command() -> glint.Command(CliAction) {
  use <- glint.command_help(sbom_help)
  use <- glint.unnamed_args(glint.EqArgs(0))
  use manifest <- glint.flag(manifest_flag())
  use quiet <- glint.flag(quiet_flag())
  use verbose <- glint.flag(verbose_flag())
  use no_cache <- glint.flag(no_cache_flag())
  use cache_path <- glint.flag(cache_path_flag())
  use output <- glint.flag(output_flag())
  use offline <- glint.flag(offline_flag())
  use _, _, flags <- glint.command()

  let assert Ok(manifest_path) = manifest(flags)
  let assert Ok(quiet) = quiet(flags)
  let assert Ok(verbose) = verbose(flags)
  let assert Ok(no_cache) = no_cache(flags)
  let assert Ok(cache_path_value) = cache_path(flags)
  let assert Ok(output_value) = output(flags)
  let assert Ok(offline_value) = offline(flags)

  case verbosity(quiet, verbose) {
    Error(verbosity_error) ->
      InvalidUsage(verbosity_error_message(verbosity_error))
    Ok(verbosity) ->
      RunSbom(SbomOptions(
        manifest_path: optional_string(manifest_path),
        project_root: None,
        verbosity: verbosity,
        no_cache: no_cache,
        cache_path: optional_string(cache_path_value),
        output: optional_string(output_value),
        offline: offline_value,
      ))
  }
}

const vulns_help = "Report known vulnerabilities for locked dependencies using the OSV.dev database. Does not evaluate licence policy."

fn vulns_command() -> glint.Command(CliAction) {
  use <- glint.command_help(vulns_help)
  use <- glint.unnamed_args(glint.EqArgs(0))
  use manifest <- glint.flag(manifest_flag())
  use quiet <- glint.flag(quiet_flag())
  use verbose <- glint.flag(verbose_flag())
  use color_flag <- glint.flag(color_flag())
  // Accepted and ignored: `vulns` queries OSV and uses no licence cache, but
  // accepting --no-cache keeps it consistent with the other subcommands.
  use _no_cache <- glint.flag(no_cache_flag())
  use _, _, flags <- glint.command()

  let assert Ok(manifest_path) = manifest(flags)
  let assert Ok(quiet) = quiet(flags)
  let assert Ok(verbose) = verbose(flags)
  let assert Ok(color_value) = color_flag(flags)

  case verbosity(quiet, verbose), color.mode_from_string(color_value) {
    Error(verbosity_error), _ ->
      InvalidUsage(verbosity_error_message(verbosity_error))
    _, Error(color_error) -> InvalidUsage(color.mode_error_message(color_error))
    Ok(verbosity), Ok(color_mode) ->
      RunVulns(VulnsOptions(
        manifest_path: optional_string(manifest_path),
        project_root: None,
        verbosity: verbosity,
        color: color_mode,
      ))
  }
}
