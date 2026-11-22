import gleam/int
import gleam/list
import gleam/option.{type Option}
import gleam/string
import licence_audit/color
import licence_audit/internal/vendor/glint
import licence_audit/internal/vendor/glint/constraint
import licence_audit/progress
import tty

pub type DependencyScope {
  Prod
  All
}

pub type Checks {
  Licences
  Vulnerabilities
  AllChecks
}

pub type ReportFormat {
  Text
  Json
}

pub type ReportOptions {
  ReportOptions(
    manifest_path: Option(String),
    config_path: Option(String),
    ignore_config: Bool,
    verbosity: progress.Verbosity,
    color: color.Mode,
    no_cache: Bool,
    cache_dir: Option(String),
    scope: DependencyScope,
    format: ReportFormat,
  )
}

pub type Options {
  Options(
    manifest_path: Option(String),
    config_path: Option(String),
    ignore_config: Bool,
    check: Bool,
    verbosity: progress.Verbosity,
    color: color.Mode,
    no_cache: Bool,
    cache_dir: Option(String),
    checks: Checks,
    vuln_severity: Option(String),
    vuln_block_unknown: Option(Bool),
    scope: DependencyScope,
    format: ReportFormat,
  )
}

pub type UpdateOptions {
  UpdateOptions(
    manifest_path: Option(String),
    config_path: Option(String),
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
    format: ReportFormat,
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
  |> glint.add(at: [], do: root_command())
  |> glint.path_help(
    at: [],
    put: "Report locked dependency licences by default, or select a command. Use --help (alias: -h) for help.\n\n\n"
      <> report_help,
  )
  |> glint.add(at: ["report"], do: named_report_command())
  |> glint.add(at: ["check"], do: check_command())
  |> glint.add(at: ["update"], do: update_command())
  |> glint.add(at: ["sbom"], do: sbom_command())
  |> glint.add(at: ["vulns"], do: vulns_command())
  |> glint.add(at: ["notices"], do: notices_command())
}

pub fn execute(
  args: List(String),
  stdout_color_level: tty.ColorLevel,
  stderr_color_level: tty.ColorLevel,
) -> Result(glint.Out(CliAction), String) {
  let args = normalize_args(args)
  let mode = help_color_mode(args, color.Auto)
  let palette = color.resolve_with_color_level(mode, stdout_color_level)
  let error_palette = color.resolve_with_color_level(mode, stderr_color_level)
  let app = case palette.enabled {
    True -> app() |> glint.pretty_help(glint.default_pretty_help())
    False -> app()
  }
  case glint.execute_detailed(app, args) {
    Error(error) -> Error(parser_error_message(error, error_palette))
    Ok(glint.Out(InvalidUsage(message))) ->
      Error(usage_message(
        escape_input(message),
        command_path(args),
        "",
        error_palette,
      ))
    Ok(output) -> Ok(output)
  }
}

fn command_path(args: List(String)) -> List(String) {
  let positionals =
    list.filter(args, fn(arg) { !string.starts_with(arg, "--") })
  case positionals {
    [name, ..] -> {
      case list.contains(command_names(), name) {
        True -> [name]
        False -> []
      }
    }
    [] -> []
  }
}

fn command_names() -> List(String) {
  glint.document(app()).subcommands
  |> list.map(fn(command) { command.meta.name })
  |> list.sort(string.compare)
}

fn parser_error_message(
  error: glint.ExecutionError,
  palette: color.Palette,
) -> String {
  let #(message, hint) = case error.cause {
    glint.UnknownFlag("", "--") -> #("the '--' separator is not supported", "")
    glint.UnknownFlag("", input) -> #(
      "unknown flag " <> escape_input(input),
      "",
    )
    glint.UnknownFlag(name, _) -> #(
      "unknown flag --" <> escape_input(name),
      migration_hint(name),
    )
    glint.MissingFlagValue(name, _) -> #(
      "--" <> escape_input(name) <> " requires a value",
      "",
    )
    glint.InvalidFlagValue(name, value, _) -> #(
      invalid_value_message(name, value),
      "",
    )
    glint.InvalidArgumentCount(_, [argument, ..]) -> {
      case error.command_path, string.starts_with(argument, "-") {
        _, True -> #("unknown flag " <> escape_input(argument), "")
        [], False -> {
          let suggestion = case argument {
            "help" -> "; use --help"
            "version" -> "; use --version"
            _ -> ""
          }
          #(
            "unknown command '" <> escape_input(argument) <> "'" <> suggestion,
            "Commands: " <> string.join(command_names(), ", "),
          )
        }
        [_, ..], False -> #(
          "unexpected argument '" <> escape_input(argument) <> "'",
          "",
        )
      }
    }
    glint.InvalidArgumentCount(_, []) -> #("missing required arguments", "")
    glint.UnmatchedNamedArguments(names) -> #(
      "missing required arguments: " <> escape_input(string.join(names, ", ")),
      "",
    )
    glint.CommandNotFound -> #("a command is required", "")
  }
  usage_message(message, error.command_path, hint, palette)
}

fn usage_message(
  message: String,
  path: List(String),
  hint: String,
  palette: color.Palette,
) -> String {
  let command = string.join(["licence_audit", ..path], " ")
  color.red(palette, "Error:")
  <> " "
  <> message
  <> case hint {
    "" -> ""
    _ -> "\n" <> hint
  }
  <> "\nRun '"
  <> command
  <> " --help' for usage."
}

fn migration_hint(name: String) -> String {
  case name {
    "allow" | "deny" ->
      "Put the lists in [tools.licence_audit] and select the file with --config."
    "prod-only" -> "Use --scope=prod."
    "include-dev" -> "Use --scope=all."
    "cache-path" -> "Use --cache-dir with the application cache root."
    _ -> ""
  }
}

const scope_values = ["prod", "all"]

const check_values = ["licences", "licenses", "vulns", "all"]

const severity_values = ["low", "medium", "high", "critical"]

const format_values = ["text", "json"]

fn invalid_value_message(name: String, value: String) -> String {
  let expected = case name {
    "scope" -> scope_values
    "checks" -> check_values
    "vuln-severity" -> severity_values
    "format" -> format_values
    _ -> ["true", "false"]
  }
  "invalid value '"
  <> escape_input(value)
  <> "' for --"
  <> escape_input(name)
  <> " (expected "
  <> string.join(expected, " or ")
  <> ")"
}

fn escape_input(value: String) -> String {
  value
  |> string.replace("\\", "\\\\")
  |> string.replace("'", "\\'")
  |> escape_controls
}

fn escape_controls(value: String) -> String {
  value
  |> string.to_utf_codepoints
  |> list.map(fn(point) {
    let code = string.utf_codepoint_to_int(point)
    case code {
      10 -> "\\n"
      13 -> "\\r"
      9 -> "\\t"
      code
        if code < 32
        || code >= 127
        && code <= 159
        || code == 8232
        || code == 8233
      -> "\\u{" <> int.to_base16(code) <> "}"
      _ -> string.from_utf_codepoints([point])
    }
  })
  |> string.concat
}

fn help_color_mode(args: List(String), mode: color.Mode) -> color.Mode {
  case args {
    [] | ["--", ..] -> mode
    ["--color=" <> value, ..rest] -> {
      // Rendering must not change Glint's help-first or invalid-value behavior.
      let mode = case color.mode_from_string(value) {
        Ok(mode) -> mode
        Error(_) -> color.Auto
      }
      help_color_mode(rest, mode)
    }
    [_, ..rest] -> help_color_mode(rest, mode)
  }
}

pub fn normalize_args(args: List(String)) -> List(String) {
  let tree = glint.document(app())
  let value_flags =
    [tree, ..tree.subcommands]
    |> list.flat_map(fn(command) { command.flags })
    |> list.filter(fn(flag) { flag.type_ != "BOOL" })
    |> list.map(fn(flag) { "--" <> flag.meta.name })
  normalize_values(args, value_flags, [])
}

/// Recognize the selected JSON format even when another argument is invalid.
/// Callers must retain normal help output when execution returns Glint help.
pub fn recognized_json_command(args: List(String)) -> Option(String) {
  let args = args |> normalize_args |> before_separator
  case command_path(args), selected_format(args, option.None) {
    [command], option.Some("json")
      if command == "report" || command == "check" || command == "vulns"
    -> option.Some(command)
    _, _ -> option.None
  }
}

/// Preserve valid check selection when JSON usage fails before action parsing.
pub fn recognized_checks(args: List(String)) -> Option(Checks) {
  let args = args |> normalize_args |> before_separator
  case command_path(args) {
    ["report"] -> option.Some(Licences)
    ["vulns"] -> option.Some(Vulnerabilities)
    ["check"] -> selected_checks(args, option.Some(Licences))
    _ -> option.None
  }
}

fn selected_checks(
  args: List(String),
  selected: Option(Checks),
) -> Option(Checks) {
  case args {
    [] -> selected
    ["--checks=" <> value, ..rest] ->
      selected_checks(rest, case value {
        "licences" | "licenses" -> option.Some(Licences)
        "vulns" -> option.Some(Vulnerabilities)
        "all" -> option.Some(AllChecks)
        _ -> option.None
      })
    ["--checks", ..rest] -> selected_checks(rest, option.None)
    [_, ..rest] -> selected_checks(rest, selected)
  }
}

fn before_separator(args: List(String)) -> List(String) {
  case args {
    [] | ["--", ..] -> []
    [arg, ..rest] -> [arg, ..before_separator(rest)]
  }
}

fn selected_format(
  args: List(String),
  selected: Option(String),
) -> Option(String) {
  case args {
    [] -> selected
    ["--format=" <> value, ..rest] -> selected_format(rest, option.Some(value))
    ["--format", ..rest] -> selected_format(rest, option.None)
    [_, ..rest] -> selected_format(rest, selected)
  }
}

fn normalize_values(
  args: List(String),
  value_flags: List(String),
  normalized: List(String),
) -> List(String) {
  case args {
    [] -> list.reverse(normalized)
    // Glint rejects separators; leave this suffix untouched for its usage error.
    ["--", ..] -> list.append(list.reverse(normalized), args)
    [arg, ..rest] -> {
      let arg = normalize_alias(arg)
      case list.contains(value_flags, arg), rest {
        True, [value, ..remaining] if value != "--" ->
          // Glint only accepts values in --flag=value form.
          normalize_values(remaining, value_flags, [
            arg <> "=" <> value,
            ..normalized
          ])
        _, _ -> normalize_values(rest, value_flags, [arg, ..normalized])
      }
    }
  }
}

fn normalize_alias(arg: String) -> String {
  case arg {
    "-h" -> "--help"
    "-q" -> "--quiet"
    "-v" -> "--verbose"
    "--colour" -> "--color"
    "--license-text" -> "--licence-text"
    other -> {
      case
        string.starts_with(other, "--colour="),
        string.starts_with(other, "--license-text=")
      {
        True, _ ->
          "--color=" <> string.drop_start(other, string.length("--colour="))
        _, True ->
          "--licence-text="
          <> string.drop_start(other, string.length("--license-text="))
        False, False -> other
      }
    }
  }
}

fn root_command() -> glint.Command(CliAction) {
  use show_version <- glint.flag(version_flag())
  report_command(
    fn(flags) {
      let assert Ok(value) = show_version(flags)
      value
    },
    fn(_) { Text },
  )
}

const check_help =
  "Enforce selected checks: licences (default), vulns, or all. Licence checks require a licence policy. Vulnerability-only checks do not evaluate licence policy or fetch licence metadata."

const report_help =
  "Report Hex package licences without enforcing policy findings. Operational failures exit 2. Use `check` to enforce a licence policy."

type CommonFlags {
  CommonFlags(
    manifest_path: Option(String),
    quiet: Bool,
    verbose: Bool,
    color_value: String,
  )
}

type ConfigFlags {
  ConfigFlags(config_path: Option(String), ignore_config: Bool)
}

type CacheFlags {
  CacheFlags(no_cache: Bool, cache_dir: Option(String))
}

fn common_flags(
  next: fn(fn(glint.Flags) -> CommonFlags) -> glint.Command(a),
) -> glint.Command(a) {
  use manifest <- glint.optional_flag(manifest_flag())
  use quiet <- glint.flag(quiet_flag())
  use verbose <- glint.flag(verbose_flag())
  use color_flag <- glint.flag(color_flag())
  next(fn(flags) {
    let assert Ok(manifest_path) = manifest(flags)
    let assert Ok(quiet) = quiet(flags)
    let assert Ok(verbose) = verbose(flags)
    let assert Ok(color_value) = color_flag(flags)
    CommonFlags(manifest_path:, quiet:, verbose:, color_value:)
  })
}

fn config_flags(
  next: fn(fn(glint.Flags) -> ConfigFlags) -> glint.Command(a),
) -> glint.Command(a) {
  use config <- glint.optional_flag(config_flag())
  use ignore_config <- glint.flag(ignore_config_flag())
  next(fn(flags) {
    let assert Ok(config_path) = config(flags)
    let assert Ok(ignore_config) = ignore_config(flags)
    ConfigFlags(config_path:, ignore_config:)
  })
}

fn cache_flags(
  next: fn(fn(glint.Flags) -> CacheFlags) -> glint.Command(a),
) -> glint.Command(a) {
  use no_cache <- glint.flag(no_cache_flag())
  use cache_dir <- glint.optional_flag(cache_dir_flag())
  next(fn(flags) {
    let assert Ok(no_cache) = no_cache(flags)
    let assert Ok(cache_dir) = cache_dir(flags)
    CacheFlags(no_cache:, cache_dir:)
  })
}

fn licence_flags(
  next: fn(
    fn(glint.Flags) -> #(CommonFlags, ConfigFlags, CacheFlags, DependencyScope),
  ) -> glint.Command(a),
) -> glint.Command(a) {
  use config <- config_flags()
  use common <- common_flags()
  use cache <- cache_flags()
  use scope <- glint.flag(scope_flag("all"))
  next(fn(flags) {
    let assert Ok(scope) = scope(flags)
    #(common(flags), config(flags), cache(flags), scope_from_string(scope))
  })
}

fn report_command(
  show_version: fn(glint.Flags) -> Bool,
  format: fn(glint.Flags) -> ReportFormat,
) -> glint.Command(CliAction) {
  use <- glint.command_help(report_help)
  use <- glint.unnamed_args(glint.EqArgs(0))
  use licence <- licence_flags()
  use _, _, flags <- glint.command()

  let #(common, config, cache, scope) = licence(flags)
  use <- validate_conflicts(
    config.config_path,
    config.ignore_config,
    cache.cache_dir,
    cache.no_cache,
  )
  case
    show_version(flags),
    verbosity(common.quiet, common.verbose),
    color.mode_from_string(common.color_value)
  {
    True, _, _ -> ShowVersion
    False, Error(verbosity_error), _ ->
      InvalidUsage(verbosity_error_message(verbosity_error))
    False, _, Error(color_error) ->
      InvalidUsage(color.mode_error_message(color_error))
    False, Ok(verbosity), Ok(color_mode) ->
      RunReport(ReportOptions(
        manifest_path: common.manifest_path,
        config_path: config.config_path,
        ignore_config: config.ignore_config,
        verbosity: verbosity,
        color: color_mode,
        no_cache: cache.no_cache,
        cache_dir: cache.cache_dir,
        scope: scope,
        format: format(flags),
      ))
  }
}

fn named_report_command() -> glint.Command(CliAction) {
  use format <- report_format_flags()
  report_command(fn(_) { False }, format)
}

fn report_format_flags(
  next: fn(fn(glint.Flags) -> ReportFormat) -> glint.Command(a),
) -> glint.Command(a) {
  use format <- glint.flag(
    glint.string_flag("format")
    |> glint.flag_value_name("text|json")
    |> glint.flag_default("text")
    |> glint.flag_constraint(constraint.one_of(format_values))
    |> glint.flag_help("Output format: text|json (default text)"),
  )
  next(fn(flags) {
    let assert Ok(value) = format(flags)
    let assert Ok(format) = report_format_from_string(value)
    format
  })
}

fn report_format_from_string(value: String) -> Result(ReportFormat, Nil) {
  case value {
    "text" -> Ok(Text)
    "json" -> Ok(Json)
    _ -> Error(Nil)
  }
}

fn check_command() -> glint.Command(CliAction) {
  use <- glint.command_help(check_help)
  use <- glint.unnamed_args(glint.EqArgs(0))
  use licence <- licence_flags()
  use format <- report_format_flags()
  use checks <- glint.flag(checks_flag())
  use vuln_severity <- glint.optional_flag(vuln_severity_flag())
  use vuln_block_unknown <- glint.optional_flag(vuln_block_unknown_flag())
  use _, _, flags <- glint.command()

  let #(common, config, cache, scope) = licence(flags)
  let assert Ok(checks_value) = checks(flags)
  let assert Ok(vuln_severity_value) = vuln_severity(flags)
  let assert Ok(vuln_block_unknown_value) = vuln_block_unknown(flags)
  let checks_value = case checks_value {
    "vulns" -> Vulnerabilities
    "all" -> AllChecks
    _ -> Licences
  }

  use <- validate_conflicts(
    config.config_path,
    config.ignore_config,
    cache.cache_dir,
    cache.no_cache,
  )
  case
    verbosity(common.quiet, common.verbose),
    color.mode_from_string(common.color_value),
    checks_value == Licences
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
        manifest_path: common.manifest_path,
        config_path: config.config_path,
        ignore_config: config.ignore_config,
        check: True,
        verbosity: verbosity,
        color: color_mode,
        no_cache: cache.no_cache,
        cache_dir: cache.cache_dir,
        checks: checks_value,
        vuln_severity: vuln_severity_value,
        vuln_block_unknown: vuln_block_unknown_value,
        scope: scope,
        format: format(flags),
      ))
  }
}

fn config_flag() -> glint.Flag(String) {
  glint.string_flag("config")
  |> glint.flag_value_name("PATH")
  |> glint.flag_help("Read configuration from PATH")
}

fn manifest_flag() -> glint.Flag(String) {
  glint.string_flag("manifest")
  |> glint.flag_value_name("PATH")
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
  |> glint.flag_value_name("auto|always|never")
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
  |> glint.flag_value_name("prod|all")
  |> glint.flag_default(default)
  |> glint.flag_constraint(constraint.one_of(scope_values))
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
  |> glint.flag_value_name("DIR")
  |> glint.flag_help(
    "Use DIR as the application cache root for all cache families",
  )
}

fn checks_flag() -> glint.Flag(String) {
  glint.string_flag("checks")
  |> glint.flag_value_name("licences|vulns|all")
  |> glint.flag_default("licences")
  |> glint.flag_constraint(constraint.one_of(check_values))
  |> glint.flag_help(
    "Select checks: licences|vulns|all (default licences); licences and all require a licence policy",
  )
}

fn vuln_severity_flag() -> glint.Flag(String) {
  glint.string_flag("vuln-severity")
  |> glint.flag_value_name("low|medium|high|critical")
  |> glint.flag_constraint(constraint.one_of(severity_values))
  |> glint.flag_help(
    "Minimum blocking vulnerability severity: low|medium|high|critical (overrides config; default high; requires --checks=vulns or --checks=all)",
  )
}

fn vuln_block_unknown_flag() -> glint.Flag(Bool) {
  glint.bool_flag("vuln-block-unknown")
  |> glint.flag_help(
    "Fail on advisories whose severity is unknown (true or false overrides config; default false; requires --checks=vulns or --checks=all)",
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

fn validate_conflicts(
  config_path: Option(String),
  ignore_config: Bool,
  cache_dir: Option(String),
  no_cache: Bool,
  next: fn() -> CliAction,
) -> CliAction {
  case
    option.is_some(config_path) && ignore_config,
    option.is_some(cache_dir) && no_cache
  {
    True, _ ->
      InvalidUsage("--config and --ignore-config cannot be used together")
    False, True ->
      InvalidUsage("--no-cache and --cache-dir cannot be used together")
    False, False -> next()
  }
}

fn update_command() -> glint.Command(CliAction) {
  use <- glint.command_help(
    "Interactively review discovered licences and write an updated [tools.licence_audit] policy to gleam.toml.",
  )
  use <- glint.unnamed_args(glint.EqArgs(0))
  use config <- glint.optional_flag(config_flag())
  use common <- common_flags()
  use cache <- cache_flags()
  use _, _, flags <- glint.command()

  let assert Ok(config_path) = config(flags)
  let common = common(flags)
  let cache = cache(flags)
  use <- validate_conflicts(config_path, False, cache.cache_dir, cache.no_cache)
  case
    verbosity(common.quiet, common.verbose),
    color.mode_from_string(common.color_value)
  {
    Error(verbosity_error), _ ->
      InvalidUsage(verbosity_error_message(verbosity_error))
    _, Error(color_error) -> InvalidUsage(color.mode_error_message(color_error))
    Ok(verbosity), Ok(color_mode) ->
      UpdateConfig(UpdateOptions(
        manifest_path: common.manifest_path,
        config_path: config_path,
        verbosity: verbosity,
        color: color_mode,
        no_cache: cache.no_cache,
        cache_dir: cache.cache_dir,
      ))
  }
}

fn output_flag(help: String) -> glint.Flag(String) {
  glint.string_flag("output")
  |> glint.flag_value_name("PATH")
  |> glint.flag_help(help)
}

fn offline_flag() -> glint.Flag(Bool) {
  glint.bool_flag("offline")
  |> glint.flag_default(False)
  |> glint.flag_help(
    "Prohibit network access; use local files and usable cached evidence. Required metadata, publication verification, and requested SPDX text must remain available",
  )
}

fn reproducible_flag() -> glint.Flag(Bool) {
  glint.bool_flag("reproducible")
  |> glint.flag_default(False)
  |> glint.flag_help(
    "Reproducible output from locked metadata, current local metadata, and publication evidence; serialNumber is a content hash and timestamp comes from SOURCE_DATE_EPOCH (default 1970-01-01T00:00:00Z)",
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
  use common <- common_flags()
  use cache <- cache_flags()
  use output <- glint.optional_flag(output_flag(
    "Write SBOM to PATH instead of stdout",
  ))
  use offline <- glint.flag(offline_flag())
  use reproducible <- glint.flag(reproducible_flag())
  use with_vulns <- glint.flag(sbom_vulns_flag())
  use license_text <- glint.flag(
    glint.bool_flag("licence-text")
    |> glint.flag_default(False)
    |> glint.flag_help(
      "Embed canonical SPDX text for recognised licence IDs (offline requires usable pinned text in the cache; alias: --license-text)",
    ),
  )
  use _, _, flags <- glint.command()

  let common = common(flags)
  let cache = cache(flags)
  let assert Ok(output_value) = output(flags)
  let assert Ok(offline_value) = offline(flags)
  let assert Ok(reproducible_value) = reproducible(flags)
  let assert Ok(with_vulns_value) = with_vulns(flags)
  let assert Ok(license_text_value) = license_text(flags)

  use <- validate_conflicts(option.None, False, cache.cache_dir, cache.no_cache)
  case
    verbosity(common.quiet, common.verbose),
    offline_value && with_vulns_value,
    reproducible_value && with_vulns_value,
    color.mode_from_string(common.color_value)
  {
    Error(verbosity_error), _, _, _ ->
      InvalidUsage(verbosity_error_message(verbosity_error))
    _, True, _, _ ->
      InvalidUsage(
        "--vulns requires network access and cannot be combined with --offline",
      )
    _, _, True, _ ->
      InvalidUsage(
        "--vulns uses mutable advisory data and cannot be combined with --reproducible",
      )
    _, _, _, Error(color_error) ->
      InvalidUsage(color.mode_error_message(color_error))
    Ok(verbosity), False, False, Ok(color_mode) ->
      RunSbom(SbomOptions(
        manifest_path: common.manifest_path,
        verbosity: verbosity,
        color: color_mode,
        no_cache: cache.no_cache,
        cache_dir: cache.cache_dir,
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
  use common <- common_flags()
  use config <- config_flags()
  use output <- glint.optional_flag(output_flag(
    "Write notices to PATH instead of stdout",
  ))
  use scope <- glint.flag(scope_flag("prod"))
  use cache <- cache_flags()
  use _, _, flags <- glint.command()

  let common = common(flags)
  let config = config(flags)
  let assert Ok(output_value) = output(flags)
  let assert Ok(scope_value) = scope(flags)
  let cache = cache(flags)

  use <- validate_conflicts(
    config.config_path,
    config.ignore_config,
    cache.cache_dir,
    cache.no_cache,
  )
  case
    verbosity(common.quiet, common.verbose),
    color.mode_from_string(common.color_value)
  {
    Error(verbosity_error), _ ->
      InvalidUsage(verbosity_error_message(verbosity_error))
    _, Error(color_error) -> InvalidUsage(color.mode_error_message(color_error))
    Ok(verbosity), Ok(color_mode) ->
      RunNotices(NoticesOptions(
        manifest_path: common.manifest_path,
        config_path: config.config_path,
        ignore_config: config.ignore_config,
        verbosity: verbosity,
        color: color_mode,
        output: output_value,
        scope: scope_from_string(scope_value),
        no_cache: cache.no_cache,
        cache_dir: cache.cache_dir,
      ))
  }
}

const vulns_help =
  "Report known vulnerabilities for locked dependencies using the OSV.dev database. Does not evaluate licence policy. Includes dev dependencies unless --scope=prod is set. Queries OSV directly and uses no on-disk cache."

fn vulns_command() -> glint.Command(CliAction) {
  use <- glint.command_help(vulns_help)
  use <- glint.unnamed_args(glint.EqArgs(0))
  use common <- common_flags()
  use config <- config_flags()
  use scope <- glint.flag(scope_flag("all"))
  use format <- report_format_flags()
  use _, _, flags <- glint.command()

  let common = common(flags)
  let config = config(flags)
  let assert Ok(scope_value) = scope(flags)

  use <- validate_conflicts(
    config.config_path,
    config.ignore_config,
    option.None,
    False,
  )
  case
    verbosity(common.quiet, common.verbose),
    color.mode_from_string(common.color_value)
  {
    Error(verbosity_error), _ ->
      InvalidUsage(verbosity_error_message(verbosity_error))
    _, Error(color_error) -> InvalidUsage(color.mode_error_message(color_error))
    Ok(verbosity), Ok(color_mode) ->
      RunVulns(VulnsOptions(
        manifest_path: common.manifest_path,
        config_path: config.config_path,
        ignore_config: config.ignore_config,
        verbosity: verbosity,
        color: color_mode,
        scope: scope_from_string(scope_value),
        format: format(flags),
      ))
  }
}
