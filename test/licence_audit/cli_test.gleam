import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleeunit/should
import glint
import licence_audit/cli
import licence_audit/color
import licence_audit/progress

fn parse_options(args: List(String)) -> cli.Options {
  let assert Ok(glint.Out(cli.RunAudit(options))) =
    glint.execute(cli.app(), cli.normalize_args(args))
  options
}

fn parse_update_options(args: List(String)) -> cli.UpdateOptions {
  let assert Ok(glint.Out(cli.UpdateConfig(options))) =
    glint.execute(cli.app(), cli.normalize_args(args))
  options
}

fn help_text(args: List(String)) -> String {
  let assert Ok(glint.Help(help)) =
    glint.execute(cli.app(), cli.normalize_args(args))
  help
}

fn usage_error(args: List(String)) -> String {
  let assert Error(message) = glint.execute(cli.app(), cli.normalize_args(args))
  message
}

pub fn help_long_option_returns_glint_help_test() {
  let help = help_text(["--help"])

  assert string.contains(help, "licence_audit")
  assert string.contains(help, "USAGE:")
}

pub fn short_help_option_returns_glint_help_test() {
  let help = help_text(["-h"])

  assert string.contains(help, "licence_audit")
  assert string.contains(help, "USAGE:")
}

pub fn check_subcommand_enables_check_mode_test() {
  let options = parse_options(["check"])

  should.equal(options.check, True)
}

pub fn comma_separated_allow_options_are_preserved_test() {
  let options = parse_options(["--allow=MIT,Apache-2.0"])

  should.equal(options.allow_licences, ["MIT", "Apache-2.0"])
}

pub fn comma_separated_deny_options_are_preserved_test() {
  let options = parse_options(["--deny=GPL-3.0-only,AGPL-3.0-only"])

  should.equal(options.deny_licences, ["GPL-3.0-only", "AGPL-3.0-only"])
}

pub fn default_report_mode_accepts_empty_policy_test() {
  let options = parse_options([])

  should.equal(options.allow_licences, [])
  should.equal(options.deny_licences, [])
  should.equal(options.check, False)
}

pub fn default_verbosity_is_normal_test() {
  let options = parse_options([])

  should.equal(options.verbosity, progress.Normal)
}

pub fn quiet_option_sets_quiet_verbosity_test() {
  let options = parse_options(["--quiet"])

  should.equal(options.verbosity, progress.Quiet)
}

pub fn verbose_option_sets_verbose_verbosity_test() {
  let options = parse_options(["--verbose"])

  should.equal(options.verbosity, progress.Verbose)
}

pub fn quiet_and_verbose_returns_invalid_usage_action_test() {
  let assert Ok(glint.Out(cli.InvalidUsage(message))) =
    glint.execute(cli.app(), ["--quiet", "--verbose"])

  assert string.contains(message, "--quiet")
  assert string.contains(message, "--verbose")
}

pub fn config_option_sets_config_path_test() {
  let options = parse_options(["--config=audit.toml"])

  should.equal(options.config_path, Some("audit.toml"))
}

pub fn manifest_option_sets_manifest_path_test() {
  let options = parse_options(["--manifest=manifest.toml"])

  should.equal(options.manifest_path, Some("manifest.toml"))
}

pub fn ignore_config_option_sets_flag_test() {
  let options = parse_options(["--ignore-config"])

  should.equal(options.ignore_config, True)
}

pub fn unknown_option_returns_glint_usage_error_test() {
  let message = usage_error(["--wat"])

  assert string.contains(message, "wat")
  assert string.contains(message, "USAGE:")
}

pub fn missing_allow_value_returns_usage_error_test() {
  let message = usage_error(["--allow"])

  assert string.contains(message, "allow")
}

pub fn american_deny_license_option_returns_usage_error_test() {
  let message = usage_error(["--deny-license=MIT"])

  assert string.contains(message, "deny-license")
}

pub fn missing_deny_value_returns_usage_error_test() {
  let message = usage_error(["--deny"])

  assert string.contains(message, "deny")
}

pub fn missing_config_value_returns_usage_error_test() {
  let message = usage_error(["--config"])

  assert string.contains(message, "config")
}

pub fn missing_manifest_value_returns_usage_error_test() {
  let message = usage_error(["--manifest"])

  assert string.contains(message, "manifest")
}

pub fn positional_argument_returns_usage_error_test() {
  let message = usage_error(["unexpected"])

  assert string.contains(message, "invalid number of arguments")
}

pub fn help_text_includes_usage_and_supported_options_test() {
  let help = help_text(["--help"])

  [
    "licence_audit",
    "--allow",
    "--deny",
    "--config",
    "--manifest",
    "--ignore-config",
    "--quiet",
    "--verbose",
    "--color",
    "--colour",
    "--no-cache",
    "--cache-path",
    "--help",
  ]
  |> list.each(fn(text) {
    assert string.contains(help, text)
  })
}

pub fn check_subcommand_is_listed_in_help_test() {
  let help = help_text(["--help"])

  assert string.contains(help, "check")
}

pub fn update_subcommand_is_listed_in_help_test() {
  let help = help_text(["--help"])

  assert string.contains(help, "update")
}

pub fn root_vulns_option_returns_usage_error_test() {
  let message = usage_error(["--vulns"])

  assert string.contains(message, "vulns")
}

pub fn root_vuln_severity_option_returns_usage_error_test() {
  let message = usage_error(["--vuln-severity=medium"])

  assert string.contains(message, "vuln-severity")
}

pub fn invalid_check_vuln_severity_returns_usage_error_test() {
  let message = usage_error(["check", "--vuln-severity=crit"])

  assert string.contains(message, "vuln-severity")
  assert string.contains(message, "crit")
}

pub fn update_subcommand_parses_defaults_test() {
  let options = parse_update_options(["update"])

  should.equal(options.manifest_path, None)
  should.equal(options.config_path, None)
  should.equal(options.ignore_config, False)
  should.equal(options.verbosity, progress.Normal)
  should.equal(options.color, color.Auto)
  should.equal(options.no_cache, False)
  should.equal(options.cache_path, None)
}

pub fn update_subcommand_parses_supported_flags_test() {
  let options =
    parse_update_options([
      "update",
      "--config=audit.toml",
      "--manifest=locked.toml",
      "--ignore-config",
      "--verbose",
      "--color=never",
      "--no-cache",
      "--cache-path=/tmp/licence-audit.dets",
    ])

  should.equal(options.config_path, Some("audit.toml"))
  should.equal(options.manifest_path, Some("locked.toml"))
  should.equal(options.ignore_config, True)
  should.equal(options.verbosity, progress.Verbose)
  should.equal(options.color, color.Never)
  should.equal(options.no_cache, True)
  should.equal(options.cache_path, Some("/tmp/licence-audit.dets"))
}

pub fn default_color_mode_is_auto_test() {
  let options = parse_options([])

  should.equal(options.color, color.Auto)
}

pub fn default_no_cache_is_false_test() {
  let options = parse_options([])

  should.equal(options.no_cache, False)
  should.equal(options.cache_path, None)
}

pub fn no_cache_flag_sets_no_cache_test() {
  let options = parse_options(["--no-cache"])

  should.equal(options.no_cache, True)
}

pub fn cache_path_flag_sets_cache_path_test() {
  let options = parse_options(["--cache-path=/tmp/foo.dets"])

  should.equal(options.cache_path, Some("/tmp/foo.dets"))
}

pub fn color_always_sets_always_mode_test() {
  let options = parse_options(["--color=always"])

  should.equal(options.color, color.Always)
}

pub fn colour_alias_always_sets_always_mode_test() {
  let options = parse_options(["--colour=always"])

  should.equal(options.color, color.Always)
}

pub fn color_never_sets_never_mode_test() {
  let options = parse_options(["--color=never"])

  should.equal(options.color, color.Never)
}

pub fn update_subcommand_accepts_colour_alias_test() {
  let options = parse_update_options(["update", "--colour=never"])

  should.equal(options.color, color.Never)
}

pub fn invalid_color_value_returns_invalid_usage_action_test() {
  let assert Ok(glint.Out(cli.InvalidUsage(message))) =
    glint.execute(cli.app(), ["--color=rainbow"])

  assert string.contains(message, "color")
  assert string.contains(message, "rainbow")
}

pub fn sbom_subcommand_parses_defaults_test() {
  let assert Ok(glint.Out(cli.RunSbom(options))) =
    glint.execute(cli.app(), ["sbom"])
  should.equal(options.output, None)
  should.equal(options.offline, False)
  should.equal(options.no_cache, False)
  should.equal(options.reproducible, False)
}

pub fn sbom_subcommand_parses_reproducible_flag_test() {
  let assert Ok(glint.Out(cli.RunSbom(options))) =
    glint.execute(cli.app(), ["sbom", "--reproducible"])
  should.equal(options.reproducible, True)
}

pub fn sbom_subcommand_parses_output_flag_test() {
  let assert Ok(glint.Out(cli.RunSbom(options))) =
    glint.execute(cli.app(), ["sbom", "--output=sbom.json"])
  should.equal(options.output, Some("sbom.json"))
}

pub fn sbom_subcommand_parses_offline_flag_test() {
  let assert Ok(glint.Out(cli.RunSbom(options))) =
    glint.execute(cli.app(), ["sbom", "--offline"])
  should.equal(options.offline, True)
}

pub fn sbom_subcommand_rejects_config_flag_test() {
  let message = usage_error(["sbom", "--config=gleam.toml"])

  assert string.contains(message, "config")
}

pub fn sbom_subcommand_rejects_ignore_config_flag_test() {
  let message = usage_error(["sbom", "--ignore-config"])

  assert string.contains(message, "ignore-config")
}
