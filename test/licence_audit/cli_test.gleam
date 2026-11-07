import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleeunit/should
import licence_audit/cli
import licence_audit/color
import licence_audit/internal/vendor/glint
import licence_audit/progress

const optional_path_flags = [
  #([], ["manifest", "config", "cache-path"]),
  #(["check"], ["manifest", "config", "cache-path"]),
  #(["update"], ["manifest", "config", "cache-path"]),
  #(["sbom"], ["manifest", "cache-path", "output"]),
  #(["notices"], ["manifest", "config", "cache-path", "output"]),
  #(["vulns"], ["manifest", "config"]),
]

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

fn parse_notices_options(args: List(String)) -> cli.NoticesOptions {
  let assert Ok(glint.Out(cli.RunNotices(options))) =
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

pub fn version_option_returns_version_action_test() {
  let assert Ok(glint.Out(cli.ShowVersion)) =
    glint.execute(cli.app(), ["--version"])
}

pub fn check_subcommand_enables_check_mode_test() {
  let options = parse_options(["check"])

  should.equal(options.check, True)
  should.equal(options.vuln_severity, None)
  should.equal(options.vuln_block_unknown, False)
}

pub fn optional_path_flags_preserve_absence_and_explicit_values_test() {
  use expected <- list.each([
    None,
    Some("custom/path.toml"),
    Some(""),
    Some("__licence_audit_absent_string_flag__"),
    Some("path=with=equals"),
  ])
  use command <- list.each(optional_path_flags)
  let #(command, names) = command
  let args = case expected {
    None -> command
    Some(value) ->
      list.append(
        command,
        list.map(names, fn(name) { "--" <> name <> "=" <> value }),
      )
  }
  let assert Ok(glint.Out(action)) = glint.execute(cli.app(), args)
  let paths = case action {
    cli.RunAudit(options) -> [
      options.manifest_path,
      options.config_path,
      options.cache_path,
    ]
    cli.UpdateConfig(options) -> [
      options.manifest_path,
      options.config_path,
      options.cache_path,
    ]
    cli.RunSbom(options) -> [
      options.manifest_path,
      options.cache_path,
      options.output,
    ]
    cli.RunNotices(options) -> [
      options.manifest_path,
      options.config_path,
      options.cache_path,
      options.output,
    ]
    cli.RunVulns(options) -> [options.manifest_path, options.config_path]
    cli.ShowVersion | cli.InvalidUsage(_) -> panic as "expected parsed options"
  }

  should.equal(paths, list.map(names, fn(_) { expected }))
}

pub fn optional_string_flags_still_require_values_when_supplied_test() {
  use command <- list.each([
    #(["check"], ["vuln-severity"]),
    ..optional_path_flags
  ])
  let #(command, names) = command
  use name <- list.each(names)
  let message = usage_error(list.append(command, ["--" <> name]))

  assert string.contains(message, name)
  assert string.contains(message, "has no assigned value")
}

pub fn check_vuln_block_unknown_option_enables_unknown_gate_test() {
  let options = parse_options(["check", "--vulns", "--vuln-block-unknown"])

  should.equal(options.vuln_block_unknown, True)
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

pub fn short_verbose_option_normalizes_to_verbose_test() {
  should.equal(cli.normalize_args(["-v"]), ["--verbose"])
}

pub fn short_verbose_option_sets_verbose_verbosity_test() {
  let options = parse_options(["-v"])

  should.equal(options.verbosity, progress.Verbose)
}

pub fn quiet_and_short_verbose_returns_invalid_usage_action_test() {
  let assert Ok(glint.Out(cli.InvalidUsage(message))) =
    glint.execute(cli.app(), cli.normalize_args(["--quiet", "-v"]))

  assert string.contains(message, "--quiet")
  assert string.contains(message, "--verbose")
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
    "--version",
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

pub fn notices_subcommand_is_listed_in_help_test() {
  let help = help_text(["--help"])

  assert string.contains(help, "notices")
}

pub fn internal_gen_docs_subcommand_is_not_listed_in_help_test() {
  let help = help_text(["--help"])

  assert !string.contains(help, "gen-docs")
}

pub fn notices_subcommand_help_describes_notice_output_test() {
  let help = help_text(["notices", "--help"])

  assert string.contains(help, "Write notices to PATH instead of stdout")
}

pub fn root_vulns_option_returns_usage_error_test() {
  let message = usage_error(["--vulns"])

  assert string.contains(message, "vulns")
}

pub fn root_vuln_severity_option_returns_usage_error_test() {
  let message = usage_error(["--vuln-severity=medium"])

  assert string.contains(message, "vuln-severity")
}

pub fn root_vuln_block_unknown_option_returns_usage_error_test() {
  let message = usage_error(["--vuln-block-unknown"])

  assert string.contains(message, "vuln-block-unknown")
}

pub fn vulns_vuln_block_unknown_option_returns_usage_error_test() {
  let message = usage_error(["vulns", "--vuln-block-unknown"])

  assert string.contains(message, "vuln-block-unknown")
}

pub fn invalid_check_vuln_severity_returns_usage_error_test() {
  use value <- list.each(["crit", "", "__licence_audit_absent_string_flag__"])
  let message = usage_error(["check", "--vuln-severity=" <> value])

  assert string.contains(message, "vuln-severity")
  assert string.contains(message, "must be one of")
}

pub fn check_vuln_severity_preserves_supported_values_test() {
  use severity <- list.each(["low", "medium", "high", "critical"])
  let options =
    parse_options(["check", "--vulns", "--vuln-severity=" <> severity])

  should.equal(options.vuln_severity, Some(severity))
}

pub fn check_vulnerability_flags_require_enabled_scan_test() {
  use flags <- list.each([
    ["--vuln-severity=critical"],
    ["--vuln-block-unknown"],
    ["--vuln-block-unknown=true"],
    ["--vuln-block-unknown=false"],
    ["--vuln-severity=high", "--vuln-block-unknown"],
  ])
  use scan <- list.each([[], ["--vulns=false"]])
  let assert Ok(glint.Out(cli.InvalidUsage(message))) =
    glint.execute(cli.app(), list.append(["check", ..scan], flags))
  assert string.contains(message, "require --vulns")
}

pub fn check_enabled_scan_preserves_explicit_boolean_values_test() {
  use value <- list.each([#("true", True), #("false", False)])
  let #(text, expected) = value
  use flags <- list.each([
    ["--vulns", "--vuln-block-unknown=" <> text],
    ["--vuln-block-unknown=" <> text, "--vulns=true"],
  ])
  let options = parse_options(["check", ..flags])
  should.equal(options.check_vulns, True)
  should.equal(options.vuln_block_unknown, expected)
}

pub fn vulnerability_gate_flags_remain_check_only_test() {
  use command <- list.each([[], ["update"], ["notices"], ["sbom"], ["vulns"]])
  use flag <- list.each(["--vuln-severity=high", "--vuln-block-unknown"])
  let message = usage_error(list.append(command, [flag]))
  assert string.contains(message, "vuln-")
  let message = usage_error(list.append(command, ["--vulns", flag]))
  assert string.contains(message, "vuln")
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

pub fn notices_subcommand_parses_defaults_test() {
  let options = parse_notices_options(["notices"])

  should.equal(options.manifest_path, None)
  should.equal(options.output, None)
  should.equal(options.include_dev, False)
  should.equal(options.verbosity, progress.Normal)
}

pub fn notices_subcommand_parses_supported_flags_test() {
  let options =
    parse_notices_options([
      "notices",
      "--manifest=locked.toml",
      "--output=THIRD_PARTY_LICENSES.txt",
      "--include-dev",
      "--verbose",
    ])

  should.equal(options.manifest_path, Some("locked.toml"))
  should.equal(options.output, Some("THIRD_PARTY_LICENSES.txt"))
  should.equal(options.include_dev, True)
  should.equal(options.verbosity, progress.Verbose)
}

pub fn notices_subcommand_accepts_ignored_no_cache_flag_test() {
  let options = parse_notices_options(["notices", "--no-cache"])

  should.equal(options.verbosity, progress.Normal)
}

pub fn notices_subcommand_rejects_quiet_and_verbose_test() {
  let assert Ok(glint.Out(cli.InvalidUsage(message))) =
    glint.execute(cli.app(), ["notices", "--quiet", "--verbose"])

  assert string.contains(message, "--quiet")
  assert string.contains(message, "--verbose")
}

pub fn notices_subcommand_accepts_config_controls_test() {
  let options =
    parse_notices_options(["notices", "--config=custom.toml", "--ignore-config"])
  should.equal(options.config_path, Some("custom.toml"))
  should.equal(options.ignore_config, True)
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
  should.equal(options.license_text, False)
}

pub fn sbom_license_text_allows_reproducible_but_rejects_offline_test() {
  let assert Ok(glint.Out(cli.RunSbom(options))) =
    glint.execute(cli.app(), ["sbom", "--license-text", "--reproducible"])
  should.equal(options.license_text, True)
  let assert Ok(glint.Out(cli.InvalidUsage(message))) =
    glint.execute(cli.app(), ["sbom", "--license-text", "--offline"])
  assert string.contains(message, "--license-text")
  assert string.contains(message, "--offline")
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

const commands = [[], ["check"], ["update"], ["sbom"], ["vulns"], ["notices"]]

pub fn shared_aliases_and_color_modes_work_on_all_commands_test() {
  use command <- list.each(commands)
  let help = help_text(list.append(command, ["-h"]))
  assert string.contains(help, "--quiet")
  assert string.contains(help, "-q")
  assert string.contains(help, "--colour")
  use verbosity <- list.each(["-q", "-v"])
  use mode <- list.each(["auto", "always", "never"])
  use spelling <- list.each(["--color=", "--colour="])
  let assert Ok(glint.Out(action)) =
    glint.execute(
      cli.app(),
      cli.normalize_args(list.append(command, [verbosity, spelling <> mode])),
    )
  let #(actual_verbosity, actual_color) = case action {
    cli.RunAudit(options) -> #(options.verbosity, options.color)
    cli.UpdateConfig(options) -> #(options.verbosity, options.color)
    cli.RunSbom(options) -> #(options.verbosity, options.color)
    cli.RunVulns(options) -> #(options.verbosity, options.color)
    cli.RunNotices(options) -> #(options.verbosity, options.color)
    cli.ShowVersion | cli.InvalidUsage(_) -> panic as "expected options"
  }
  should.equal(actual_verbosity, case verbosity {
    "-q" -> progress.Quiet
    _ -> progress.Verbose
  })
  should.equal(Ok(actual_color), color.mode_from_string(mode))
}

pub fn all_commands_reject_conflicting_aliases_and_invalid_colors_test() {
  use command <- list.each(commands)
  use flags <- list.each([["-q", "-v"], ["--colour=rainbow"]])
  let assert Ok(glint.Out(cli.InvalidUsage(_))) =
    glint.execute(cli.app(), cli.normalize_args(list.append(command, flags)))
}

pub fn command_specific_flag_matrix_test() {
  use entry <- list.each([
    #("--config=custom.toml", [True, True, True, False, True, True]),
    #("--ignore-config", [True, True, True, False, True, True]),
    #("--no-cache", [True, True, True, True, False, True]),
    #("--cache-path=custom.cache", [True, True, True, True, False, True]),
    #("--prod-only", [True, True, False, False, True, False]),
    #("--include-dev", [False, False, False, False, False, True]),
    #("--allow=MIT", [True, True, False, False, False, False]),
    #("--deny=MIT", [True, True, False, False, False, False]),
    #("--output=out", [False, False, False, True, False, True]),
    #("--vulns", [False, True, False, True, False, False]),
    #("--offline", [False, False, False, True, False, False]),
    #("--reproducible", [False, False, False, True, False, False]),
    #("--license-text", [False, False, False, True, False, False]),
    #("--version", [True, False, False, False, False, False]),
  ])
  use command <- list.each(list.zip(commands, entry.1))
  let result = glint.execute(cli.app(), list.append(command.0, [entry.0]))
  case command.1 {
    True -> {
      let assert Ok(glint.Out(_)) = result
    }
    False -> {
      let assert Error(_) = result
    }
  }
}

pub fn standalone_vulns_scope_defaults_and_flag_test() {
  use prod_only <- list.each([False, True])
  let flags = case prod_only {
    False -> []
    True -> ["--prod-only"]
  }
  let assert Ok(glint.Out(cli.RunVulns(options))) =
    glint.execute(cli.app(), list.append(["vulns"], flags))
  should.equal(options.prod_only, prod_only)
}
