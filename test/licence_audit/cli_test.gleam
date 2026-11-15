import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleeunit/should
import licence_audit/cli
import licence_audit/color
import licence_audit/internal/vendor/glint
import licence_audit/progress

const optional_path_flags = [
  #([], ["manifest", "config", "cache-dir"]),
  #(["report"], ["manifest", "config", "cache-dir"]),
  #(["check"], ["manifest", "config", "cache-dir"]),
  #(["update"], ["manifest", "config", "cache-dir"]),
  #(["sbom"], ["manifest", "cache-dir", "output"]),
  #(["notices"], ["manifest", "config", "cache-dir", "output"]),
  #(["vulns"], ["manifest", "config"]),
]

fn parse_options(args: List(String)) -> cli.Options {
  let assert Ok(glint.Out(action)) =
    glint.execute(cli.app(), cli.normalize_args(args))
  case action {
    cli.RunAudit(options) -> options
    cli.RunReport(options) ->
      cli.Options(
        manifest_path: options.manifest_path,
        config_path: options.config_path,
        allow_licences: options.allow_licences,
        deny_licences: options.deny_licences,
        ignore_config: options.ignore_config,
        check: False,
        verbosity: options.verbosity,
        color: options.color,
        no_cache: options.no_cache,
        cache_dir: options.cache_dir,
        checks: cli.Licences,
        vuln_severity: None,
        vuln_block_unknown: False,
        scope: options.scope,
      )
    _ -> panic as "expected report or check options"
  }
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
  should.equal(options.checks, cli.Licences)
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
    cli.RunReport(options) -> [
      options.manifest_path,
      options.config_path,
      options.cache_dir,
    ]
    cli.RunAudit(options) -> [
      options.manifest_path,
      options.config_path,
      options.cache_dir,
    ]
    cli.UpdateConfig(options) -> [
      options.manifest_path,
      options.config_path,
      options.cache_dir,
    ]
    cli.RunSbom(options) -> [
      options.manifest_path,
      options.cache_dir,
      options.output,
    ]
    cli.RunNotices(options) -> [
      options.manifest_path,
      options.config_path,
      options.cache_dir,
      options.output,
    ]
    cli.RunVulns(options) -> [options.manifest_path, options.config_path]
    cli.ShowVersion | cli.InvalidUsage(_) -> panic as "expected parsed options"
  }

  should.equal(paths, list.map(names, fn(_) { expected }))
}

pub fn optional_string_flags_still_require_values_when_supplied_test() {
  use command <- list.each([
    #(["check"], ["vuln-severity", "checks"]),
    ..optional_path_flags
  ])
  let #(command, names) = command
  use name <- list.each(names)
  let message = usage_error(list.append(command, ["--" <> name]))

  assert string.contains(message, name)
  assert string.contains(message, "has no assigned value")
}

pub fn path_values_that_look_like_aliases_are_preserved_test() {
  use value <- list.each(["-v", "-q", "-h", "--colour", "--colour=never"])
  use command <- list.each(optional_path_flags)
  let #(command, names) = command
  use name <- list.each(names)
  let separated = list.append(command, ["--" <> name, value, "-q"])
  let equals = list.append(command, ["--" <> name <> "=" <> value, "-q"])
  should.equal(cli.normalize_args(separated), cli.normalize_args(equals))
  let assert Ok(glint.Out(action)) =
    glint.execute(cli.app(), cli.normalize_args(separated))
  let #(paths, verbosity) = case action {
    cli.RunReport(options) -> #(
      [options.manifest_path, options.config_path, options.cache_dir],
      options.verbosity,
    )
    cli.RunAudit(options) -> #(
      [options.manifest_path, options.config_path, options.cache_dir],
      options.verbosity,
    )
    cli.UpdateConfig(options) -> #(
      [options.manifest_path, options.config_path, options.cache_dir],
      options.verbosity,
    )
    cli.RunSbom(options) -> #(
      [options.manifest_path, options.cache_dir, options.output],
      options.verbosity,
    )
    cli.RunNotices(options) -> #(
      [
        options.manifest_path,
        options.config_path,
        options.cache_dir,
        options.output,
      ],
      options.verbosity,
    )
    cli.RunVulns(options) -> #(
      [options.manifest_path, options.config_path],
      options.verbosity,
    )
    cli.ShowVersion | cli.InvalidUsage(_) -> panic as "expected parsed options"
  }
  should.equal(list.filter(paths, option.is_some), [Some(value)])
  should.equal(verbosity, progress.Quiet)
}

pub fn policy_values_that_look_like_aliases_are_preserved_test() {
  use value <- list.each(["-v", "-q", "-h", "--colour"])
  use command <- list.each([[], ["report"], ["check"]])
  use flags <- list.each([
    ["--allow", value, "--deny", value],
    ["--allow=" <> value, "--deny=" <> value],
  ])
  let options = parse_options(list.append(command, list.append(flags, ["-v"])))
  should.equal(options.allow_licences, [value])
  should.equal(options.deny_licences, [value])
  should.equal(options.verbosity, progress.Verbose)
}

pub fn constrained_values_that_look_like_aliases_remain_invalid_values_test() {
  use value <- list.each(["-v", "-q", "-h", "--colour"])
  use flag <- list.each([
    "--color",
    "--colour",
    "--vuln-severity",
    "--checks",
    "--scope",
  ])
  let command = case flag {
    "--checks" -> ["check"]
    _ -> ["check", "--checks=all"]
  }
  let args = list.append(command, [flag, value])
  let normalized = cli.normalize_args(args)
  let canonical = case flag {
    "--colour" -> "--color"
    _ -> flag
  }
  should.equal(normalized, list.append(command, [canonical <> "=" <> value]))
  should.equal(
    cli.normalize_args(list.append(command, [flag <> "=" <> value])),
    normalized,
  )
  case glint.execute(cli.app(), normalized) {
    Ok(glint.Out(cli.InvalidUsage(message))) -> {
      assert string.contains(message, value)
    }
    Error(message) -> {
      assert string.contains(message, "must be one of")
    }
    _ -> panic as "expected an invalid value, not help or parsed options"
  }
}

pub fn equals_values_do_not_consume_the_next_alias_test() {
  let options =
    parse_options(["--manifest=-h", "--config=--colour", "--allow=-q", "-v"])
  should.equal(options.manifest_path, Some("-h"))
  should.equal(options.config_path, Some("--colour"))
  should.equal(options.allow_licences, ["-q"])
  should.equal(options.verbosity, progress.Verbose)
}

pub fn separated_colour_alias_accepts_a_value_test() {
  let options = parse_options(["--colour", "never", "-q"])
  should.equal(options.color, color.Never)
  should.equal(options.verbosity, progress.Quiet)
}

pub fn missing_colour_alias_value_returns_usage_error_test() {
  let message = usage_error(["--colour"])
  assert string.contains(message, "color")
  assert string.contains(message, "has no assigned value")
}

pub fn separators_remain_unsupported_and_do_not_rewrite_aliases_test() {
  should.equal(cli.normalize_args(["--", "-h", "--colour"]), [
    "--",
    "-h",
    "--colour",
  ])
  let message = usage_error(["--", "-h"])
  assert string.contains(message, "flag provided but not defined")
  let args = ["sbom", "--output", "--", "-v"]
  should.equal(cli.normalize_args(args), args)
  let message = usage_error(args)
  assert string.contains(message, "output")
  assert string.contains(message, "has no assigned value")
}

pub fn check_vuln_block_unknown_option_enables_unknown_gate_test() {
  let options = parse_options(["check", "--checks=all", "--vuln-block-unknown"])

  should.equal(options.vuln_block_unknown, True)
}

pub fn comma_separated_allow_options_are_preserved_test() {
  let options = parse_options(["report", "--allow=MIT,Apache-2.0"])

  should.equal(options.allow_licences, ["MIT", "Apache-2.0"])
}

pub fn comma_separated_deny_options_are_preserved_test() {
  let options = parse_options(["report", "--deny=GPL-3.0-only,AGPL-3.0-only"])

  should.equal(options.deny_licences, ["GPL-3.0-only", "AGPL-3.0-only"])
}

pub fn default_report_mode_accepts_empty_policy_test() {
  let options = parse_options(["report"])

  should.equal(options.allow_licences, [])
  should.equal(options.deny_licences, [])
  should.equal(options.check, False)
}

pub fn default_verbosity_is_normal_test() {
  let options = parse_options(["report"])

  should.equal(options.verbosity, progress.Normal)
}

pub fn quiet_option_sets_quiet_verbosity_test() {
  let options = parse_options(["report", "--quiet"])

  should.equal(options.verbosity, progress.Quiet)
}

pub fn verbose_option_sets_verbose_verbosity_test() {
  let options = parse_options(["report", "--verbose"])

  should.equal(options.verbosity, progress.Verbose)
}

pub fn short_verbose_option_normalizes_to_verbose_test() {
  should.equal(cli.normalize_args(["-v"]), ["--verbose"])
}

pub fn short_verbose_option_sets_verbose_verbosity_test() {
  let options = parse_options(["report", "-v"])

  should.equal(options.verbosity, progress.Verbose)
}

pub fn quiet_and_short_verbose_returns_invalid_usage_action_test() {
  let assert Ok(glint.Out(cli.InvalidUsage(message))) =
    glint.execute(cli.app(), cli.normalize_args(["report", "--quiet", "-v"]))

  assert string.contains(message, "--quiet")
  assert string.contains(message, "--verbose")
}

pub fn quiet_and_verbose_returns_invalid_usage_action_test() {
  let assert Ok(glint.Out(cli.InvalidUsage(message))) =
    glint.execute(cli.app(), ["report", "--quiet", "--verbose"])

  assert string.contains(message, "--quiet")
  assert string.contains(message, "--verbose")
}

pub fn config_option_sets_config_path_test() {
  let options = parse_options(["report", "--config=audit.toml"])

  should.equal(options.config_path, Some("audit.toml"))
}

pub fn manifest_option_sets_manifest_path_test() {
  let options = parse_options(["report", "--manifest=manifest.toml"])

  should.equal(options.manifest_path, Some("manifest.toml"))
}

pub fn ignore_config_option_sets_flag_test() {
  let options = parse_options(["report", "--ignore-config"])

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
  let help = help_text(["report", "--help"])

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
    "--cache-dir",
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
    parse_options(["check", "--checks=all", "--vuln-severity=" <> severity])

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
  use scan <- list.each([[], ["--checks=licences"]])
  let assert Ok(glint.Out(cli.InvalidUsage(message))) =
    glint.execute(cli.app(), list.append(["check", ..scan], flags))
  assert string.contains(message, "require --checks=vulns or --checks=all")
}

pub fn check_enabled_scan_preserves_explicit_boolean_values_test() {
  use value <- list.each([#("true", True), #("false", False)])
  let #(text, expected) = value
  use flags <- list.each([
    ["--checks=all", "--vuln-block-unknown=" <> text],
    ["--vuln-block-unknown=" <> text, "--checks=vulns"],
  ])
  let options = parse_options(["check", ..flags])
  assert options.checks != cli.Licences
  should.equal(options.vuln_block_unknown, expected)
}

pub fn vulnerability_gate_flags_remain_check_only_test() {
  use command <- list.each([
    [],
    ["report"],
    ["update"],
    ["notices"],
    ["sbom"],
    ["vulns"],
  ])
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
  should.equal(options.verbosity, progress.Normal)
  should.equal(options.color, color.Auto)
  should.equal(options.no_cache, False)
  should.equal(options.cache_dir, None)
}

pub fn update_subcommand_parses_supported_flags_test() {
  let options =
    parse_update_options([
      "update",
      "--config=audit.toml",
      "--manifest=locked.toml",
      "--verbose",
      "--color=never",
      "--no-cache",
      "--cache-dir=build/cache-é中",
    ])

  should.equal(options.config_path, Some("audit.toml"))
  should.equal(options.manifest_path, Some("locked.toml"))
  should.equal(options.verbosity, progress.Verbose)
  should.equal(options.color, color.Never)
  should.equal(options.no_cache, True)
  should.equal(options.cache_dir, Some("build/cache-é中"))
}

pub fn update_rejects_ignore_config_forms_but_read_only_commands_keep_them_test() {
  list.each(
    [
      ["--ignore-config"],
      ["--ignore-config=true"],
      ["--ignore-config=false"],
      ["--ignore-config="],
      ["--ignore-config", "true"],
      ["--ignore-config", "false"],
    ],
    fn(flags) {
      let message = usage_error(["update", ..flags])
      assert string.contains(message, "ignore-config")
    },
  )
  list.each([[], ["check"], ["vulns"], ["notices"]], fn(command) {
    list.each(
      ["--ignore-config", "--ignore-config=true", "--ignore-config=false"],
      fn(flag) {
        let assert Ok(glint.Out(_)) =
          glint.execute(cli.app(), list.append(command, [flag]))
      },
    )
  })
}

pub fn default_color_mode_is_auto_test() {
  let options = parse_options(["report"])

  should.equal(options.color, color.Auto)
}

pub fn default_no_cache_is_false_test() {
  let options = parse_options(["report"])

  should.equal(options.no_cache, False)
  should.equal(options.cache_dir, None)
}

pub fn no_cache_flag_sets_no_cache_test() {
  let options = parse_options(["report", "--no-cache"])

  should.equal(options.no_cache, True)
}

pub fn cache_dir_flag_sets_application_root_test() {
  use command <- list.each([[], ["report"], ["check"]])
  let options =
    parse_options(list.append(command, ["--cache-dir=build/cache-é中"]))
  should.equal(options.cache_dir, Some("build/cache-é中"))
}

pub fn all_commands_reject_removed_cache_path_test() {
  use command <- list.each([[], ..commands])
  use flag <- list.each(["--cache-path", "--cache-path=old-cache"])
  let assert Error(_) = glint.execute(cli.app(), list.append(command, [flag]))
  assert !string.contains(
    help_text(list.append(command, ["--help"])),
    "--cache-path",
  )
}

pub fn color_always_sets_always_mode_test() {
  let options = parse_options(["report", "--color=always"])

  should.equal(options.color, color.Always)
}

pub fn colour_alias_always_sets_always_mode_test() {
  let options = parse_options(["report", "--colour=always"])

  should.equal(options.color, color.Always)
}

pub fn color_never_sets_never_mode_test() {
  let options = parse_options(["report", "--color=never"])

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
  should.equal(options.scope, cli.Prod)
  should.equal(options.verbosity, progress.Normal)
}

pub fn notices_subcommand_parses_supported_flags_test() {
  let options =
    parse_notices_options([
      "notices",
      "--manifest=locked.toml",
      "--output=THIRD_PARTY_LICENSES.txt",
      "--scope=all",
      "--verbose",
    ])

  should.equal(options.manifest_path, Some("locked.toml"))
  should.equal(options.output, Some("THIRD_PARTY_LICENSES.txt"))
  should.equal(options.scope, cli.All)
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
    glint.execute(cli.app(), ["report", "--color=rainbow"])

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

pub fn sbom_licence_text_spellings_preserve_boolean_values_test() {
  use spelling <- list.each(["--licence-text", "--license-text"])
  use value <- list.each([#("", True), #("=true", True), #("=false", False)])
  let #(suffix, expected) = value
  let assert Ok(glint.Out(cli.RunSbom(options))) =
    glint.execute(cli.app(), cli.normalize_args(["sbom", spelling <> suffix]))
  should.equal(options.license_text, expected)
}

pub fn sbom_licence_text_spellings_reject_malformed_booleans_test() {
  use spelling <- list.each(["--licence-text", "--license-text"])
  use value <- list.each(["", "yes", "1", "true=false"])
  let message = usage_error(["sbom", spelling <> "=" <> value])
  assert string.contains(message, "licence-text")
  assert string.contains(message, "cannot parse")
}

pub fn sbom_licence_text_mixed_spellings_follow_repeated_flag_behavior_test() {
  use first <- list.each(["", "=true", "=false"])
  use second <- list.each(["", "=true", "=false"])
  let assert Ok(glint.Out(cli.RunSbom(expected))) =
    glint.execute(cli.app(), [
      "sbom",
      "--licence-text" <> first,
      "--licence-text" <> second,
    ])
  use spellings <- list.each([
    #("--licence-text", "--license-text"),
    #("--license-text", "--licence-text"),
    #("--license-text", "--license-text"),
  ])
  let assert Ok(glint.Out(cli.RunSbom(actual))) =
    glint.execute(
      cli.app(),
      cli.normalize_args([
        "sbom",
        spellings.0 <> first,
        spellings.1 <> second,
      ]),
    )
  should.equal(actual, expected)
}

pub fn sbom_licence_text_alias_does_not_rewrite_flag_values_test() {
  use value <- list.each([
    "--license-text",
    "--license-text=true",
    "--license-text=false",
    "prefix--license-text",
  ])
  use flags <- list.each([
    ["--output=" <> value],
    ["--output", value],
  ])
  let assert Ok(glint.Out(cli.RunSbom(options))) =
    glint.execute(cli.app(), cli.normalize_args(["sbom", ..flags]))
  should.equal(options.output, Some(value))
  should.equal(options.license_text, False)
}

pub fn sbom_licence_text_help_lists_primary_and_supported_alias_test() {
  let help = help_text(["sbom", "--help"])
  assert string.contains(help, "--licence-text")
  assert string.contains(help, "alias: --license-text")
}

pub fn sbom_licence_text_spellings_allow_reproducible_and_offline_test() {
  use spelling <- list.each(["--licence-text", "--license-text"])
  use suffix <- list.each(["", "=true"])
  use flags <- list.each([
    ["--reproducible"],
    ["--offline"],
    ["--reproducible", "--offline"],
  ])
  let assert Ok(glint.Out(cli.RunSbom(options))) =
    glint.execute(
      cli.app(),
      cli.normalize_args(["sbom", spelling <> suffix, ..flags]),
    )
  should.equal(options.license_text, True)
  let assert Ok(glint.Out(cli.RunSbom(options))) =
    glint.execute(
      cli.app(),
      cli.normalize_args(["sbom", spelling <> "=false", "--offline"]),
    )
  should.equal(options.license_text, False)
  should.equal(options.offline, True)
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

const commands = [
  ["report"],
  ["check"],
  ["update"],
  ["sbom"],
  ["vulns"],
  ["notices"],
]

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
    cli.RunReport(options) -> #(options.verbosity, options.color)
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
    #("--ignore-config", [True, True, False, False, True, True]),
    #("--no-cache", [True, True, True, True, False, True]),
    #("--cache-dir=custom.cache", [True, True, True, True, False, True]),
    #("--scope=prod", [True, True, False, False, True, True]),
    #("--scope=all", [True, True, False, False, True, True]),
    #("--allow=MIT", [True, True, False, False, False, False]),
    #("--deny=MIT", [True, True, False, False, False, False]),
    #("--output=out", [False, False, False, True, False, True]),
    #("--vulns", [False, False, False, True, False, False]),
    #("--checks=all", [False, True, False, False, False, False]),
    #("--offline", [False, False, False, True, False, False]),
    #("--reproducible", [False, False, False, True, False, False]),
    #("--licence-text", [False, False, False, True, False, False]),
    #("--license-text", [False, False, False, True, False, False]),
    #("--version", [False, False, False, False, False, False]),
  ])
  use command <- list.each(list.zip(commands, entry.1))
  let result =
    glint.execute(
      cli.app(),
      cli.normalize_args(list.append(command.0, [entry.0])),
    )
  case command.1 {
    True -> {
      let assert Ok(glint.Out(_)) = result
    }
    False -> {
      let assert Error(_) = result
    }
  }
}

pub fn dependency_scope_defaults_and_values_test() {
  use command <- list.each([[], ["report"], ["check"], ["vulns"], ["notices"]])
  use flags <- list.each([
    [],
    ["--scope=prod"],
    ["--scope=all"],
    ["--scope", "prod"],
    ["--scope", "all"],
  ])
  let assert Ok(glint.Out(action)) =
    glint.execute(cli.app(), cli.normalize_args(list.append(command, flags)))
  let scope = case action {
    cli.RunReport(options) -> options.scope
    cli.RunAudit(options) -> options.scope
    cli.RunVulns(options) -> options.scope
    cli.RunNotices(options) -> options.scope
    cli.UpdateConfig(_)
    | cli.RunSbom(_)
    | cli.ShowVersion
    | cli.InvalidUsage(_) -> panic as "expected scoped command"
  }
  should.equal(scope, case flags, command {
    ["--scope=prod"], _ | ["--scope", "prod"], _ | [], ["notices"] -> cli.Prod
    _, _ -> cli.All
  })
}

pub fn dependency_scope_rejects_missing_and_invalid_values_test() {
  use command <- list.each([[], ["report"], ["check"], ["vulns"], ["notices"]])
  use flag <- list.each([
    "--scope",
    "--scope=",
    "--scope=dev",
    "--scope=Prod",
    "--scope=true",
    "--scope=false",
  ])
  let message = usage_error(list.append(command, [flag]))
  assert string.contains(message, "scope")
}

pub fn removed_dependency_flags_are_rejected_on_all_commands_test() {
  use command <- list.each([[], ..commands])
  use name <- list.each(["prod-only", "include-dev"])
  use suffix <- list.each(["", "=true", "=false"])
  let message = usage_error(list.append(command, ["--" <> name <> suffix]))
  assert string.contains(message, name)
  assert !string.contains(
    help_text(list.append(command, ["--help"])),
    "--" <> name,
  )
}

pub fn check_selection_accepts_only_supported_values_test() {
  list.each(
    [
      #("licences", cli.Licences),
      #("vulns", cli.Vulnerabilities),
      #("all", cli.AllChecks),
    ],
    fn(selection) {
      use flags <- list.each([
        ["--checks=" <> selection.0],
        ["--checks", selection.0],
      ])
      let options = parse_options(["check", ..flags])
      should.equal(options.checks, selection.1)
    },
  )
  use value <- list.each([
    "",
    "licenses",
    "none",
    "true",
    "ALL",
    "licences,vulns",
  ])
  let message = usage_error(["check", "--checks=" <> value])
  assert string.contains(message, "checks")
  assert string.contains(message, "must be one of")
}

pub fn removed_check_vulns_flag_and_help_test() {
  list.each(["--vulns", "--vulns=true", "--vulns=false"], fn(flag) {
    assert string.contains(usage_error(["check", flag]), "vulns")
  })
  let help = help_text(["check", "--help"])
  assert string.contains(help, "--checks")
  assert !string.contains(help, "--vulns")
}

pub fn bare_root_matches_named_report_and_lists_report_test() {
  should.equal(parse_options([]), parse_options(["report"]))
  let help = help_text(["--help"])
  assert string.contains(help, "report")
  assert !string.contains(help, "audit --")
  assert string.contains(help, "--no-cache")
  assert string.contains(help, "--allow")
}

pub fn root_scan_options_match_named_report_test() {
  use flags <- list.each([
    ["--manifest=missing.toml"],
    ["--config=missing.toml"],
    ["--ignore-config"],
    ["--allow=MIT"],
    ["--deny=MIT"],
    ["--scope=prod"],
    ["--scope=all"],
    ["--cache-dir=cache"],
    ["--no-cache"],
    ["--quiet"],
    ["--verbose"],
    ["--color=never"],
  ])
  should.equal(
    parse_options(flags),
    parse_options(list.append(["report"], flags)),
  )
}

pub fn audit_alias_remains_unsupported_test() {
  let message = usage_error(["audit"])
  assert string.contains(message, "invalid number of arguments")
}
