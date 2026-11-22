import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleeunit/should
import licence_audit/cli
import licence_audit/color
import licence_audit/internal/vendor/glint
import licence_audit/progress
import tty

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
  let assert Error(message) = cli.execute(args, tty.NoColor, tty.NoColor)
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

pub fn help_value_forms_match_each_command_declaration_test() -> Nil {
  let tree = glint.document(cli.app())
  use command <- list.each([tree, ..tree.subcommands])
  let args = case command.meta.name {
    "licence_audit" -> ["--help"]
    name -> [name, "--help"]
  }
  let help = help_text(args)
  assert !string.contains(help, "<BOOL>")
  assert !string.contains(help, "<STRING>")
  use flag <- list.each(command.flags)
  let value_name = case flag.meta.name {
    "config" | "manifest" | "output" -> "PATH"
    "cache-dir" -> "DIR"
    "color" -> "auto|always|never"
    "scope" -> "prod|all"
    "checks" -> "licences|vulns|all"
    "vuln-severity" -> "low|medium|high|critical"
    "format" -> "text|json"
    _ -> "BOOL"
  }
  should.equal(flag.type_, value_name)
  let name = "--" <> flag.meta.name
  case value_name {
    "BOOL" -> {
      assert !string.contains(help, name <> "=")
    }
    value -> {
      assert string.contains(help, name <> "=<" <> value <> ">")
    }
  }
}

pub fn root_lists_one_sentence_per_command_and_keeps_long_help_test() -> Nil {
  let tree = glint.document(cli.app())
  let root = help_text(["--help"])
  let assert Ok(#(_, subcommands)) = string.split_once(root, "SUBCOMMANDS:")
  let lines =
    subcommands
    |> string.split("\n")
    |> list.filter(fn(line) { string.trim(line) != "" })
  should.equal(list.length(lines), list.length(tree.subcommands))
  use command <- list.each(tree.subcommands)
  let summary = case string.split_once(command.meta.description, ". ") {
    Ok(#(sentence, _)) -> sentence <> "."
    Error(_) -> command.meta.description
  }
  assert list.any(lines, fn(line) {
    string.starts_with(string.trim(line), command.meta.name <> " ")
    && string.ends_with(line, summary)
  })
  let help = help_text([command.meta.name, "--help"])
  let normalized = help |> string.split("\n") |> string.join(" ")
  assert string.starts_with(normalized, summary)
  assert !string.contains(help, "Report locked dependency licences by default")
  assert string.contains(help, "Command: " <> command.meta.name)
  let description =
    command.meta.description |> string.split("\n") |> string.join(" ")
  assert string.contains(normalized, description)
}

pub fn help_and_usage_colors_follow_destination_levels_test() {
  use #(args, help) <- list.each([
    #(["--help"], True),
    #(["-h"], True),
    #(["check", "-h"], True),
    #(["--unknown"], False),
    #(["check", "--manifest"], False),
    #(["bogus", "--help"], False),
    #(["check", "extra", "-h"], False),
  ])
  use #(stdout, stderr) <- list.each([
    #(tty.NoColor, tty.NoColor),
    #(tty.NoColor, tty.TrueColor),
    #(tty.TrueColor, tty.NoColor),
    #(tty.TrueColor, tty.TrueColor),
  ])
  use #(flags, mode) <- list.each([
    #([], color.Auto),
    #(["--color=auto"], color.Auto),
    #(["--colour", "ALWAYS"], color.Always),
    #(["--colour=never"], color.Never),
    #(["--color", "always", "--colour=never"], color.Never),
    #(["--colour=never", "--color", "always"], color.Always),
  ])
  let result = cli.execute(list.append(flags, args), stdout, stderr)
  let text = case result {
    Ok(glint.Help(text)) if help -> text
    Error(text) if !help -> text
    _ -> panic as "expected help on the original destination"
  }
  let level = case help {
    True -> stdout
    False -> stderr
  }
  should.equal(
    string.contains(text, "\u{1b}"),
    color.resolve_with_color_level(mode, level).enabled,
  )
  case help {
    True -> {
      assert string.contains(text, "USAGE:")
    }
    False -> {
      assert string.contains(text, "Error:")
    }
  }
}

pub fn help_color_scan_does_not_read_option_values_as_flags_test() {
  use #(command, names) <- list.each(optional_path_flags)
  use name <- list.each(names)
  use value <- list.each(["--color=always", "--colour=always", "--colour"])
  use flags <- list.each([
    ["--" <> name, value],
    ["--" <> name <> "=" <> value],
  ])
  let args = list.append(command, flags)
  let assert Ok(glint.Help(help)) =
    cli.execute(list.append(args, ["-h"]), tty.NoColor, tty.TrueColor)
  assert !string.contains(help, "\u{1b}")
  should.equal(
    cli.execute(args, tty.TrueColor, tty.TrueColor),
    glint.execute(cli.app(), cli.normalize_args(args)),
  )
  let assert Error(message) =
    cli.execute(list.append(args, ["--unknown"]), tty.TrueColor, tty.NoColor)
  assert !string.contains(message, "\u{1b}")
}

pub fn help_color_preserves_invalid_actions_and_separator_behavior_test() {
  use args <- list.each([
    ["report", "--color=rainbow"],
    ["--colour"],
    ["--", "--colour=always"],
    ["--color=never", "--", "--colour=always"],
    ["--quiet", "--verbose"],
  ])
  let message = usage_error(args)
  assert string.starts_with(message, "Error:")
  assert string.contains(message, " --help' for usage.")
  assert !string.contains(message, "USAGE:")
}

pub fn color_before_separator_still_controls_usage_help_test() {
  let assert Error(message) =
    cli.execute(
      ["--color=always", "--", "--colour=never"],
      tty.NoColor,
      tty.NoColor,
    )
  assert string.contains(message, "the '--' separator is not supported")
  assert string.contains(message, "\u{1b}")
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
  should.equal(options.vuln_block_unknown, None)
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
  assert string.contains(message, "requires a value")
}

pub fn path_values_that_look_like_aliases_are_preserved_test() {
  use value <- list.each([
    "-v", "-q", "-h", "--help", "--colour", "--colour=never", "check", "--allow",
    "--prod-only",
  ])
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
    parse_options([
      "--manifest=-h",
      "--config=--colour",
      "--cache-dir=-q",
      "-v",
    ])
  should.equal(options.manifest_path, Some("-h"))
  should.equal(options.config_path, Some("--colour"))
  should.equal(options.cache_dir, Some("-q"))
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
  assert string.contains(message, "requires a value")
}

pub fn separators_remain_unsupported_and_do_not_rewrite_aliases_test() {
  should.equal(cli.normalize_args(["--", "-h", "--colour"]), [
    "--",
    "-h",
    "--colour",
  ])
  let message = usage_error(["--", "-h"])
  assert string.contains(message, "the '--' separator is not supported")
  let args = ["sbom", "--output", "--", "-v"]
  should.equal(cli.normalize_args(args), args)
  let message = usage_error(args)
  assert string.contains(message, "output")
  assert string.contains(message, "requires a value")
}

pub fn check_vuln_block_unknown_option_enables_unknown_gate_test() {
  let options = parse_options(["check", "--checks=all", "--vuln-block-unknown"])

  should.equal(options.vuln_block_unknown, Some(True))
}

pub fn removed_policy_flags_reject_all_forms_test() -> Nil {
  use command <- list.each([
    [],
    ["report"],
    ["check"],
    ["check", "--checks=all"],
    ["check", "--checks=vulns"],
  ])
  use name <- list.each(["allow", "deny"])
  use flags <- list.each([
    ["--" <> name],
    ["--" <> name <> "="],
    ["--" <> name <> "=MIT"],
    ["--" <> name <> "=MIT,Apache-2.0"],
    ["--" <> name, "MIT"],
    ["--" <> name, ""],
  ])
  let message = usage_error(list.append(command, flags))
  assert string.contains(message, "unknown flag")
  assert string.contains(message, name)
}

pub fn default_report_mode_accepts_empty_policy_test() {
  let options = parse_options(["report"])

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
  assert string.contains(message, "Run 'licence_audit --help' for usage.")
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

  assert string.contains(message, "unknown command 'unexpected'")
}

pub fn help_text_includes_usage_and_supported_options_test() {
  let help = help_text(["report", "--help"])

  [
    "licence_audit",
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
  assert string.contains(message, "expected low or medium or high or critical")
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
  use scan <- list.each([
    [],
    ["--checks=licences"],
    ["--checks=licenses"],
    ["--checks", "licenses"],
  ])
  let assert Ok(glint.Out(cli.InvalidUsage(message))) =
    glint.execute(
      cli.app(),
      cli.normalize_args(list.append(["check", ..scan], flags)),
    )
  assert string.contains(message, "require --checks=vulns or --checks=all")
}

pub fn check_enabled_scan_preserves_optional_boolean_values_test() {
  use #(flags, expected) <- list.each([
    #([], None),
    #(["--vuln-block-unknown"], Some(True)),
    #(["--vuln-block-unknown=true"], Some(True)),
    #(["--vuln-block-unknown=false"], Some(False)),
  ])
  use selection <- list.each(["all", "vulns"])
  use flags <- list.each([
    ["--checks=" <> selection, ..flags],
    list.append(flags, ["--checks=" <> selection]),
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
      "--no-cache=false",
      "--cache-dir=build/cache-é中",
    ])

  should.equal(options.config_path, Some("audit.toml"))
  should.equal(options.manifest_path, Some("locked.toml"))
  should.equal(options.verbosity, progress.Verbose)
  should.equal(options.color, color.Never)
  should.equal(options.no_cache, False)
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
    parse_notices_options([
      "notices",
      "--config=custom.toml",
      "--ignore-config=false",
    ])
  should.equal(options.config_path, Some("custom.toml"))
  should.equal(options.ignore_config, False)
}

pub fn config_conflicts_use_effective_boolean_values_on_all_commands_test() {
  use command <- list.each([[], ["report"], ["check"], ["notices"], ["vulns"]])
  use path <- list.each(["policy.toml", ""])
  use flags <- list.each([
    ["--ignore-config"],
    ["--ignore-config=true"],
    ["--ignore-config=false", "--ignore-config=true"],
  ])
  use args <- list.each([
    list.append(command, ["--config=" <> path, ..flags]),
    list.append(list.append(command, flags), ["--config", path]),
  ])
  let assert Ok(glint.Out(cli.InvalidUsage(message))) =
    glint.execute(cli.app(), cli.normalize_args(args))
  should.equal(message, "--config and --ignore-config cannot be used together")
}

pub fn cache_conflicts_use_effective_boolean_values_on_all_commands_test() {
  use command <- list.each([
    [],
    ["report"],
    ["check"],
    ["update"],
    ["sbom"],
    ["notices"],
  ])
  use path <- list.each(["cache", ""])
  use flags <- list.each([
    ["--no-cache"],
    ["--no-cache=true"],
    ["--no-cache=false", "--no-cache=true"],
  ])
  use args <- list.each([
    list.append(command, ["--cache-dir=" <> path, ..flags]),
    list.append(list.append(command, flags), ["--cache-dir", path]),
  ])
  let assert Ok(glint.Out(cli.InvalidUsage(message))) =
    glint.execute(cli.app(), cli.normalize_args(args))
  should.equal(message, "--no-cache and --cache-dir cannot be used together")
}

pub fn disabled_boolean_flags_do_not_conflict_with_explicit_paths_test() {
  use command <- list.each([
    [],
    ["report"],
    ["check"],
    ["update"],
    ["sbom"],
    ["notices"],
    ["vulns"],
  ])
  use flags <- list.each([
    ["=false"],
    ["=true", "=false"],
  ])
  let config = case command {
    ["sbom"] | ["update"] -> []
    _ -> [
      "--config=policy.toml",
      ..list.map(flags, fn(suffix) { "--ignore-config" <> suffix })
    ]
  }
  let cache = case command {
    ["vulns"] -> []
    _ -> [
      "--cache-dir=cache",
      ..list.map(flags, fn(suffix) { "--no-cache" <> suffix })
    ]
  }
  let assert Ok(glint.Out(action)) =
    glint.execute(cli.app(), list.append(list.append(command, config), cache))
  case action {
    cli.InvalidUsage(message) -> panic as message
    _ -> Nil
  }
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
  assert string.contains(message, "invalid value")
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

pub fn shared_flag_readers_preserve_validation_precedence_test() -> Nil {
  list.each([[], ..commands], fn(command) {
    let assert Ok(glint.Out(cli.InvalidUsage(message))) =
      glint.execute(
        cli.app(),
        list.append(command, ["--quiet", "--verbose", "--color=rainbow"]),
      )
    should.equal(message, "--quiet and --verbose cannot be used together")
  })

  use #(flags, expected) <- list.each([
    #(
      [
        "--config=policy.toml",
        "--ignore-config",
        "--cache-dir=cache",
        "--no-cache",
      ],
      "--config and --ignore-config cannot be used together",
    ),
    #(
      ["--cache-dir=cache", "--no-cache"],
      "--no-cache and --cache-dir cannot be used together",
    ),
  ])
  use command <- list.each([[], ["report"], ["check"], ["notices"]])
  let args =
    list.append(list.append(command, flags), [
      "--quiet",
      "--verbose",
      "--color=rainbow",
    ])
  let assert Ok(glint.Out(cli.InvalidUsage(message))) =
    glint.execute(cli.app(), args)
  should.equal(message, expected)
}

pub fn shared_flag_readers_preserve_version_and_sbom_error_order_test() -> Nil {
  let assert Ok(glint.Out(cli.ShowVersion)) =
    glint.execute(cli.app(), [
      "--version",
      "--quiet",
      "--verbose",
      "--color=rainbow",
    ])
  let assert Ok(glint.Out(cli.InvalidUsage(message))) =
    glint.execute(cli.app(), [
      "--version",
      "--cache-dir=cache",
      "--no-cache",
    ])
  should.equal(message, "--no-cache and --cache-dir cannot be used together")

  use #(flags, expected) <- list.each([
    #(
      ["--offline", "--reproducible"],
      "--vulns requires network access and cannot be combined with --offline",
    ),
    #(
      ["--reproducible"],
      "--vulns uses mutable advisory data and cannot be combined with --reproducible",
    ),
  ])
  let assert Ok(glint.Out(cli.InvalidUsage(message))) =
    glint.execute(cli.app(), ["sbom", "--vulns", "--color=rainbow", ..flags])
  should.equal(message, expected)
}

pub fn command_specific_flag_matrix_test() {
  use entry <- list.each([
    #("--config=custom.toml", [True, True, True, False, True, True]),
    #("--ignore-config", [True, True, False, False, True, True]),
    #("--no-cache", [True, True, True, True, False, True]),
    #("--cache-dir=custom.cache", [True, True, True, True, False, True]),
    #("--scope=prod", [True, True, False, False, True, True]),
    #("--scope=all", [True, True, False, False, True, True]),
    #("--allow=MIT", [False, False, False, False, False, False]),
    #("--deny=MIT", [False, False, False, False, False, False]),
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
      #("licenses", cli.Licences),
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
    "license",
    "none",
    "true",
    "ALL",
    "licences,vulns",
    "licenses,vulns",
  ])
  use flags <- list.each([["--checks=" <> value], ["--checks", value]])
  let message = usage_error(["check", ..flags])
  assert string.contains(message, "checks")
  assert string.contains(
    message,
    "expected licences or licenses or vulns or all",
  )
}

pub fn check_licenses_alias_matches_canonical_action_test() -> Nil {
  let expected =
    cli.execute(
      ["check", "--checks=licences", "--manifest=licenses"],
      tty.NoColor,
      tty.NoColor,
    )
  let assert Ok(glint.Out(cli.RunAudit(options))) = expected
  should.equal(options.checks, cli.Licences)
  should.equal(options.manifest_path, Some("licenses"))
  use flags <- list.each([["--checks=licenses"], ["--checks", "licenses"]])
  should.equal(
    cli.execute(
      ["check", "--manifest", "licenses", ..flags],
      tty.NoColor,
      tty.NoColor,
    ),
    expected,
  )
}

pub fn check_help_keeps_canonical_selector_spelling_test() -> Nil {
  let help = help_text(["check", "--help"])
  assert string.contains(help, "licences|vulns|all")
  assert !string.contains(help, "licenses")
  should.equal(help_text(["check", "--checks=licenses", "--help"]), help)
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
  assert !string.contains(help, "--allow")
  assert !string.contains(help, "--deny")
}

pub fn root_scan_options_match_named_report_test() {
  use flags <- list.each([
    ["--manifest=missing.toml"],
    ["--config=missing.toml"],
    ["--ignore-config"],
    ["--scope=prod"],
    ["--scope=all"],
    ["--cache-dir=cache"],
    ["--no-cache"],
    ["--quiet"],
    ["--verbose"],
    ["--color=never"],
    ["--manifest=locked.toml", "--config=policy.toml"],
    ["--scope=prod", "--no-cache", "-q", "--colour=never"],
    ["--scope=all", "--no-cache", "-q", "--colour=never"],
    ["--cache-dir=explicit-cache", "-v", "--color=never"],
    [
      "--manifest=locked.toml",
      "--config=policy.toml",
      "--scope=all",
      "--cache-dir=explicit-cache",
      "-v",
      "--colour=never",
    ],
  ])
  should.equal(
    parse_options(flags),
    parse_options(list.append(["report"], flags)),
  )
}

pub fn version_flag_is_root_only_test() {
  use command <- list.each(commands)
  let message = usage_error(list.append(command, ["--version"]))
  assert string.contains(message, "unknown flag")
  assert string.contains(message, "version")
}

pub fn audit_alias_remains_unsupported_test() {
  let message = usage_error(["audit"])
  assert string.contains(message, "unknown command 'audit'")
}

pub fn usage_diagnostic_classes_have_short_contextual_messages_test() {
  use #(command, _) <- list.each(optional_path_flags)
  let help =
    "\nRun '"
    <> string.join(["licence_audit", ..command], " ")
    <> " --help' for usage."
  use #(flags, cause) <- list.each([
    #(["--bogus"], "unknown flag --bogus"),
    #(["--=bogus"], "unknown flag --=bogus"),
    #(["--manifest"], "--manifest requires a value"),
    #(
      ["--quiet=bogus"],
      "invalid value 'bogus' for --quiet (expected true or false)",
    ),
    #(["--color=bogus"], "invalid --color value: bogus"),
    #(["--"], "the '--' separator is not supported"),
    #(["--quiet", "--verbose"], "--quiet and --verbose cannot be used together"),
  ])
  should.equal(
    usage_error(list.append(command, flags)),
    "Error: " <> cause <> help,
  )
}

pub fn constrained_value_diagnostics_do_not_show_parser_internals_test() {
  use #(flag, expected) <- list.each([
    #("scope", "prod or all"),
    #("checks", "licences or licenses or vulns or all"),
    #("vuln-severity", "low or medium or high or critical"),
  ])
  use value <- list.each(["bogus", "", "-h", "--help", "path=with=equals"])
  use flags <- list.each([
    ["--" <> flag <> "=" <> value],
    ["--" <> flag, value],
  ])
  should.equal(
    usage_error(["check", ..flags]),
    "Error: invalid value '"
      <> value
      <> "' for --"
      <> flag
      <> " (expected "
      <> expected
      <> ")\nRun 'licence_audit check --help' for usage.",
  )
}

pub fn unknown_commands_and_pseudo_commands_remain_errors_with_help_test() {
  use #(word, suggestion) <- list.each([
    #("chekc", ""),
    #("audit", ""),
    #("bogus", ""),
    #("help", "; use --help"),
    #("version", "; use --version"),
  ])
  use suffix <- list.each([[], ["--help"], ["-h"]])
  should.equal(
    usage_error([word, ..suffix]),
    "Error: unknown command '"
      <> word
      <> "'"
      <> suggestion
      <> "\nCommands: check, notices, report, sbom, update, vulns"
      <> "\nRun 'licence_audit --help' for usage.",
  )
  use command <- list.each(commands)
  use suffix <- list.each([[], ["--help"]])
  should.equal(
    usage_error(list.append(command, ["extra", ..suffix])),
    "Error: unexpected argument 'extra'\nRun 'licence_audit "
      <> string.join(command, " ")
      <> " --help' for usage.",
  )
}

pub fn every_removed_flag_form_has_its_exact_migration_hint_test() {
  use command <- list.each([[], ..commands])
  use #(name, hint) <- list.each([
    #(
      "allow",
      "Put the lists in [tools.licence_audit] and select the file with --config.",
    ),
    #(
      "deny",
      "Put the lists in [tools.licence_audit] and select the file with --config.",
    ),
    #("prod-only", "Use --scope=prod."),
    #("include-dev", "Use --scope=all."),
    #("cache-path", "Use --cache-dir with the application cache root."),
  ])
  use suffix <- list.each([
    "",
    "=",
    "=true",
    "=false",
    "=MIT",
    "=path=with=equals",
  ])
  should.equal(
    usage_error(list.append(command, ["--" <> name <> suffix])),
    "Error: unknown flag --"
      <> name
      <> "\n"
      <> hint
      <> "\nRun '"
      <> string.join(["licence_audit", ..command], " ")
      <> " --help' for usage.",
  )
}

pub fn invalid_arguments_escape_control_text_without_extra_lines_test() {
  let value = "bad\nvalue\r\t\u{1b}\u{85}\u{2028}\u{2029}'\\"
  use args <- list.each([
    [value],
    ["check", value],
    ["--" <> value],
    ["--scope=" <> value],
    ["--color=" <> value],
  ])
  let message = usage_error(args)
  should.equal(list.length(string.split(message, "\n")) <= 3, True)
  use control <- list.each([
    "\r",
    "\t",
    "\u{1b}",
    "\u{85}",
    "\u{2028}",
    "\u{2029}",
  ])
  assert !string.contains(message, control)
  assert string.contains(message, "\\n")
  assert string.contains(message, "\\'")
  assert string.contains(message, "\\\\")
}

fn parsed_report_format(args: List(String)) -> cli.ReportFormat {
  let assert Ok(glint.Out(action)) = cli.execute(args, tty.NoColor, tty.NoColor)
  case action {
    cli.RunReport(options) -> options.format
    cli.RunAudit(options) -> options.format
    cli.RunVulns(options) -> options.format
    cli.UpdateConfig(_)
    | cli.RunSbom(_)
    | cli.RunNotices(_)
    | cli.ShowVersion
    | cli.InvalidUsage(_) -> panic as "expected a formatted report command"
  }
}

pub fn named_report_formats_accept_separated_and_equals_values_test() -> Nil {
  use command <- list.each(["report", "check", "vulns"])
  should.equal(parsed_report_format([command]), cli.Text)
  use entry <- list.each([#("text", cli.Text), #("json", cli.Json)])
  use flags <- list.each([
    ["--format=" <> entry.0],
    ["--format", entry.0],
  ])
  use args <- list.each([
    [command, ..flags],
    list.append(flags, [command]),
  ])
  should.equal(parsed_report_format(args), entry.1)
  should.equal(cli.recognized_json_command(args), case entry.1 {
    cli.Text -> None
    cli.Json -> Some(command)
  })
}

pub fn report_format_does_not_change_other_options_or_check_selection_test() -> Nil {
  use selection <- list.each(["licences", "licenses", "vulns", "all"])
  let flags = [
    "check",
    "--checks=" <> selection,
    "--scope=prod",
    "--manifest=locked.toml",
    "--no-cache",
    "-q",
    "--colour=never",
  ]
  let original = parse_options(flags)
  should.equal(
    parse_options(list.append(flags, ["--format=json"])),
    cli.Options(..original, format: cli.Json),
  )
}

pub fn root_and_other_commands_do_not_accept_report_format_test() -> Nil {
  should.equal(parsed_report_format([]), cli.Text)
  use command <- list.each([[], ["sbom"], ["notices"], ["update"]])
  let help = help_text(list.append(command, ["--help"]))
  assert !string.contains(help, "--format")
  use flags <- list.each([
    ["--format=json"],
    ["--format", "json"],
    ["--format=text"],
    ["--format", "text"],
  ])
  let args = list.append(command, flags)
  assert string.contains(usage_error(args), "unknown flag --format")
  should.equal(cli.recognized_json_command(args), None)
}

pub fn named_report_format_help_and_invalid_values_test() -> Nil {
  use command <- list.each(["report", "check", "vulns"])
  let help = help_text([command, "--help"])
  assert string.contains(help, "--format=<text|json>")
  should.equal(help_text([command, "--format=json", "--help"]), help)
  assert string.contains(
    usage_error([command, "--format"]),
    "--format requires a value",
  )
  use value <- list.each(["", "JSON", "xml", "true", "-h", "--help"])
  use flags <- list.each([
    ["--format=" <> value],
    ["--format", value],
  ])
  let args = [command, ..flags]
  let message = usage_error(args)
  assert string.contains(message, "expected text or json")
  should.equal(cli.recognized_json_command(args), None)
}

pub fn json_recognition_survives_independent_usage_errors_test() -> Nil {
  use command <- list.each(["report", "check", "vulns"])
  use invalid <- list.each([
    ["--unknown"],
    ["extra"],
    ["--scope=dev"],
    ["--manifest"],
    ["--quiet", "--verbose"],
    ["--config=policy.toml", "--ignore-config"],
  ])
  let args = [command, "--format=json", ..invalid]
  let assert Error(_) = cli.execute(args, tty.NoColor, tty.NoColor)
  should.equal(cli.recognized_json_command(args), Some(command))
  let args = list.append([command, ..invalid], ["--format=json"])
  // A separated value flag consumes its next token, even if it resembles a flag.
  case invalid {
    ["--manifest"] -> should.equal(cli.recognized_json_command(args), None)
    _ -> should.equal(cli.recognized_json_command(args), Some(command))
  }
}

pub fn json_recognition_respects_option_values_and_first_command_test() -> Nil {
  use args <- list.each([
    ["report", "--manifest", "--format=json"],
    ["check", "--config=--format=json"],
    ["vulns", "--manifest=report", "--format=text"],
    ["--manifest", "report", "--format=json"],
    ["--format=json"],
    ["bogus", "report", "--format=json"],
    ["update", "report", "--format=json"],
    ["report", "--format=json", "--format=xml"],
    ["report", "--format=json", "--format"],
    ["report", "--format=json", "--format=text"],
  ])
  should.equal(cli.recognized_json_command(args), None)
  use args <- list.each([
    ["--manifest", "report", "check", "--format=json"],
    ["report", "--format=text", "--format=json"],
    ["report", "--format", "text", "--format", "json"],
  ])
  assert option.is_some(cli.recognized_json_command(args))
}

pub fn json_recognition_does_not_read_unsupported_separator_suffix_test() -> Nil {
  should.equal(
    cli.recognized_json_command(["report", "--", "--format=json"]),
    None,
  )
  should.equal(
    cli.recognized_json_command(["--", "report", "--format=json"]),
    None,
  )
  should.equal(
    cli.recognized_json_command([
      "report", "--format=json", "--", "--format=text",
    ]),
    Some("report"),
  )
}

pub fn json_usage_recognition_preserves_valid_selected_checks_test() -> Nil {
  use entry <- list.each([
    #(["report", "--format=json", "--unknown"], Some(cli.Licences)),
    #(["vulns", "--format=json", "--unknown"], Some(cli.Vulnerabilities)),
    #(["check", "--format=json", "--unknown"], Some(cli.Licences)),
    #(
      ["check", "--checks", "all", "--format=json", "--unknown"],
      Some(cli.AllChecks),
    ),
    #(
      ["check", "--checks=vulns", "--format=json", "--unknown"],
      Some(cli.Vulnerabilities),
    ),
    #(["check", "--checks=bogus", "--format=json"], None),
    #(["check", "--format=json", "--checks"], None),
    #(
      ["check", "--config", "--checks=all", "--format=json"],
      Some(cli.Licences),
    ),
  ])
  should.equal(cli.recognized_checks(entry.0), entry.1)
}
