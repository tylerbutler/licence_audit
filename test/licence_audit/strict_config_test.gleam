import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleeunit/should
import licence_audit
import licence_audit/config
import licence_audit/error
import licence_audit/progress
import simplifile

fn unknown_keys() -> List(#(String, String)) {
  [
    #("[tools.licence_audit]\nalow = [\"MIT\"]\n", "alow"),
    #("[tools.licence_audit]\nvuln_severty = \"low\"\n", "vuln_severty"),
    #("[tools.licence_audit]\n\"allow.licences\" = []\n", "allow.licences"),
    #("[tools.licence_audit]\nalow.value = []\n", "alow"),
    #("tools.licence_audit.alow = []\n", "alow"),
    #("tools.licence_audit = { alow = [] }\n", "alow"),
    #("[tools.licence_audit.alow]\n", "alow"),
    #("[[tools.licence_audit.alow]]\n", "alow"),
    #("[tools.licence_audit.alow.empty]\n", "alow"),
    #("[[tools.licence_audit.alow.empty]]\n", "alow"),
    #("[\"tools\".'licence_audit'.\"\\u0061low\"]\n", "alow"),
    #("[tools.licence_audit.\"alow.empty\"]\n", "alow.empty"),
    #("[tools.licence_audit.notices]\nincldue = []\n", "notices.incldue"),
    #("[tools.licence_audit.notices]\nexlcude = []\n", "notices.exlcude"),
    #("[tools.licence_audit]\nnotices.incldue = []\n", "notices.incldue"),
    #("[tools.licence_audit]\nnotices = { incldue = [] }\n", "notices.incldue"),
    #("tools.licence_audit.notices.incldue.empty = true\n", "notices.incldue"),
    #("[tools.licence_audit.notices.incldue]\n", "notices.incldue"),
    #("[[tools.licence_audit.notices.incldue]]\n", "notices.incldue"),
    #("[tools.licence_audit.notices.incldue.empty]\n", "notices.incldue"),
    #(
      "[tools.licence_audit.notices]\n\"include.names\" = []\n",
      "notices.include.names",
    ),
    #("[tools.licence_audit.notices.\"\\u0069ncldue\"]\n", "notices.incldue"),
  ]
}

pub fn unknown_keys_fail_in_both_configuration_parsers_test() {
  list.each(unknown_keys(), fn(pair) {
    let #(input, field) = pair
    should.equal(config.parse(input), Error(config.UnknownField(field)))
    should.equal(config.parse_notices(input), Error(config.UnknownField(field)))
    let failure = error.from_config_error(config.UnknownField(field))
    should.equal(error.exit_code(failure), 2)
    should.equal(error.message(failure), "Unknown config field " <> field)
  })
}

pub fn policy_parser_does_not_ignore_malformed_notices_test() {
  [
    "[tools.licence_audit]\nnotices = false\n",
    "[[tools.licence_audit.notices]]\ninclude = []\n",
    "[tools.licence_audit.notices]\ninclude = \"one\"\n",
    "[tools.licence_audit.notices]\nexclude = [1]\n",
    "[tools.licence_audit.notices.include]\n",
    "[[tools.licence_audit.notices.exclude]]\n",
    "[tools.licence_audit.notices]\ninclude.names = []\n",
    "[tools.licence_audit.notices]\nexclude = { names = [] }\n",
  ]
  |> list.each(fn(input) {
    let assert Error(config.InvalidField(_, _)) = config.parse(input)
  })
}

pub fn all_supported_keys_and_unrelated_settings_remain_valid_test() {
  let input =
    "name = \"fixture\"
[tools.other]
alow = []
[tools.licence_audit]
allow = [\"MIT\"]
deny = [\"GPL-3.0-only\"]
vuln_severity = \"critical\"
vuln_block_unknown = true
[tools.licence_audit.notices]
include = [\"one\"]
exclude = [\"two\"]
[[tools.licence_audit.exceptions]]
purl = \"pkg:hex/example@1.2.3\"
finding = \"no-licences-declared\"
reason = \"Reviewed\"
"
  let assert Ok(policy) = config.parse(input)
  should.equal(policy.allow, ["MIT"])
  should.equal(policy.deny, ["GPL-3.0-only"])
  should.equal(policy.vuln_severity, Some("critical"))
  should.equal(policy.vuln_block_unknown, True)
  should.equal(list.length(policy.exceptions), 1)
  should.equal(
    config.parse_notices(input),
    Ok(config.Notices(["one"], ["two"])),
  )
  let assert Ok(_) =
    config.parse("[tools.licence_audit]\n[tools.licence_audit.notices]\n")
}

fn malformed_licences() -> List(String) {
  [
    "",
    " \t\r\n",
    "MIT/Apache-2.0",
    "Apache 2.0",
    "MIT AND",
    "MIT OR",
    "OR MIT",
    "MIT and Apache-2.0",
    "(MIT",
    "MIT)",
    "()",
    "(MIT OR Apache-2.0) WITH LLVM-exception",
    "MIT WITH",
    "GPL-2.0++",
    "LicenseRef-",
    "LicenseRef-custom+",
    "DocumentRef-:LicenseRef-custom",
    string.repeat("a", 65_537),
    string.repeat("MIT OR ", 512) <> "MIT",
    string.repeat("(", 65) <> "MIT" <> string.repeat(")", 65),
  ]
}

fn policy(allow: List(String), deny: List(String)) -> config.Policy {
  config.Policy(allow, deny, None, False, [])
}

fn load_options(allow: List(String), deny: List(String)) -> config.LoadOptions {
  config.LoadOptions(
    config_path: None,
    project_root: "test/fixtures/no-policy",
    allow_licences: allow,
    deny_licences: deny,
    vuln_severity: None,
    vuln_block_unknown: False,
    ignore_config: False,
    check: False,
  )
}

pub fn malformed_licences_fail_in_parse_load_and_merge_test() {
  list.each(malformed_licences(), fn(licence) {
    list.each(["allow", "deny"], fn(field) {
      let allow = case field {
        "allow" -> [licence]
        _ -> ["MIT"]
      }
      let deny = case field {
        "deny" -> [licence]
        _ -> []
      }
      let input =
        "[tools.licence_audit]\n" <> field <> " = ['''" <> licence <> "''']\n"
      should.equal(config.parse(input), Error(config.InvalidLicenceIdentifier))
      should.equal(
        config.parse_notices(input),
        Error(config.InvalidLicenceIdentifier),
      )
      let options = load_options(allow, deny)
      should.equal(config.load(options), Error(config.InvalidLicenceIdentifier))
      should.equal(
        config.load(config.LoadOptions(..options, ignore_config: True)),
        Error(config.InvalidLicenceIdentifier),
      )
      should.equal(
        config.merge(policy(["MIT"], []), policy(allow, deny)),
        Error(config.InvalidLicenceIdentifier),
      )
      should.equal(
        config.merge(policy(allow, deny), policy(["MIT"], [])),
        Error(config.InvalidLicenceIdentifier),
      )
    })
  })
}

pub fn valid_spdx_syntax_is_preserved_without_membership_checks_test() {
  let licences = [
    "MIT", "Proprietary", "Unlicence", "GPL-2.0", "GPL-2.0+", "GPL-2.0-only",
    "GPL-2.0-or-later", "GPL-2.0-only WITH Classpath-exception-2.0",
    "MIT OR Apache-2.0", "(MIT OR Apache-2.0) AND BSD-3-Clause",
    "LicenseRef-Custom", "DocumentRef-project:LicenseRef-Custom", " \tMIT\n",
    "mit",
  ]
  let values = "['''" <> string.join(licences, "''', '''") <> "''']"
  let assert Ok(parsed) =
    config.parse(
      "[tools.licence_audit]\nallow = " <> values <> "\ndeny = " <> values,
    )
  should.equal(parsed.allow, licences)
  should.equal(parsed.deny, licences)
  should.equal(config.load(load_options(licences, licences)), Ok(parsed))
  should.equal(config.merge(policy([], []), parsed), Ok(parsed))
}

fn no_fetch_clients() -> licence_audit.Clients {
  licence_audit.Clients(..licence_audit.default_clients(), fetcher: fn(_) {
    panic as "Invalid policy must fail before metadata requests"
  })
}

fn assert_invalid_cli(
  commands: List(String),
  field: String,
  value: String,
  ignore_config: Bool,
) -> Nil {
  let flags = case ignore_config {
    True -> ["--ignore-config"]
    False -> ["--config=test/fixtures/licence_audit_config.toml"]
  }
  let arguments =
    list.append(commands, [
      "--manifest=test/fixtures/manifest.toml",
      "--" <> field <> "=" <> value,
      ..flags
    ])
  let #(result, _) =
    licence_audit.run_configured(
      arguments,
      no_fetch_clients(),
      progress.disabled(),
    )
  should.equal(result.exit_code, 2)
  assert string.contains(result.output, "valid SPDX expressions")
}

pub fn cli_malformed_entries_fail_before_fetching_test() {
  list.each(["", "check"], fn(command) {
    let commands = case command {
      "" -> []
      _ -> [command]
    }
    list.each(["allow", "deny"], fn(field) {
      list.each(
        ["MIT/Apache-2.0", "Apache 2.0", "", "MIT,", ",MIT", "MIT,,Apache-2.0"],
        fn(value) {
          list.each([False, True], fn(ignore_config) {
            assert_invalid_cli(commands, field, value, ignore_config)
          })
        },
      )
    })
  })
}

pub fn file_errors_cannot_be_hidden_by_cli_additions_test() {
  let root = "build/strict-config-validation"
  let assert Ok(_) = simplifile.create_directory_all(root)
  let manifest_path = root <> "/manifest.toml"
  let config_path = root <> "/gleam.toml"
  let assert Ok(manifest) = simplifile.read("test/fixtures/manifest.toml")
  let assert Ok(_) = simplifile.write(manifest_path, manifest)
  list.each(unknown_keys(), fn(pair) {
    let #(input, field) = pair
    let assert Ok(_) = simplifile.write(config_path, input)
    list.each([False, True], fn(explicit) {
      let flags = case explicit {
        True -> ["--config=" <> config_path]
        False -> []
      }
      let #(result, _) =
        licence_audit.run_configured(
          [
            "check",
            "--manifest=" <> manifest_path,
            "--allow=MIT",
            "--deny=GPL-3.0-only",
            ..flags
          ],
          no_fetch_clients(),
          progress.disabled(),
        )
      should.equal(result.exit_code, 2)
      assert string.contains(result.output, "Unknown config field " <> field)
    })
    should.equal(
      config.load_notices(root, None, False),
      Error(config.UnknownField(field)),
    )
  })
  list.each(["allow", "deny"], fn(field) {
    let assert Ok(_) =
      simplifile.write(
        config_path,
        "[tools.licence_audit]\n" <> field <> " = [\"MIT/Apache-2.0\"]\n",
      )
    list.each([False, True], fn(explicit) {
      let flags = case explicit {
        True -> ["--config=" <> config_path]
        False -> []
      }
      let #(result, _) =
        licence_audit.run_configured(
          [
            "check",
            "--manifest=" <> manifest_path,
            "--allow=MIT",
            "--deny=GPL-3.0-only",
            ..flags
          ],
          no_fetch_clients(),
          progress.disabled(),
        )
      should.equal(result.exit_code, 2)
      assert string.contains(result.output, "valid SPDX expressions")
    })
    should.equal(
      config.load_notices(root, None, False),
      Error(config.InvalidLicenceIdentifier),
    )
  })
  let assert Ok(_) = simplifile.delete(config_path)
  let assert Ok(_) = simplifile.delete(manifest_path)
  let assert Ok(_) = simplifile.delete(root)
}
