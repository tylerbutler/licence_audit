import gleam/list
import gleam/string
import gleeunit/should
import licence_audit/toml

pub fn preserves_leading_comments_test() {
  let input =
    "# top comment\n# second comment\n\n[tools.licence_audit]\nallow = []\ndeny = []\n"
  let assert Ok(output) =
    toml.set_string_array(input, ["tools", "licence_audit"], "allow", [
      "MIT",
    ])
  should.be_true(string.contains(output, "# top comment"))
  should.be_true(string.contains(output, "# second comment"))
  should.be_true(string.contains(output, "[\"MIT\"]"))
}

pub fn preserves_inline_trailing_comment_test() {
  let input = "[tools.licence_audit]\nallow = [\"MIT\"] # keep me\ndeny = []\n"
  let assert Ok(output) =
    toml.set_string_array(input, ["tools", "licence_audit"], "allow", [
      "MIT",
      "Apache-2.0",
    ])
  should.be_true(string.contains(output, "# keep me"))
  should.be_true(string.contains(output, "[\"MIT\", \"Apache-2.0\"]"))
}

pub fn preserves_trailing_comment_containing_quote_test() {
  let input =
    "[tools.licence_audit]\nallow = [\"MIT\"] # use \"MIT\" only\ndeny = []\n"
  let assert Ok(output) =
    toml.set_string_array(input, ["tools", "licence_audit"], "allow", [
      "MIT",
      "Apache-2.0",
    ])

  should.be_true(string.contains(output, "# use \"MIT\" only"))
  should.be_true(string.contains(output, "[\"MIT\", \"Apache-2.0\"]"))
  should.equal(string.contains(output, "__licence_audit_array__allow_2"), False)
}

pub fn preserves_trailing_comment_containing_hash_test() {
  let input =
    "[tools.licence_audit]\nallow = [\"MIT\"] # keep #123\ndeny = []\n"
  let assert Ok(output) =
    toml.set_string_array(input, ["tools", "licence_audit"], "allow", [
      "MIT",
      "Apache-2.0",
    ])

  should.be_true(string.contains(output, "# keep #123"))
  should.be_true(string.contains(output, "[\"MIT\", \"Apache-2.0\"]"))
}

pub fn rewrites_only_matching_key_in_target_table_test() {
  let input =
    "[dependencies]\ndeny = \">= 1.0.0\"\n\n[tools.licence_audit]\nallow = []\ndeny = [\"MIT\"]\n"
  let assert Ok(output) =
    toml.set_string_array(input, ["tools", "licence_audit"], "deny", [
      "GPL-3.0",
    ])

  should.be_true(string.contains(output, "[dependencies]"))
  should.be_true(string.contains(output, "deny = \">= 1.0.0\""))
  should.be_true(string.contains(output, "[tools.licence_audit]"))
  should.be_true(string.contains(output, "deny = [\"GPL-3.0\"]"))
}

pub fn array_table_after_target_does_not_inherit_target_scope_test() {
  let input =
    "[tools.licence_audit]\ndeny = [\"MIT\"]\n\n[[dependencies]]\ndeny = \"__licence_audit_array__deny_1\"\n"
  let assert Ok(output) =
    toml.set_string_array(input, ["tools", "licence_audit"], "deny", [
      "GPL-3.0",
    ])

  should.be_true(string.contains(output, "deny = [\"GPL-3.0\"]"))
  should.be_true(string.contains(
    output,
    "deny = \"__licence_audit_array__deny_1\"",
  ))
}

pub fn matching_array_table_is_not_rewritten_as_standard_table_test() {
  let input = "[[tools.licence_audit]]\nallow = [\"MIT\"]\n"
  let assert Error(_) =
    toml.set_string_array(input, ["tools", "licence_audit"], "allow", [
      "GPL-3.0",
    ])
  Nil
}

pub fn quoted_bracket_header_after_target_does_not_inherit_scope_test() {
  let input =
    "[tools.licence_audit]\nallow = [\"MIT\"]\n\n[other.\"]\"]\nallow = \"__licence_audit_array__allow_1\"\n"
  let assert Ok(output) =
    toml.set_string_array(input, ["tools", "licence_audit"], "allow", [
      "GPL-3.0",
    ])

  should.be_true(string.contains(output, "allow = [\"GPL-3.0\"]"))
  should.be_true(string.contains(
    output,
    "allow = \"__licence_audit_array__allow_1\"",
  ))
}

pub fn quoted_assignment_key_is_rewritten_test() {
  let input = "[tools.licence_audit]\n\"allow\" = [\"MIT\"]\n"
  let assert Ok(output) =
    toml.set_string_array(input, ["tools", "licence_audit"], "allow", [
      "Apache-2.0",
    ])

  should.be_true(string.contains(output, "\"allow\" = [\"Apache-2.0\"]"))
}

pub fn multiline_strings_are_not_scanned_as_tables_test() {
  let input =
    "[other]\nblob = \"\"\"\n[tools.licence_audit]\nallow = \"__licence_audit_array__allow_1\"\n\"\"\"\n"
  let assert Ok(output) =
    toml.set_string_array(input, ["tools", "licence_audit"], "allow", [
      "Apache-2.0",
    ])

  should.be_true(string.contains(
    output,
    "allow = \"__licence_audit_array__allow_1\"",
  ))
  should.be_true(string.contains(output, "allow = [\"Apache-2.0\"]"))
}

pub fn multiline_string_in_array_does_not_hide_later_target_table_test() {
  let input =
    "arr = [\"\"\"\nexample\n\"\"\"]\n\n[tools.licence_audit]\nallow = [\"MIT\"]\n"
  let assert Ok(output) =
    toml.set_string_array(input, ["tools", "licence_audit"], "allow", [
      "Apache-2.0",
    ])

  should.be_true(string.contains(output, "arr = [\"\"\""))
  should.be_true(string.contains(output, "allow = [\"Apache-2.0\"]"))
}

pub fn same_line_multiline_string_in_array_preserves_depth_test() {
  let input =
    "arr = [\"\"\"example\"\"\"]\n\n[tools.licence_audit]\nallow = [\"MIT\"]\n"
  let assert Ok(output) =
    toml.set_string_array(input, ["tools", "licence_audit"], "allow", [
      "Apache-2.0",
    ])

  should.be_true(string.contains(output, "arr = [\"\"\"example\"\"\"]"))
  should.be_true(string.contains(output, "allow = [\"Apache-2.0\"]"))
}

pub fn quoted_table_key_spaces_do_not_match_trimmed_target_test() {
  let input =
    "[tools.\" licence_audit \"]\nallow = \"__licence_audit_array__allow_1\"\n"
  let assert Ok(output) =
    toml.set_string_array(input, ["tools", "licence_audit"], "allow", [
      "Apache-2.0",
    ])

  should.be_true(string.contains(output, "[tools.\" licence_audit \"]"))
  should.be_true(string.contains(
    output,
    "allow = \"__licence_audit_array__allow_1\"",
  ))
  should.be_true(string.contains(output, "[tools.licence_audit]"))
  should.be_true(string.contains(output, "allow = [\"Apache-2.0\"]"))
}

pub fn rewrites_key_in_quoted_target_table_header_test() {
  let input = "[tools.\"licence_audit\"]\nallow = [\"MIT\"]\ndeny = []\n"
  let assert Ok(output) =
    toml.set_string_array(input, ["tools", "licence_audit"], "allow", [
      "Apache-2.0",
    ])

  should.be_true(string.contains(output, "[tools.\"licence_audit\"]"))
  should.be_true(string.contains(output, "allow = [\"Apache-2.0\"]"))
}

pub fn ignores_array_items_that_look_like_table_headers_test() {
  let input =
    "[tools.licence_audit]\ngroups = [\n  [\"MIT\"]\n]\ndeny = [\"MIT\"]\n"
  let assert Ok(output) =
    toml.set_string_array(input, ["tools", "licence_audit"], "deny", [
      "GPL-3.0",
    ])

  should.be_true(string.contains(output, "groups = ["))
  should.be_true(string.contains(output, "[\"MIT\"]"))
  should.be_true(string.contains(output, "deny = [\"GPL-3.0\"]"))
}

pub fn leaves_keys_containing_target_key_untouched_test() {
  let input =
    "[tools.licence_audit]\nallowlist = \"keep\"\nallow = [\"MIT\"]\ndeny = []\n"
  let assert Ok(output) =
    toml.set_string_array(input, ["tools", "licence_audit"], "allow", [
      "Apache-2.0",
    ])

  should.be_true(string.contains(output, "allowlist = \"keep\""))
  should.be_true(string.contains(output, "allow = [\"Apache-2.0\"]"))
}

pub fn preserves_hashes_inside_array_values_test() {
  let input =
    "[tools.licence_audit]\nallow = [\"MIT\"] # value can include #\ndeny = []\n"
  let assert Ok(output) =
    toml.set_string_array(input, ["tools", "licence_audit"], "allow", [
      "License #1",
      "Apache-2.0",
    ])

  should.be_true(string.contains(output, "\"License #1\""))
  should.be_true(string.contains(output, "# value can include #"))
}

pub fn leaves_unrelated_sections_untouched_test() {
  let input =
    "[tools.licence_audit]\nallow = []\ndeny = []\n\n[other]\nkey = \"value\"\nnumber = 42\n"
  let assert Ok(output) =
    toml.set_string_array(input, ["tools", "licence_audit"], "allow", [
      "MIT",
    ])
  should.be_true(string.contains(output, "[other]"))
  should.be_true(string.contains(output, "key = \"value\""))
  should.be_true(string.contains(output, "number = 42"))
}

pub fn empty_input_creates_nested_table_test() {
  let assert Ok(output) =
    toml.set_string_array("", ["tools", "licence_audit"], "allow", [
      "MIT",
    ])
  should.be_true(string.contains(output, "[tools.licence_audit]"))
  should.be_true(string.contains(output, "[\"MIT\"]"))
}

pub fn creates_subtable_under_existing_parent_test() {
  let input = "[tools]\nother = \"keep\"\n"
  let assert Ok(output) =
    toml.set_string_array(input, ["tools", "licence_audit"], "allow", [
      "MIT",
    ])
  should.be_true(string.contains(output, "other = \"keep\""))
  should.be_true(string.contains(output, "licence_audit"))
  should.be_true(string.contains(output, "[\"MIT\"]"))
}

pub fn invalid_toml_returns_toml_error_test() {
  let assert Error(err) = toml.set_string_array("not = = valid", ["x"], "y", [])
  let toml.TomlError(_) = err
  Nil
}

pub fn end_to_end_round_trip_preserves_everything_test() {
  let input =
    "# Project licence policy
# Edit by hand — `licence_audit update` preserves your comments.

[tools.licence_audit]
# Currently allowed:
allow = [\"MIT\"]  # extend as needed
deny = []

[other]
note = \"leave me alone\"
"
  let assert Ok(after_allow) =
    toml.set_string_array(input, ["tools", "licence_audit"], "allow", [
      "MIT",
      "Apache-2.0",
    ])
  let assert Ok(after_both) =
    toml.set_string_array(after_allow, ["tools", "licence_audit"], "deny", [
      "GPL-3.0",
    ])

  should.be_true(string.contains(after_both, "# Project licence policy"))
  should.be_true(string.contains(after_both, "# Edit by hand"))
  should.be_true(string.contains(after_both, "# Currently allowed:"))
  should.be_true(string.contains(after_both, "# extend as needed"))
  should.be_true(string.contains(after_both, "[other]"))
  should.be_true(string.contains(after_both, "note = \"leave me alone\""))
  should.be_true(string.contains(after_both, "\"Apache-2.0\""))
  should.be_true(string.contains(after_both, "\"GPL-3.0\""))
}

const packages_doc = "packages = [
  { name = \"app_a\", version = \"1.0.0\", source = \"hex\", requirements = [\"lib_b\"] },
  { name = \"lib_b\", version = \"2.0.0\", source = \"hex\", requirements = [] },
]

[requirements]
app_a = { version = \">= 1.0.0\" }
gleam_stdlib = { version = \">= 1.0.0\" }
"

pub fn parse_ok_test() {
  let assert Ok(_) = toml.parse(packages_doc)
}

pub fn parse_error_on_malformed_test() {
  let assert Error(Nil) = toml.parse("packages = [")
}

pub fn get_array_returns_items_test() {
  let assert Ok(doc) = toml.parse(packages_doc)
  let assert Ok(items) = toml.get_array(doc, ["packages"])
  should.equal(list.length(items), 2)
}

pub fn get_array_missing_test() {
  let assert Ok(doc) = toml.parse("[requirements]\n")
  should.equal(toml.get_array(doc, ["packages"]), Error(toml.ArrayMissing))
}

pub fn get_array_not_array_test() {
  let assert Ok(doc) = toml.parse("packages = 42\n")
  should.equal(toml.get_array(doc, ["packages"]), Error(toml.ArrayNotArray))
}

pub fn as_table_and_field_string_test() {
  let assert Ok(doc) = toml.parse(packages_doc)
  let assert Ok([first, ..]) = toml.get_array(doc, ["packages"])
  let assert Ok(entry) = toml.as_table(first)
  let assert Ok(value) = toml.field(entry, "name")
  should.equal(toml.as_string(value), Ok("app_a"))
}

pub fn field_missing_test() {
  let assert Ok(doc) = toml.parse(packages_doc)
  let assert Ok([first, ..]) = toml.get_array(doc, ["packages"])
  let assert Ok(entry) = toml.as_table(first)
  should.equal(toml.field(entry, "nope"), Error(Nil))
}

pub fn as_array_of_requirements_test() {
  let assert Ok(doc) = toml.parse(packages_doc)
  let assert Ok([first, ..]) = toml.get_array(doc, ["packages"])
  let assert Ok(entry) = toml.as_table(first)
  let assert Ok(value) = toml.field(entry, "requirements")
  let assert Ok(items) = toml.as_array(value)
  should.equal(list.length(items), 1)
}

pub fn table_keys_returns_keys_test() {
  let assert Ok(doc) = toml.parse(packages_doc)
  let assert Ok(keys) = toml.table_keys(doc, ["requirements"])
  should.equal(list.sort(keys, string.compare), ["app_a", "gleam_stdlib"])
}

pub fn table_keys_missing_test() {
  let assert Ok(doc) = toml.parse("packages = []\n")
  should.equal(toml.table_keys(doc, ["requirements"]), Error(Nil))
}

pub fn get_table_returns_entries_test() {
  let assert Ok(doc) = toml.parse("[tools.licence_audit]\nallow = [\"MIT\"]\n")
  let assert Ok(entry) = toml.get_table(doc, ["tools", "licence_audit"])
  let assert Ok(value) = toml.field(entry, "allow")
  let assert Ok(items) = toml.as_array(value)
  should.equal(list.length(items), 1)
}

pub fn get_table_missing_test() {
  let assert Ok(doc) = toml.parse("name = \"x\"\n")
  should.equal(
    toml.get_table(doc, ["tools", "licence_audit"]),
    Error(toml.TableLookupMissing),
  )
}

pub fn get_table_not_table_test() {
  let assert Ok(doc) = toml.parse("tools = 7\n")
  should.equal(toml.get_table(doc, ["tools"]), Error(toml.TableLookupNotTable))
}

pub fn get_string_test() {
  let assert Ok(doc) = toml.parse("name = \"hello\"\nversion = \"1.2.3\"\n")
  should.equal(toml.get_string(doc, ["name"]), Ok("hello"))
  should.equal(toml.get_string(doc, ["missing"]), Error(Nil))
}
