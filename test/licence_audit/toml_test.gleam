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
  let assert Error(err) =
    toml.set_string_array("not = = valid", ["x"], "y", [])
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
