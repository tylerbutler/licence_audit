import gleam/list
import gleam/string
import simplifile

fn file(path: String) -> String {
  let assert Ok(contents) = simplifile.read(from: path)
  contents
}

fn assert_not_contains(haystack: String, needles: List(String)) {
  list.each(needles, fn(needle) {
    assert !string.contains(haystack, needle)
  })
}

pub fn chosen_simplifications_stay_removed_test() {
  assert_not_contains(file("gleam.toml"), [
    "envoy",
    "gleam_regexp",
    "youid",
  ])
  assert_not_contains(file("src/licence_audit/sbom.gleam"), ["gleam/regexp"])
  assert_not_contains(file("src/licence_audit/sbom_uuid.gleam"), [
    "envoy",
    "youid",
  ])
  assert_not_contains(file("src/licence_audit/cache.gleam"), ["envoy"])
  assert_not_contains(file("src/licence_audit/cli.gleam"), ["project_root"])
}
