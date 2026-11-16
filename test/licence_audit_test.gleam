import gleam/string
import gleeunit
import licence_audit
import licence_audit/version

pub fn bare_invocation_returns_root_help_test() {
  assert licence_audit.run([]) == licence_audit.run(["--help"])
}

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn help_path_returns_usage_text_test() {
  let licence_audit.RunResult(exit_code, output) = licence_audit.run(["--help"])

  assert exit_code == 0
  assert string.contains(output, "licence_audit")
  assert string.contains(output, "USAGE:")
}

pub fn short_help_path_returns_usage_text_test() {
  let licence_audit.RunResult(exit_code, output) = licence_audit.run(["-h"])

  assert exit_code == 0
  assert string.contains(output, "licence_audit")
  assert string.contains(output, "USAGE:")
}

pub fn version_path_returns_build_version_test() {
  let assert Ok(build_version) = version.build_version()
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run(["--version"])

  assert exit_code == 0
  assert output == build_version <> "\n"
}

pub fn unknown_option_returns_usage_error_test() {
  let licence_audit.RunResult(exit_code, output) = licence_audit.run(["--wat"])

  assert exit_code == 1
  assert string.contains(output, "wat")
  assert string.contains(output, "USAGE:")
}

pub fn quiet_and_verbose_path_returns_usage_error_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run(["report", "--quiet", "--verbose"])

  assert exit_code == 1
  assert string.contains(output, "--quiet")
  assert string.contains(output, "--verbose")
}

pub fn missing_path_value_is_not_filled_by_library_cache_override_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run(["report", "--manifest"])
  assert exit_code == 1
  assert string.contains(output, "manifest")
  assert string.contains(output, "has no assigned value")
}

pub fn manifest_value_that_looks_like_help_is_not_help_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run(["report", "--manifest", "-h", "--ignore-config"])
  assert exit_code == 2
  assert string.contains(output, "-h")
  assert !string.contains(output, "USAGE:")
}
