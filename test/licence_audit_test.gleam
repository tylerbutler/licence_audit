import gleam/string
import gleeunit
import licence_audit

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn help_path_returns_usage_text_test() {
  let licence_audit.RunResult(exit_code, output) = licence_audit.run(["--help"])

  assert exit_code == 0
  assert string.contains(output, "licence_audit")
  assert string.contains(output, "USAGE:")
}

pub fn short_help_path_returns_usage_error_test() {
  let licence_audit.RunResult(exit_code, output) = licence_audit.run(["-h"])

  assert exit_code == 1
  assert string.contains(output, "invalid number of arguments")
}

pub fn unknown_option_returns_usage_error_test() {
  let licence_audit.RunResult(exit_code, output) = licence_audit.run(["--wat"])

  assert exit_code == 1
  assert string.contains(output, "wat")
  assert string.contains(output, "USAGE:")
}

pub fn quiet_and_verbose_path_returns_usage_error_test() {
  let licence_audit.RunResult(exit_code, output) =
    licence_audit.run(["--quiet", "--verbose"])

  assert exit_code == 1
  assert string.contains(output, "--quiet")
  assert string.contains(output, "--verbose")
}
