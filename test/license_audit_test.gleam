import gleam/string
import gleeunit
import license_audit

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn help_path_returns_usage_text_test() {
  let license_audit.RunResult(exit_code, output) = license_audit.run(["--help"])

  assert exit_code == 0
  assert string.contains(output, "Usage: license-audit")
}
