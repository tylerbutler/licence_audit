import gleam/string
import gleeunit/should
import licence_audit/config
import licence_audit/error
import licence_audit/hex
import licence_audit/manifest
import licence_audit/policy

pub fn success_report_maps_to_exit_zero_test() {
  should.equal(error.exit_code(error.Success), 0)
  should.equal(error.message(error.Success), "")
}

pub fn audit_failure_maps_to_exit_one_and_message_test() {
  should.equal(error.exit_code(error.AuditFailed), 1)
  should.equal(
    error.message(error.AuditFailed),
    "Dependency licence audit failed. Review the report above and update the dependency or policy.",
  )
}

pub fn missing_policy_maps_to_exit_two_and_message_test() {
  should.equal(error.exit_code(error.MissingPolicy), 2)
  should.equal(
    error.message(error.MissingPolicy),
    "No licence policy supplied for the `check` subcommand. Add a [tools.licence_audit] section to gleam.toml or pass --allow/--deny.",
  )
}

pub fn generic_input_config_hex_errors_map_to_exit_two_test() {
  let errors = [
    error.Usage("Unknown option: --wat"),
    error.Config("Invalid TOML"),
    error.Input("Could not read manifest.toml"),
    error.Hex("Hex.pm returned 429"),
    error.Decode("Invalid Hex package metadata"),
  ]

  errors
  |> list_each(fn(app_error) {
    should.equal(error.exit_code(app_error), 2)
    assert string.length(error.message(app_error)) > 0
  })
}

pub fn policy_errors_map_to_app_errors_test() {
  should.equal(
    error.from_policy_error(policy.MissingPolicy),
    error.MissingPolicy,
  )
}

pub fn config_errors_map_to_app_errors_test() {
  should.equal(
    error.from_config_error(config.MissingPolicy),
    error.MissingPolicy,
  )
  should.equal(
    error.from_config_error(config.InvalidToml("bad")),
    error.Config("bad"),
  )
  should.equal(
    error.from_config_error(config.InvalidField("allow", "Array")),
    error.Config("Invalid config field allow: expected Array"),
  )
  should.equal(
    error.from_config_error(config.InvalidLicenceIdentifier),
    error.Config("Licence identifiers must not be empty"),
  )
  should.equal(
    error.from_config_error(config.FileReadError("gleam.toml")),
    error.Input("Could not read gleam.toml"),
  )
}

pub fn manifest_errors_map_to_app_errors_test() {
  should.equal(
    error.from_manifest_error(manifest.InvalidToml("bad")),
    error.Decode("bad"),
  )
  should.equal(
    error.from_manifest_error(manifest.MissingPackages),
    error.Decode("Manifest is missing packages"),
  )
  should.equal(
    error.from_manifest_error(manifest.InvalidPackageField(
      "gleam_stdlib",
      "version",
      "String",
    )),
    error.Decode(
      "Invalid manifest package gleam_stdlib field version: expected String",
    ),
  )
  should.equal(
    error.from_manifest_error(manifest.FileReadError("manifest.toml")),
    error.Input("Could not read manifest.toml"),
  )
}

pub fn hex_errors_map_to_app_errors_test() {
  should.equal(
    error.from_hex_error(hex.InvalidJson("invalid json")),
    error.Decode("invalid json"),
  )
  should.equal(
    error.from_hex_error(hex.InvalidMetadata("invalid metadata")),
    error.Decode("invalid metadata"),
  )
  should.equal(
    error.from_hex_error(hex.NotFound),
    error.Hex("Hex package not found"),
  )
  should.equal(
    error.from_hex_error(hex.RateLimited),
    error.Hex("Hex.pm rate limit exceeded"),
  )
  should.equal(
    error.from_hex_error(hex.UnexpectedResponse(500)),
    error.Hex("Hex.pm returned 500"),
  )
  should.equal(
    error.from_hex_error(hex.NetworkFailure("connection refused")),
    error.Hex("Hex.pm request failed: connection refused"),
  )
}

fn list_each(items: List(a), fun: fn(a) -> Nil) -> Nil {
  case items {
    [] -> Nil
    [item, ..rest] -> {
      fun(item)
      list_each(rest, fun)
    }
  }
}

pub fn unsupported_source_for_sbom_message_includes_package_test() {
  let err =
    error.UnsupportedSourceForSbom(
      package: "foo",
      source: "git",
      detail: "https://gitlab.com/x/foo",
    )

  let message = error.message(err)
  let assert True = string.contains(message, "foo")
  let assert True = string.contains(message, "git")
  let assert True = string.contains(message, "gitlab.com")
  should.equal(error.exit_code(err), 2)
}

pub fn sbom_write_failed_message_includes_path_test() {
  let err = error.SbomWriteFailed(path: "/tmp/sbom.json", reason: "EACCES")
  let message = error.message(err)
  let assert True = string.contains(message, "/tmp/sbom.json")
  let assert True = string.contains(message, "EACCES")
  should.equal(error.exit_code(err), 2)
}
