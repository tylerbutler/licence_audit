import gleam/int
import licence_audit/config
import licence_audit/hex
import licence_audit/manifest
import licence_audit/osv
import licence_audit/policy

pub type Error {
  Success
  AuditFailed
  MissingPolicy
  Usage(String)
  Config(String)
  Input(String)
  Hex(String)
  Decode(String)
  UnsupportedSourceForSbom(package: String, source: String, detail: String)
  SbomWriteFailed(path: String, reason: String)
  Osv(String)
}

pub fn exit_code(error: Error) -> Int {
  case error {
    Success -> 0
    AuditFailed -> 1
    _ -> 2
  }
}

pub fn message(error: Error) -> String {
  case error {
    Success -> ""
    AuditFailed ->
      "Dependency licence audit failed. Review the report above and update the dependency or policy."
    MissingPolicy ->
      "No licence policy supplied for the `check` subcommand. Add a [tools.licence_audit] section to gleam.toml or pass --allow/--deny."
    Usage(message) -> message
    Config(message) -> message
    Input(message) -> message
    Hex(message) -> message
    Decode(message) -> message
    UnsupportedSourceForSbom(package, source, detail) ->
      "Cannot generate purl for package `"
      <> package
      <> "` (source: "
      <> source
      <> ", "
      <> detail
      <> "). SBOM generation supports source = \"hex\" and source = \"git\" with a github.com repository."
    SbomWriteFailed(path, reason) ->
      "Failed to write SBOM to " <> path <> ": " <> reason
    Osv(message) -> message
  }
}

pub fn from_osv_error(error: osv.Error) -> Error {
  case error {
    osv.InvalidJson(message) -> Decode(message)
    osv.InvalidResponse(message) -> Decode(message)
    osv.NotFound -> Osv("OSV resource not found")
    osv.RateLimited -> Osv("OSV rate limit exceeded")
    osv.UnexpectedResponse(status) ->
      Osv("OSV returned " <> int.to_string(status))
    osv.NetworkFailure -> Osv("OSV request failed")
  }
}

pub fn from_policy_error(error: policy.Error) -> Error {
  case error {
    policy.MissingPolicy -> MissingPolicy
  }
}

pub fn from_config_error(error: config.Error) -> Error {
  case error {
    config.MissingPolicy -> MissingPolicy
    config.InvalidToml(message) -> Config(message)
    config.InvalidField(field, expected) ->
      Config("Invalid config field " <> field <> ": expected " <> expected)
    config.InvalidLicenceIdentifier ->
      Config("Licence identifiers must not be empty")
    config.FileReadError(path) -> Input("Could not read " <> path)
  }
}

pub fn from_manifest_error(error: manifest.Error) -> Error {
  case error {
    manifest.InvalidToml(message) -> Decode(message)
    manifest.MissingPackages -> Decode("Manifest is missing packages")
    manifest.InvalidPackageField(package, field, expected) ->
      Decode(
        "Invalid manifest package "
        <> package
        <> " field "
        <> field
        <> ": expected "
        <> expected,
      )
    manifest.FileReadError(path) -> Input("Could not read " <> path)
  }
}

pub fn from_hex_error(error: hex.Error) -> Error {
  case error {
    hex.InvalidJson(message) -> Decode(message)
    hex.InvalidMetadata(message) -> Decode(message)
    hex.NotFound -> Hex("Hex package not found")
    hex.RateLimited -> Hex("Hex.pm rate limit exceeded")
    hex.UnexpectedResponse(status) ->
      Hex("Hex.pm returned " <> int.to_string(status))
    hex.NetworkFailure -> Hex("Hex.pm request failed")
  }
}
