/// Why pretty-printing an SBOM JSON document failed.
pub type PrettyPrintError {
  InvalidJson
}

@external(erlang, "sbom_json_ffi", "pretty_print")
pub fn pretty_print(json: String) -> Result(String, PrettyPrintError)

/// Human-readable description of a pretty-printing failure.
pub fn describe_error(error: PrettyPrintError) -> String {
  let InvalidJson = error
  "invalid JSON"
}
