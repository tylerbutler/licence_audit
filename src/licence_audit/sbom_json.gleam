pub fn pretty_print(json: String) -> Result(String, String) {
  pretty_print_json(json)
}

@external(erlang, "sbom_json_ffi", "pretty_print")
fn pretty_print_json(json: String) -> Result(String, String)
