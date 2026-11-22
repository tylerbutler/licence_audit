import gleam/json
import gleam/string
import simplifile

pub fn flag(allow: List(String), deny: List(String)) -> String {
  let path =
    "build/tmp/policies/"
    <> string.join(allow, "_")
    <> "--"
    <> string.join(deny, "_")
    <> ".toml"
  let assert Ok(_) = simplifile.create_directory_all("build/tmp/policies")
  let assert Ok(_) =
    simplifile.write(
      path,
      "[tools.licence_audit]\nallow = "
        <> json.to_string(json.array(allow, json.string))
        <> "\ndeny = "
        <> json.to_string(json.array(deny, json.string))
        <> "\n",
    )
  "--config=" <> path
}
