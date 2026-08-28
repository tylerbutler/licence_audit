import glint
import glint_markdown/cli as glint_markdown_cli
import licence_audit/cli

@external(erlang, "args_ffi", "arguments")
fn arguments() -> List(String)

pub fn main() -> Nil {
  glint.new()
  |> glint.with_name("licence_audit gen-docs")
  |> glint.add(
    at: [],
    do: glint_markdown_cli.command(glint.document(cli.app())),
  )
  |> glint.run(for: arguments())
}
