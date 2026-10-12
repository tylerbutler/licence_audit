import gleam/list
import gleeunit/should
import glint
import glint/help
import glint_markdown/cli

fn nil_command() {
  glint.command(fn(_, _, _) { Nil })
}

fn sample_app() -> glint.Glint(Nil) {
  glint.new()
  |> glint.with_name("myapp")
  |> glint.add(at: [], do: {
    use <- glint.command_help("Top-level command")
    nil_command()
  })
  |> glint.add(at: ["serve"], do: {
    use <- glint.command_help("Start the server")
    nil_command()
  })
}

fn subcommand_named(tree: help.Tree, name: String) -> Result(help.Tree, Nil) {
  list.find(tree.subcommands, fn(s) { s.meta.name == name })
}

// ---------------------------------------------------------------------------
// command
// ---------------------------------------------------------------------------

pub fn command_can_be_added_to_a_glint_app_test() {
  // Round-trip smoke test: build the command from the sample app's tree, add
  // it back to the same app under a fresh path, and assert the subcommand
  // shows up in the resulting tree. This is the strongest contract we can
  // assert without invoking the runner — which would call `exit_with` and
  // terminate the test process.
  let app = sample_app()
  let tree =
    app
    |> glint.add(at: ["gen-docs"], do: cli.command(glint.document(app)))
    |> glint.document

  let names = list.map(tree.subcommands, fn(s) { s.meta.name })
  should.be_true(list.contains(names, "gen-docs"))
}

// ---------------------------------------------------------------------------
// mount
// ---------------------------------------------------------------------------

pub fn mount_adds_command_at_path_test() {
  let app =
    sample_app()
    |> cli.mount(at: ["gen-docs"])

  let tree = glint.document(app)
  let names = list.map(tree.subcommands, fn(s) { s.meta.name })
  should.be_true(list.contains(names, "gen-docs"))
}

pub fn mount_at_nested_path_test() {
  let app =
    sample_app()
    |> cli.mount(at: ["tools", "gen-docs"])

  let tree = glint.document(app)
  let assert Ok(tools) = subcommand_named(tree, "tools")
  let assert Ok(_gen_docs) = subcommand_named(tools, "gen-docs")
  Nil
}

pub fn mount_preserves_existing_subcommands_test() {
  let app =
    sample_app()
    |> cli.mount(at: ["gen-docs"])

  let tree = glint.document(app)
  let names = list.map(tree.subcommands, fn(s) { s.meta.name })

  // `serve` from the original app must survive the mount.
  should.be_true(list.contains(names, "serve"))
  should.be_true(list.contains(names, "gen-docs"))
}
