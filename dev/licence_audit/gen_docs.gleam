import gleam/list
import gleam/result
import gleam/string
import licence_audit/cli
import licence_audit/internal/vendor/glint
import licence_audit/internal/vendor/glint/help.{type Tree}
import licence_audit/internal/vendor/glint_markdown
import licence_audit/internal/vendor/glint_markdown/internal/exit
import licence_audit/internal/vendor/glint_markdown/internal/io as file_io
import licence_audit/internal/vendor/glint_markdown/internal/plan
import simplifile

const start_marker = "<!-- cli-reference -->"

const stop_marker = "<!-- cli-referencestop -->"

@external(erlang, "args_ffi", "arguments")
fn arguments() -> List(String)

pub fn main() -> Nil {
  glint.new()
  |> glint.with_name("licence_audit gen-docs")
  |> glint.add(at: [], do: command())
  |> glint.run(for: arguments())
}

fn command() -> glint.Command(Nil) {
  use <- glint.command_help(
    "Generate CLI reference sections in website guides.",
  )
  use check <- glint.flag(
    glint.bool_flag("check")
    |> glint.flag_default(False)
    |> glint.flag_help("Check for drift without writing files."),
  )
  use _, _, flags <- glint.command()
  let assert Ok(check) = check(flags)
  case actions(glint.document(cli.app())) {
    Error(message) -> report_errors([message])
    Ok(actions) ->
      case file_io.execute(actions, check, False) {
        Ok(_) -> Nil
        Error(messages) -> report_errors(messages)
      }
  }
}

pub fn reference_pages(tree: Tree) -> List(#(String, String)) {
  let root = #(
    "website/src/pages/docs/index.md",
    glint_markdown.to_root_body(tree, glint_markdown.options(tree.meta.name)),
  )
  let commands =
    tree.subcommands
    |> list.map(fn(command) {
      #(
        "website/src/pages/docs/" <> command.meta.name <> ".md",
        glint_markdown.to_root_body(
          command,
          glint_markdown.options(tree.meta.name <> " " <> command.meta.name),
        ),
      )
    })
  [root, ..commands]
}

pub fn update_page(
  path: String,
  existing: String,
  reference: String,
) -> Result(String, String) {
  case string.split(existing, start_marker) {
    [before, after] ->
      case string.split(after, stop_marker) {
        [_, remaining] ->
          case
            string.contains(before, stop_marker)
            || string.contains(remaining, start_marker)
          {
            False ->
              Ok(glint_markdown.inject(existing, "cli-reference", reference))
            True -> Error("invalid CLI reference markers in " <> path)
          }
        _ -> Error("expected one CLI reference stop marker in " <> path)
      }
    _ -> Error("expected one CLI reference start marker in " <> path)
  }
}

fn actions(tree: Tree) -> Result(List(plan.Action), String) {
  tree
  |> reference_pages
  |> list.try_map(fn(page) {
    let #(path, reference) = page
    use existing <- result.try(
      simplifile.read(path)
      |> result.map_error(fn(error) {
        "could not read " <> path <> ": " <> simplifile.describe_error(error)
      }),
    )
    use updated <- result.try(update_page(path, existing, reference))
    Ok(plan.WriteFile(path, updated))
  })
}

fn report_errors(messages: List(String)) -> Nil {
  list.each(messages, fn(message) {
    exit.stderr("gen_docs: " <> message <> "\n")
  })
  exit.exit_with(1)
}
