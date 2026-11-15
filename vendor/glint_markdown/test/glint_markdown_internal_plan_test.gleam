import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleeunit/should
import glint
import glint_markdown
import glint_markdown/internal/plan

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

fn nil_command() -> glint.Command(Nil) {
  glint.command(fn(_, _, _) { Nil })
}

fn sample_app() -> glint.Glint(Nil) {
  let port =
    glint.int_flag("port")
    |> glint.flag_default(8080)
    |> glint.flag_help("Port to listen on")

  glint.new()
  |> glint.add(at: [], do: {
    use <- glint.command_help("Top-level command")
    nil_command()
  })
  |> glint.add(at: ["serve"], do: {
    use <- glint.command_help("Start the server")
    use _ <- glint.flag(port)
    nil_command()
  })
  |> glint.add(at: ["user", "create"], do: {
    use <- glint.command_help("Create a new user")
    nil_command()
  })
}

fn default_options() -> plan.PlanOptions {
  plan.PlanOptions(
    bin: "myapp",
    working_directory: "/project",
    mode: plan.SingleMode,
    output: None,
    readme: None,
    repository_prefix: None,
    include_hidden: False,
    no_toc: False,
  )
}

// ---------------------------------------------------------------------------
// parse_mode
// ---------------------------------------------------------------------------

pub fn parse_mode_single_test() -> Nil {
  plan.parse_mode("single")
  |> should.equal(Ok(plan.SingleMode))
}

pub fn parse_mode_multi_test() -> Nil {
  plan.parse_mode("multi")
  |> should.equal(Ok(plan.MultiMode))
}

pub fn parse_mode_invalid_test() -> Nil {
  plan.parse_mode("foo")
  |> should.equal(Error(plan.InvalidMode("foo")))
}

// ---------------------------------------------------------------------------
// single mode → stdout / file
// ---------------------------------------------------------------------------

pub fn plan_single_to_stdout_test() -> Nil {
  let tree = glint.document(sample_app())
  let assert Ok(actions) = plan.plan(tree, default_options())

  let expected = glint_markdown.to_string(tree, glint_markdown.options("myapp"))
  actions
  |> should.equal([plan.WriteStdout(contents: expected)])
}

pub fn plan_single_to_file_test() -> Nil {
  let tree = glint.document(sample_app())
  let options =
    plan.PlanOptions(..default_options(), output: Some("docs/REF.md"))
  let assert Ok(actions) = plan.plan(tree, options)

  let expected = glint_markdown.to_string(tree, glint_markdown.options("myapp"))
  actions
  |> should.equal([plan.WriteFile(path: "docs/REF.md", contents: expected)])
}

// ---------------------------------------------------------------------------
// single mode → readme injection
// ---------------------------------------------------------------------------

pub fn plan_single_inject_readme_test() -> Nil {
  let tree = glint.document(sample_app())
  let options = plan.PlanOptions(..default_options(), readme: Some("README.md"))
  let assert Ok(actions) = plan.plan(tree, options)

  let render_options = glint_markdown.options("myapp")
  let root = glint_markdown.to_root_body(tree, render_options)
  let toc = glint_markdown.to_toc_body(tree, render_options)
  let body = glint_markdown.to_commands_body(tree, render_options)

  actions
  |> should.equal([
    plan.InjectFile(path: "README.md", tag: "root", body: root),
    plan.InjectFile(path: "README.md", tag: "toc", body: toc),
    plan.InjectFile(path: "README.md", tag: "commands", body: body),
  ])
}

pub fn plan_single_inject_readme_ignores_out_test() -> Nil {
  // --readme wins; --out should be silently ignored in single+readme mode.
  let tree = glint.document(sample_app())
  let options =
    plan.PlanOptions(
      ..default_options(),
      readme: Some("README.md"),
      output: Some("docs/REF.md"),
    )
  let assert Ok(actions) = plan.plan(tree, options)

  // No WriteFile actions should be present.
  list.any(actions, fn(action) {
    case action {
      plan.WriteFile(..) -> True
      plan.InjectFile(..) | plan.WriteStdout(..) -> False
    }
  })
  |> should.be_false

  // Should produce exactly the three inject actions.
  list.length(actions)
  |> should.equal(3)
}

// ---------------------------------------------------------------------------
// single mode + no_toc
// ---------------------------------------------------------------------------

pub fn plan_single_no_toc_stdout_test() -> Nil {
  let tree = glint.document(sample_app())
  let options = plan.PlanOptions(..default_options(), no_toc: True)
  let assert Ok(actions) = plan.plan(tree, options)

  let body =
    glint_markdown.to_commands_body(tree, glint_markdown.options("myapp"))
  let expected = "# myapp\n\n" <> body
  actions
  |> should.equal([plan.WriteStdout(contents: expected)])
}

pub fn plan_single_no_toc_inject_readme_test() -> Nil {
  let tree = glint.document(sample_app())
  let options =
    plan.PlanOptions(
      ..default_options(),
      readme: Some("README.md"),
      no_toc: True,
    )
  let assert Ok(actions) = plan.plan(tree, options)

  let body =
    glint_markdown.to_commands_body(tree, glint_markdown.options("myapp"))
  let root = glint_markdown.to_root_body(tree, glint_markdown.options("myapp"))
  actions
  |> should.equal([
    plan.InjectFile(path: "README.md", tag: "root", body: root),
    plan.InjectFile(path: "README.md", tag: "commands", body: body),
  ])
}

// ---------------------------------------------------------------------------
// multi mode
// ---------------------------------------------------------------------------

pub fn plan_multi_default_directory_test() -> Nil {
  let tree = glint.document(sample_app())
  let options = plan.PlanOptions(..default_options(), mode: plan.MultiMode)
  let assert Ok(actions) = plan.plan(tree, options)

  // sample_app exposes two top-level subcommands.
  list.length(actions)
  |> should.equal(2)

  // Every action is a WriteFile under ./docs/.
  list.all(actions, fn(action) {
    case action {
      plan.WriteFile(path: path, contents: _) ->
        case path {
          "./docs/serve.md" | "./docs/user.md" -> True
          _ -> False
        }
      plan.InjectFile(..) | plan.WriteStdout(..) -> False
    }
  })
  |> should.be_true
}

pub fn plan_multi_custom_directory_test() -> Nil {
  let tree = glint.document(sample_app())
  let options =
    plan.PlanOptions(
      ..default_options(),
      mode: plan.MultiMode,
      output: Some("reference"),
    )
  let assert Ok(actions) = plan.plan(tree, options)

  let paths =
    list.map(actions, fn(action) {
      case action {
        plan.WriteFile(path: path, contents: _) -> path
        plan.InjectFile(..) | plan.WriteStdout(..) -> ""
      }
    })

  list.contains(paths, "reference/serve.md")
  |> should.be_true

  list.contains(paths, "reference/user.md")
  |> should.be_true
}

pub fn plan_multi_inject_readme_test() -> Nil {
  let tree = glint.document(sample_app())
  let options =
    plan.PlanOptions(
      ..default_options(),
      mode: plan.MultiMode,
      output: Some("docs"),
      readme: Some("README.md"),
    )
  let assert Ok(actions) = plan.plan(tree, options)

  // 2 file writes + 2 injects = 4 actions.
  list.length(actions)
  |> should.equal(4)

  let root = glint_markdown.to_root_body(tree, glint_markdown.options("myapp"))
  let assert [_, _, root_action, _] = actions
  root_action
  |> should.equal(plan.InjectFile(path: "README.md", tag: "root", body: root))

  // Last action should be the index injection.
  let render_options =
    glint_markdown.options("myapp")
    |> glint_markdown.with_mode(glint_markdown.Multi(output_dir: "docs"))
  let index = glint_markdown.to_topics_index_body(tree, render_options)

  let assert Ok(last) = list.last(actions)
  last
  |> should.equal(plan.InjectFile(
    path: "README.md",
    tag: "commands",
    body: index,
  ))
}

pub fn plan_multi_rejects_unsafe_topic_names_test() -> Nil {
  list.each(["../README", "nested/name", "nested\\name", "C:README"], fn(name) {
    let tree =
      glint.new()
      |> glint.add(at: [name], do: nil_command())
      |> glint.document
    let options = plan.PlanOptions(..default_options(), mode: plan.MultiMode)

    plan.plan(tree, options) |> should.equal(Error(plan.UnsafeTopic(name)))
  })
}

pub fn plan_multi_rejects_injection_write_collision_test() -> Nil {
  let tree = glint.document(sample_app())
  let options =
    plan.PlanOptions(
      ..default_options(),
      mode: plan.MultiMode,
      output: Some("docs"),
      readme: Some("./docs/../docs/serve.md"),
    )

  plan.plan(tree, options)
  |> should.equal(Error(plan.ConflictingDestination("docs/serve.md")))
}

pub fn plan_multi_links_relative_to_nested_readme_test() -> Nil {
  let tree = glint.document(sample_app())
  let options =
    plan.PlanOptions(
      ..default_options(),
      mode: plan.MultiMode,
      output: Some("docs"),
      readme: Some("docs/README.md"),
    )
  let assert Ok(actions) = plan.plan(tree, options)
  let assert Ok(plan.InjectFile(_, "commands", index)) = list.last(actions)

  string.contains(index, "(./serve.md)") |> should.be_true
  string.contains(index, "(docs/serve.md)") |> should.be_false
}

pub fn plan_multi_links_relative_to_parent_readme_test() -> Nil {
  let tree = glint.document(sample_app())
  let options =
    plan.PlanOptions(
      ..default_options(),
      mode: plan.MultiMode,
      output: Some("/project/reference docs"),
      readme: Some("guides/README.md"),
    )
  let assert Ok(actions) = plan.plan(tree, options)
  let assert Ok(plan.InjectFile(_, "commands", index)) = list.last(actions)

  string.contains(index, "(../reference%20docs/serve.md)") |> should.be_true
}

pub fn plan_multi_rejects_absolute_relative_destination_collision_test() -> Nil {
  let options =
    plan.PlanOptions(
      ..default_options(),
      mode: plan.MultiMode,
      output: Some("/project/docs"),
      readme: Some("./docs/serve.md"),
    )

  plan.plan(glint.document(sample_app()), options)
  |> should.equal(Error(plan.ConflictingDestination("/project/docs/serve.md")))
}
