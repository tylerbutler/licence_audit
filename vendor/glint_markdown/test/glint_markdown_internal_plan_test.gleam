import gleam/list
import gleam/option.{None, Some}
import gleeunit/should
import glint
import glint_markdown
import glint_markdown/internal/plan

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

fn nil_command() {
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

fn default_opts() -> plan.PlanOpts {
  plan.PlanOpts(
    bin: "myapp",
    mode: plan.SingleMode,
    out: None,
    readme: None,
    repo_prefix: None,
    include_hidden: False,
    no_toc: False,
  )
}

// ---------------------------------------------------------------------------
// parse_mode
// ---------------------------------------------------------------------------

pub fn parse_mode_single_test() {
  plan.parse_mode("single")
  |> should.equal(Ok(plan.SingleMode))
}

pub fn parse_mode_multi_test() {
  plan.parse_mode("multi")
  |> should.equal(Ok(plan.MultiMode))
}

pub fn parse_mode_invalid_test() {
  plan.parse_mode("foo")
  |> should.equal(Error(plan.InvalidMode("foo")))
}

// ---------------------------------------------------------------------------
// single mode → stdout / file
// ---------------------------------------------------------------------------

pub fn plan_single_to_stdout_test() {
  let tree = glint.document(sample_app())
  let assert Ok(actions) = plan.plan(tree, default_opts())

  let expected = glint_markdown.to_string(tree, glint_markdown.options("myapp"))
  actions
  |> should.equal([plan.WriteStdout(contents: expected)])
}

pub fn plan_single_to_file_test() {
  let tree = glint.document(sample_app())
  let opts = plan.PlanOpts(..default_opts(), out: Some("docs/REF.md"))
  let assert Ok(actions) = plan.plan(tree, opts)

  let expected = glint_markdown.to_string(tree, glint_markdown.options("myapp"))
  actions
  |> should.equal([plan.WriteFile(path: "docs/REF.md", contents: expected)])
}

// ---------------------------------------------------------------------------
// single mode → readme injection
// ---------------------------------------------------------------------------

pub fn plan_single_inject_readme_test() {
  let tree = glint.document(sample_app())
  let opts = plan.PlanOpts(..default_opts(), readme: Some("README.md"))
  let assert Ok(actions) = plan.plan(tree, opts)

  let render_opts = glint_markdown.options("myapp")
  let root = glint_markdown.to_root_body(tree, render_opts)
  let toc = glint_markdown.to_toc_body(tree, render_opts)
  let body = glint_markdown.to_commands_body(tree, render_opts)

  actions
  |> should.equal([
    plan.InjectFile(path: "README.md", tag: "root", body: root),
    plan.InjectFile(path: "README.md", tag: "toc", body: toc),
    plan.InjectFile(path: "README.md", tag: "commands", body: body),
  ])
}

pub fn plan_single_inject_readme_ignores_out_test() {
  // --readme wins; --out should be silently ignored in single+readme mode.
  let tree = glint.document(sample_app())
  let opts =
    plan.PlanOpts(
      ..default_opts(),
      readme: Some("README.md"),
      out: Some("docs/REF.md"),
    )
  let assert Ok(actions) = plan.plan(tree, opts)

  // No WriteFile actions should be present.
  list.any(actions, fn(a) {
    case a {
      plan.WriteFile(..) -> True
      _ -> False
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

pub fn plan_single_no_toc_stdout_test() {
  let tree = glint.document(sample_app())
  let opts = plan.PlanOpts(..default_opts(), no_toc: True)
  let assert Ok(actions) = plan.plan(tree, opts)

  let body =
    glint_markdown.to_commands_body(tree, glint_markdown.options("myapp"))
  let expected = "# myapp\n\n" <> body
  actions
  |> should.equal([plan.WriteStdout(contents: expected)])
}

pub fn plan_single_no_toc_inject_readme_test() {
  let tree = glint.document(sample_app())
  let opts =
    plan.PlanOpts(..default_opts(), readme: Some("README.md"), no_toc: True)
  let assert Ok(actions) = plan.plan(tree, opts)

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

pub fn plan_multi_default_dir_test() {
  let tree = glint.document(sample_app())
  let opts = plan.PlanOpts(..default_opts(), mode: plan.MultiMode)
  let assert Ok(actions) = plan.plan(tree, opts)

  // sample_app exposes two top-level subcommands.
  list.length(actions)
  |> should.equal(2)

  // Every action is a WriteFile under ./docs/.
  list.all(actions, fn(a) {
    case a {
      plan.WriteFile(path: p, contents: _) ->
        case p {
          "./docs/serve.md" | "./docs/user.md" -> True
          _ -> False
        }
      _ -> False
    }
  })
  |> should.be_true
}

pub fn plan_multi_custom_dir_test() {
  let tree = glint.document(sample_app())
  let opts =
    plan.PlanOpts(
      ..default_opts(),
      mode: plan.MultiMode,
      out: Some("reference"),
    )
  let assert Ok(actions) = plan.plan(tree, opts)

  let paths =
    list.map(actions, fn(a) {
      case a {
        plan.WriteFile(path: p, contents: _) -> p
        _ -> ""
      }
    })

  list.contains(paths, "reference/serve.md")
  |> should.be_true

  list.contains(paths, "reference/user.md")
  |> should.be_true
}

pub fn plan_multi_inject_readme_test() {
  let tree = glint.document(sample_app())
  let opts =
    plan.PlanOpts(
      ..default_opts(),
      mode: plan.MultiMode,
      out: Some("docs"),
      readme: Some("README.md"),
    )
  let assert Ok(actions) = plan.plan(tree, opts)

  // 2 file writes + 2 injects = 4 actions.
  list.length(actions)
  |> should.equal(4)

  let root = glint_markdown.to_root_body(tree, glint_markdown.options("myapp"))
  let assert [_, _, root_action, _] = actions
  root_action
  |> should.equal(plan.InjectFile(path: "README.md", tag: "root", body: root))

  // Last action should be the index injection.
  let render_opts =
    glint_markdown.options("myapp")
    |> glint_markdown.with_mode(glint_markdown.Multi(output_dir: "docs"))
  let index = glint_markdown.to_topics_index_body(tree, render_opts)

  let assert Ok(last) = list.last(actions)
  last
  |> should.equal(plan.InjectFile(
    path: "README.md",
    tag: "commands",
    body: index,
  ))
}
