import gleam/dict
import gleam/string
import gleeunit
import gleeunit/should
import glint
import glint_markdown

pub fn main() {
  gleeunit.main()
}

fn nil_command() {
  glint.command(fn(_, _, _) { Nil })
}

fn sample_app() -> glint.Glint(Nil) {
  let port =
    glint.int_flag("port")
    |> glint.flag_default(8080)
    |> glint.flag_help("Port to listen on")

  let verbose =
    glint.bool_flag("verbose")
    |> glint.flag_default(False)

  glint.new()
  |> glint.add(at: [], do: {
    use <- glint.command_help("Top-level command")
    use _ <- glint.flag(verbose)
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

// ---------------------------------------------------------------------------
// to_string (single-mode rendering)
// ---------------------------------------------------------------------------

pub fn to_string_includes_bin_title_test() {
  let tree = glint.document(sample_app())
  let out = glint_markdown.to_string(tree, glint_markdown.options("myapp"))

  out
  |> string.starts_with("# myapp")
  |> should.be_true
}

pub fn to_string_includes_table_of_contents_test() {
  let tree = glint.document(sample_app())
  let out = glint_markdown.to_string(tree, glint_markdown.options("myapp"))

  string.contains(out, "## Table of Contents")
  |> should.be_true
}

pub fn to_string_renders_every_command_as_heading_test() {
  let tree = glint.document(sample_app())
  let out = glint_markdown.to_string(tree, glint_markdown.options("myapp"))

  string.contains(out, "## `myapp serve`")
  |> should.be_true

  string.contains(out, "## `myapp user create`")
  |> should.be_true
}

pub fn to_string_renders_flag_defaults_test() {
  let tree = glint.document(sample_app())
  let out = glint_markdown.to_string(tree, glint_markdown.options("myapp"))

  // The port flag defaults to 8080 — should appear in the flags table.
  string.contains(out, "8080")
  |> should.be_true

  // And the type column should be populated.
  string.contains(out, "`INT`")
  |> should.be_true
}

// ---------------------------------------------------------------------------
// to_commands_body / to_toc_body
// ---------------------------------------------------------------------------

pub fn to_commands_body_omits_top_level_title_test() {
  let tree = glint.document(sample_app())
  let body =
    glint_markdown.to_commands_body(tree, glint_markdown.options("myapp"))

  // Body should NOT start with `# myapp` — that's reserved for to_string.
  string.starts_with(body, "# myapp")
  |> should.be_false

  // But should still include the command sections.
  string.contains(body, "## `myapp serve`")
  |> should.be_true
}

pub fn to_toc_body_lists_every_command_test() {
  let tree = glint.document(sample_app())
  let toc = glint_markdown.to_toc_body(tree, glint_markdown.options("myapp"))

  string.contains(toc, "`myapp serve`")
  |> should.be_true

  string.contains(toc, "`myapp user create`")
  |> should.be_true
}

pub fn to_root_body_renders_only_root_command_docs_test() {
  let tree = glint.document(sample_app())
  let body = glint_markdown.to_root_body(tree, glint_markdown.options("myapp"))

  string.contains(body, "## `myapp`")
  |> should.be_true

  string.contains(body, "Top-level command")
  |> should.be_true

  string.contains(body, "`--verbose`")
  |> should.be_true

  string.contains(body, "**Subcommands:**")
  |> should.be_true

  string.contains(body, "## `myapp serve`")
  |> should.be_false
}

// ---------------------------------------------------------------------------
// inject (oclif replaceTag analogue)
// ---------------------------------------------------------------------------

pub fn inject_replaces_existing_block_test() {
  let readme =
    "intro\n<!-- commands -->\nold body\n<!-- commandsstop -->\noutro"
  let out = glint_markdown.inject(readme, "commands", "fresh body")

  out
  |> should.equal(
    "intro\n<!-- commands -->\nfresh body\n<!-- commandsstop -->\noutro",
  )
}

pub fn inject_appends_stop_marker_when_only_start_present_test() {
  let readme = "intro\n<!-- commands -->\noutro"
  let out = glint_markdown.inject(readme, "commands", "body")

  out
  |> should.equal(
    "intro\n<!-- commands -->\nbody\n<!-- commandsstop -->\noutro",
  )
}

pub fn inject_leaves_readme_unchanged_when_no_start_marker_test() {
  let readme = "intro\nno markers here\noutro"
  let out = glint_markdown.inject(readme, "commands", "body")

  out
  |> should.equal(readme)
}

pub fn inject_preserves_content_outside_block_test() {
  let readme =
    "# Project\n\nsome prose\n\n<!-- commands -->\nold\n<!-- commandsstop -->\n\nmore prose"
  let out = glint_markdown.inject(readme, "commands", "new")

  string.contains(out, "# Project")
  |> should.be_true

  string.contains(out, "some prose")
  |> should.be_true

  string.contains(out, "more prose")
  |> should.be_true

  string.contains(out, "old")
  |> should.be_false
}

// ---------------------------------------------------------------------------
// Multi-file mode
// ---------------------------------------------------------------------------

pub fn to_files_emits_one_file_per_top_level_subcommand_test() {
  let tree = glint.document(sample_app())
  let opts =
    glint_markdown.options("myapp")
    |> glint_markdown.with_mode(glint_markdown.Multi(output_dir: "docs"))
  let files = glint_markdown.to_files(tree, opts)

  // sample_app has two top-level subcommands: "serve" and "user".
  dict.size(files)
  |> should.equal(2)

  dict.has_key(files, "docs/serve.md")
  |> should.be_true

  dict.has_key(files, "docs/user.md")
  |> should.be_true
}

pub fn to_files_user_file_includes_nested_subcommand_test() {
  let tree = glint.document(sample_app())
  let opts =
    glint_markdown.options("myapp")
    |> glint_markdown.with_mode(glint_markdown.Multi(output_dir: "docs"))
  let files = glint_markdown.to_files(tree, opts)

  let assert Ok(user_doc) = dict.get(files, "docs/user.md")

  string.contains(user_doc, "myapp user create")
  |> should.be_true
}

pub fn to_topics_index_body_links_to_topic_files_test() {
  let tree = glint.document(sample_app())
  let opts =
    glint_markdown.options("myapp")
    |> glint_markdown.with_mode(glint_markdown.Multi(output_dir: "docs"))
  let index = glint_markdown.to_topics_index_body(tree, opts)

  string.contains(index, "docs/serve.md")
  |> should.be_true

  string.contains(index, "docs/user.md")
  |> should.be_true
}

// ---------------------------------------------------------------------------
// Anchor slugs (GitHub heading-anchor algorithm)
// ---------------------------------------------------------------------------

fn underscore_app() -> glint.Glint(Nil) {
  glint.new()
  |> glint.add(at: [], do: nil_command())
  |> glint.add(at: ["do_thing"], do: {
    use <- glint.command_help("Does the thing")
    nil_command()
  })
}

pub fn slugify_preserves_underscores_in_anchor_links_test() {
  let tree = glint.document(underscore_app())
  let out = glint_markdown.to_string(tree, glint_markdown.options("myapp"))

  // The heading is `## ` + "`myapp do_thing`", so GitHub's anchor preserves
  // the underscore: `myapp-do_thing`. The TOC / subcommand links must target
  // that exact anchor — a general slugifier would emit `myapp-do-thing`.
  string.contains(out, "## `myapp do_thing`")
  |> should.be_true

  string.contains(out, "(#myapp-do_thing)")
  |> should.be_true

  string.contains(out, "(#myapp-do-thing)")
  |> should.be_false
}

// ---------------------------------------------------------------------------
// Usage rendering: unnamed-args token
// ---------------------------------------------------------------------------

pub fn usage_suppresses_args_token_for_group_nodes_test() {
  let tree = glint.document(sample_app())
  let out = glint_markdown.to_string(tree, glint_markdown.options("myapp"))

  // Leaf commands accept unconstrained args, so `[ARGS]` is still shown.
  string.contains(out, "myapp serve [ARGS]")
  |> should.be_true

  // The `user` node is a pure group (dispatches to `create`); `[ARGS]` would
  // be noise there, so it is suppressed.
  string.contains(out, "(create) [ARGS]")
  |> should.be_false
}

// ---------------------------------------------------------------------------
// Multi-mode root body links to topic files (not in-page anchors)
// ---------------------------------------------------------------------------

pub fn to_root_body_links_subcommands_to_topic_files_in_multi_mode_test() {
  let tree = glint.document(sample_app())
  let opts =
    glint_markdown.options("myapp")
    |> glint_markdown.with_mode(glint_markdown.Multi(output_dir: "docs"))
  let body = glint_markdown.to_root_body(tree, opts)

  // Top-level subcommands live in their own files in Multi mode, so the root
  // body's Subcommands list must link to those files...
  string.contains(body, "](docs/serve.md)")
  |> should.be_true

  string.contains(body, "](docs/user.md)")
  |> should.be_true

  // ...not in-page anchors that don't exist on the README page.
  string.contains(body, "(#myapp-serve)")
  |> should.be_false
}

pub fn to_root_body_uses_in_page_anchors_in_single_mode_test() {
  let tree = glint.document(sample_app())
  let body = glint_markdown.to_root_body(tree, glint_markdown.options("myapp"))

  string.contains(body, "(#myapp-serve)")
  |> should.be_true
}
