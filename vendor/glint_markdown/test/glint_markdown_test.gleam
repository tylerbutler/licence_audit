import gleam/dict
import gleam/list
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

fn count_occurrences(haystack: String, needle: String) -> Int {
  string.split(haystack, needle)
  |> list.length
  |> fn(n) { n - 1 }
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

pub fn to_root_body_renders_top_level_command_without_heading_test() {
  let tree = glint.document(sample_app())
  let body = glint_markdown.to_root_body(tree, glint_markdown.options("myapp"))

  string.starts_with(body, "#")
  |> should.be_false

  string.contains(body, "Top-level command")
  |> should.be_true

  string.contains(body, "`--verbose`")
  |> should.be_true

  string.contains(body, "`myapp serve`")
  |> should.be_false

  string.contains(body, "**Subcommands:**")
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

pub fn to_files_topic_file_does_not_duplicate_heading_test() {
  let tree = glint.document(sample_app())
  let opts =
    glint_markdown.options("myapp")
    |> glint_markdown.with_mode(glint_markdown.Multi(output_dir: "docs"))
  let files = glint_markdown.to_files(tree, opts)

  let assert Ok(serve_doc) = dict.get(files, "docs/serve.md")

  // The `#` title already names the topic; it must not be repeated as a
  // `## ` section, and its description must appear only once.
  string.contains(serve_doc, "# `myapp serve`")
  |> should.be_true

  string.contains(serve_doc, "## `myapp serve`")
  |> should.be_false

  count_occurrences(serve_doc, "Start the server")
  |> should.equal(1)
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

pub fn to_topics_index_body_uses_subcommands_heading_test() {
  let tree = glint.document(sample_app())
  let opts =
    glint_markdown.options("myapp")
    |> glint_markdown.with_mode(glint_markdown.Multi(output_dir: "docs"))
  let index = glint_markdown.to_topics_index_body(tree, opts)

  string.starts_with(index, "## Subcommands")
  |> should.be_true

  string.contains(index, "## Command Topics")
  |> should.be_false
}
