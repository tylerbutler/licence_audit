# glint_markdown

[![Package Version](https://img.shields.io/hexpm/v/glint_markdown)](https://hex.pm/packages/glint_markdown)

Auto-generate Markdown reference documentation from a [`glint`](https://hex.pm/packages/glint) CLI.

Patterned after [oclif's readme generator][oclif] — supports both single-file
output (one README with every command as a `##` section) and multi-file output
(one Markdown file per top-level subcommand plus an index for injection into a
main README).

[oclif]: https://github.com/oclif/oclif/blob/main/src/readme-generator.ts

## Installation

```sh
gleam add glint_markdown
```

## Quick start

```gleam
import gleam/io
import glint
import glint_markdown

pub fn main() {
  // Build your CLI as usual.
  let app =
    glint.new()
    |> glint.with_name("myapp")
    |> glint.add(at: ["serve"], do: serve_command())
    |> glint.add(at: ["user", "create"], do: user_create_command())

  // Walk the command tree into a documentation-friendly value.
  let tree = glint.document(app)

  // Render the whole tree to one Markdown document.
  tree
  |> glint_markdown.to_string(glint_markdown.options("myapp"))
  |> io.println
}
```

## Modes

### Single-file (one README)

```gleam
let opts = glint_markdown.options("myapp")

// Complete document with `# myapp` title + TOC + every command.
let readme = glint_markdown.to_string(tree, opts)

// Or just the command body, for injecting into an existing README:
let body = glint_markdown.to_commands_body(tree, opts)
let toc  = glint_markdown.to_toc_body(tree, opts)
```

### Multi-file (one file per top-level subcommand)

```gleam
let opts =
  glint_markdown.options("myapp")
  |> glint_markdown.with_mode(glint_markdown.Multi(output_dir: "docs"))

// Per-topic files keyed by path (e.g. "docs/serve.md").
// Pure: caller is responsible for writing them to disk.
let files = glint_markdown.to_files(tree, opts)

// Root command body to inject into your main README.
let root = glint_markdown.to_root_body(tree, opts)

// Index body to inject into your main README between sentinel comments.
let index = glint_markdown.to_topics_index_body(tree, opts)
```

## Sentinel-comment injection

Mark up your README with sentinel comments and let `glint_markdown` rewrite the
content between them on every release. Mirrors oclif's `replaceTag`:

```markdown
<!-- toc -->
<!-- tocstop -->

<!-- root -->
<!-- rootstop -->

## Commands

<!-- commands -->
<!-- commandsstop -->
```

```gleam
let readme = read_existing_readme()

// Single-file mode: inject the generated TOC and command sections.
let updated =
  readme
  |> glint_markdown.inject("toc", glint_markdown.to_toc_body(tree, opts))
  |> glint_markdown.inject(
    "commands",
    glint_markdown.to_commands_body(tree, opts),
  )

// Multi-file mode: inject root docs and a topic-file index.
let updated =
  readme
  |> glint_markdown.inject("root", glint_markdown.to_root_body(tree, opts))
  |> glint_markdown.inject(
    "commands",
    glint_markdown.to_topics_index_body(tree, opts),
  )
```

`inject` is pure: if the start marker is missing the readme is returned
unchanged; if only the start marker is present the body and a fresh stop marker
are inserted after it.

## Dependencies

- [`glint`](https://hex.pm/packages/glint) — the introspection API
  (`glint.document/1`, `glint/help`).

## License

Apache-2.0
