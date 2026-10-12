# glint_markdown

[![CI](https://github.com/tylerbutler/glint_markdown/actions/workflows/ci.yml/badge.svg)](https://github.com/tylerbutler/glint_markdown/actions/workflows/ci.yml)
[![Package Version](https://img.shields.io/hexpm/v/glint_markdown)](https://hex.pm/packages/glint_markdown)

Auto-generate Markdown reference documentation from a [`glint`](https://hex.pm/packages/glint) CLI.

Patterned after [oclif's readme generator][oclif] — supports both single-file
output (one README with every command as a `##` section) and multi-file output
(one Markdown file per top-level subcommand plus an index for injection into a
main README).

[oclif]: https://github.com/oclif/oclif/blob/main/src/readme-generator.ts

## Installation

Until the upstream `glint.document/1` API is merged + released to Hex, this
library depends on a fork of `glint` via git ref. Add both pinned to the same
fork commit:

```toml
# gleam.toml
[dependencies]
glint = { git = "https://github.com/tylerbutler/glint.git", ref = "26c55e3" }
glint_markdown = { git = "https://github.com/tylerbutler/glint_markdown.git", ref = "..." }
```

Once on Hex:

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

// Or just the generated sections, for injecting into an existing README:
let root = glint_markdown.to_root_body(tree, opts)
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

// Index body to inject into your main README between sentinel comments.
let index = glint_markdown.to_topics_index_body(tree, opts)
```

## Sentinel-comment injection

Mark up your README with sentinel comments and let `glint_markdown` rewrite the
content between them on every release. Mirrors oclif's `replaceTag`:

```markdown
<!-- root -->
<!-- rootstop -->

## Table of contents

<!-- toc -->
<!-- tocstop -->

## Commands

<!-- commands -->
<!-- commandsstop -->
```

```gleam
let readme = read_existing_readme()
let updated =
  readme
  |> glint_markdown.inject("root", glint_markdown.to_root_body(tree, opts))
  |> glint_markdown.inject("toc", glint_markdown.to_toc_body(tree, opts))
  |> glint_markdown.inject(
    "commands",
    glint_markdown.to_commands_body(tree, opts),
  )
```

`inject` is pure: if the start marker is missing the readme is returned
unchanged; if only the start marker is present the body and a fresh stop marker
are inserted after it.

## CLI integration: `gen-docs` subcommand

The companion module [`glint_markdown/cli`](./src/glint_markdown/cli.gleam)
ships a ready-made `gen-docs` subcommand you can mount into your own glint app
with a single line:

```gleam
import glint
import glint_markdown/cli as glint_markdown_cli

pub fn main() {
  glint.new()
  |> glint.with_name("myapp")
  |> glint.add(at: ["greet"], do: greet_cmd())
  |> glint_markdown_cli.mount(at: ["gen-docs"])
  |> glint.run(argv.load().arguments)
}
```

Now `myapp gen-docs [FLAGS]` renders the rest of your CLI as Markdown.

### Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--mode` | `single` | `single` (one document) or `multi` (one file per top-level subcommand) |
| `--out` | — | File path (single mode) or directory (multi mode, defaults to `./docs`) |
| `--readme` | — | Inject between `<!-- root -->`, `<!-- commands -->`, and `<!-- toc -->` sentinels in this file |
| `--repo-prefix` | — | Repository URL prefix used by `_See code:_` links |
| `--include-hidden` | `false` | Include hidden commands |
| `--no-toc` | `false` | Skip the table of contents in single-file mode |
| `--check` | `false` | Render + diff against disk; exit 1 if anything would change, write nothing — ideal for CI |
| `--quiet` | `false` | Suppress the "wrote N, injected M" summary line |

### ⚠️ `mount` restriction: `Glint(Nil)` only

`mount` is intentionally restricted to host apps whose command return type is
`Nil` — the overwhelmingly common case (most glint apps print directly and
return `Nil`). If your app is `Glint(a)` with `a != Nil`, use the lower-level
`glint_markdown_cli.command/1` and bridge the return type with
[`glint.map_command`](https://hexdocs.pm/glint/glint.html#map_command):

```gleam
let tree = glint.document(app)
let cmd =
  glint_markdown_cli.command(tree)
  |> glint.map_command(fn(_) { my_default_return_value })

app |> glint.add(at: ["gen-docs"], do: cmd)
```

The `gen-docs` command itself is intentionally **not** included in the
rendered tree — `mount` calls `glint.document` on the app *before* adding the
subcommand, mirroring the behaviour of oclif's `oclif readme`.

## Dependencies

- [`glint`](https://hex.pm/packages/glint) — the introspection API
  (`glint.document/1`, `glint/help`).
- [`glugify`](https://hex.pm/packages/glugify) — GitHub-style anchor slugs for
  the table of contents and cross-links.
- [`simplifile`](https://hex.pm/packages/simplifile) — used by the bundled
  `gen-docs` subcommand for filesystem IO. The core rendering API is IO-free
  and target-agnostic; only `glint_markdown/cli` and `glint_markdown/internal/io`
  touch the filesystem.

## License

Apache-2.0
