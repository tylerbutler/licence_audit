import gleam/list
import gleam/string
import licence_audit/cli
import licence_audit/gen_docs
import licence_audit/internal/vendor/glint
import simplifile

pub fn all_cli_commands_have_reference_pages_test() {
  let tree = glint.document(cli.app())
  let pages = gen_docs.reference_pages(tree)
  assert list.length(pages) == list.length(tree.subcommands) + 1
  let assert [#(path, root), ..commands] = pages
  assert path == "website/src/pages/docs/index.md"
  assert string.contains(root, "`--version`")
  list.each(tree.subcommands, fn(command) {
    assert list.any(commands, fn(page) {
      let #(path, body) = page
      path == "website/src/pages/docs/" <> command.meta.name <> ".md"
      && string.contains(body, "licence_audit " <> command.meta.name)
    })
  })
  assert list.any(commands, fn(page) {
    let #(path, body) = page
    path == "website/src/pages/docs/sbom.md"
    && string.contains(body, "`--licence-text`")
    && string.contains(body, "alias: --license-text")
    && string.contains(body, "conflicts with --offline")
  })
}

pub fn injection_preserves_guide_and_is_idempotent_test() {
  let before = "---\ntitle: Guide\n---\n\nHuman prose.\n## Flags\n"
  let after = "\n\n[Source](https://example.com)\n"
  let existing =
    before
    <> "<!-- cli-reference -->\nstale\n<!-- cli-referencestop -->"
    <> after
  let assert Ok(updated) = gen_docs.update_page("guide.md", existing, "fresh")
  assert updated
    == before
    <> "<!-- cli-reference -->\nfresh\n<!-- cli-referencestop -->"
    <> after
  assert gen_docs.update_page("guide.md", updated, "fresh") == Ok(updated)
  assert updated != existing
}

pub fn injection_preserves_block_line_endings_and_detects_drift_test() -> Nil {
  use newline <- list.each(["\n", "\r\n"])
  // Authored regions can use different line endings from the generated block.
  let before = "\u{feff}---\r\ntitle: Guide\r\n---\n\nHuman prose.\n"
  let after = "\r\n\r\n[Source](https://example.com)\n"
  let existing =
    before
    <> "<!-- cli-reference -->"
    <> newline
    <> "first"
    <> newline
    <> "second"
    <> newline
    <> "<!-- cli-referencestop -->"
    <> after
  use reference <- list.each(["first\nsecond", "first\r\nsecond"])
  assert gen_docs.update_page("guide.md", existing, reference) == Ok(existing)
  let assert Ok(updated) =
    gen_docs.update_page("guide.md", existing, reference <> "\nthird")
  assert updated
    == before
    <> "<!-- cli-reference -->"
    <> newline
    <> "first"
    <> newline
    <> "second"
    <> newline
    <> "third"
    <> newline
    <> "<!-- cli-referencestop -->"
    <> after
  assert updated != existing
  assert gen_docs.update_page("guide.md", updated, reference <> "\nthird")
    == Ok(updated)
}

pub fn malformed_markers_are_errors_test() {
  list.each(
    [
      "",
      "<!-- cli-reference -->",
      "<!-- cli-referencestop -->",
      "<!-- cli-referencestop --><!-- cli-reference -->",
      "<!-- cli-reference --><!-- cli-reference --><!-- cli-referencestop -->",
      "<!-- cli-reference --><!-- cli-referencestop --><!-- cli-referencestop -->",
    ],
    fn(existing) {
      let assert Error(message) =
        gen_docs.update_page("guide.md", existing, "fresh")
      assert string.contains(message, "guide.md")
    },
  )
}

pub fn generated_tables_match_help_value_forms_test() {
  use #(path, body) <- list.each(
    gen_docs.reference_pages(glint.document(cli.app())),
  )
  assert string.contains(
    body,
    "| `--color=<auto\\|always\\|never>` | `auto\\|always\\|never` |",
  )
  assert string.contains(body, "| `--manifest=<PATH>` | `PATH` |")
  assert !string.contains(body, "--quiet=")
  assert !string.contains(body, "`STRING`")
  case string.ends_with(path, "/check.md") {
    True -> {
      assert string.contains(body, "| `--checks=<licences\\|vulns\\|all>` |")
      assert string.contains(
        body,
        "| `--vuln-severity=<low\\|medium\\|high\\|critical>` |",
      )
      assert !string.contains(body, "licenses")
    }
    False -> Nil
  }
  let assert Ok(existing) = simplifile.read(path)
  assert gen_docs.update_page(path, existing, body) == Ok(existing)
  let windows =
    existing |> string.replace("\r\n", "\n") |> string.replace("\n", "\r\n")
  assert gen_docs.update_page(path, windows, body) == Ok(windows)
}
