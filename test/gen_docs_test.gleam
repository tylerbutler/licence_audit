import gleam/list
import gleam/string
import licence_audit/cli
import licence_audit/gen_docs
import licence_audit/internal/vendor/glint

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
    && string.contains(body, "`--license-text`")
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
