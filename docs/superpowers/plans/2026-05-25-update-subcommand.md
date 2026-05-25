# Update Subcommand Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore `licence_audit update` as a supported CLI subcommand with parser coverage and README documentation.

**Architecture:** The update runtime already exists in `src/licence_audit/update.gleam` and is already wired through `src/licence_audit.gleam`. This plan restores the CLI registration in `src/licence_audit/cli.gleam`, adds parser tests in `test/licence_audit/cli_test.gleam`, and documents the command in `README.md` without changing update runtime behavior.

**Tech Stack:** Gleam, glint CLI parser, gleeunit tests, Markdown documentation.

---

## File structure

- Modify `src/licence_audit/cli.gleam`: remove the 1.0 feature gate and always register `update_command()`.
- Modify `test/licence_audit/cli_test.gleam`: add a helper for parsing update options and tests for defaults, flags, and help visibility.
- Modify `README.md`: add a short usage section for `licence_audit update`.

### Task 1: Add failing CLI parser coverage

**Files:**
- Modify: `test/licence_audit/cli_test.gleam`

- [ ] **Step 1: Add an update parser helper**

Add this helper after `parse_options`:

```gleam
fn parse_update_options(args: List(String)) -> cli.UpdateOptions {
  let assert Ok(glint.Out(cli.UpdateConfig(options))) =
    glint.execute(cli.app(), args)
  options
}
```

- [ ] **Step 2: Add update subcommand tests**

Add these tests after `check_subcommand_is_listed_in_help_test`:

```gleam
pub fn update_subcommand_is_listed_in_help_test() {
  let help = help_text(["--help"])

  assert string.contains(help, "update")
}

pub fn update_subcommand_parses_defaults_test() {
  let options = parse_update_options(["update"])

  should.equal(options.manifest_path, None)
  should.equal(options.config_path, None)
  should.equal(options.ignore_config, False)
  should.equal(options.verbosity, progress.Normal)
  should.equal(options.color, color.Auto)
  should.equal(options.no_cache, False)
  should.equal(options.cache_path, None)
}

pub fn update_subcommand_parses_supported_flags_test() {
  let options =
    parse_update_options([
      "update",
      "--config=audit.toml",
      "--manifest=locked.toml",
      "--ignore-config",
      "--verbose",
      "--color=never",
      "--no-cache",
      "--cache-path=/tmp/licence-audit.dets",
    ])

  should.equal(options.config_path, Some("audit.toml"))
  should.equal(options.manifest_path, Some("locked.toml"))
  should.equal(options.ignore_config, True)
  should.equal(options.verbosity, progress.Verbose)
  should.equal(options.color, color.Never)
  should.equal(options.no_cache, True)
  should.equal(options.cache_path, Some("/tmp/licence-audit.dets"))
}
```

- [ ] **Step 3: Run tests to verify the new tests fail**

Run:

```sh
gleam test
```

Expected: at least the update parser tests fail because `update` is not registered while `update_command_enabled` is `False`.

- [ ] **Step 4: Commit the failing tests**

```sh
git add test/licence_audit/cli_test.gleam
git commit -m "test: cover update subcommand parsing"
```

### Task 2: Re-enable the CLI subcommand

**Files:**
- Modify: `src/licence_audit/cli.gleam`
- Test: `test/licence_audit/cli_test.gleam`

- [ ] **Step 1: Register update unconditionally**

In `src/licence_audit/cli.gleam`, replace lines 70-94 with:

```gleam
pub fn app() -> glint.Glint(CliAction) {
  glint.new()
  |> glint.with_name("licence_audit")
  |> glint.global_help("Audit locked Hex package licences.")
  |> glint.pretty_help(glint.default_pretty_help())
  |> glint.add(at: [], do: audit_command(check_mode: False, help: root_help))
  |> glint.add(
    at: ["check"],
    do: audit_command(check_mode: True, help: check_help),
  )
  |> glint.add(at: ["update"], do: update_command())
  |> glint.add(at: ["sbom"], do: sbom_command())
  |> glint.add(at: ["vulns"], do: vulns_command())
}
```

- [ ] **Step 2: Run parser tests**

Run:

```sh
gleam test
```

Expected: all tests pass.

- [ ] **Step 3: Commit the implementation**

```sh
git add src/licence_audit/cli.gleam
git commit -m "feat: re-enable update subcommand"
```

### Task 3: Document update usage

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add README usage text**

Insert this section after the paragraph about root-level `--allow` and `--deny` and before `### Generating an SBOM`:

````markdown
### Updating licence policy

Interactively discover licences from the locked manifest and write the selected policy to `[tools.licence_audit]`:

```sh
licence_audit update
licence_audit update --config=path/to/gleam.toml
```

The `update` subcommand fetches package metadata, preselects any existing allow and deny entries from configuration, prompts for the licences to allow or deny, and writes the result back to `gleam.toml` unless `--config` points at another TOML file.
````

- [ ] **Step 2: Inspect Markdown fence nesting**

Run:

```sh
sed -n '48,90p' README.md
```

Expected: the new `### Updating licence policy` section appears between the general usage options and the SBOM section, with the shell code block closed before the explanatory paragraph.

- [ ] **Step 3: Commit documentation**

```sh
git add README.md
git commit -m "docs: document update subcommand"
```

### Task 4: Final validation

**Files:**
- Check: `src/licence_audit/cli.gleam`
- Check: `test/licence_audit/cli_test.gleam`
- Check: `README.md`

- [ ] **Step 1: Run full test suite**

Run:

```sh
gleam test
```

Expected: all tests pass.

- [ ] **Step 2: Confirm update appears in CLI help**

Run:

```sh
gleam run -- --help | grep update
```

Expected: output includes `update`.

- [ ] **Step 3: Confirm final diff is scoped**

Run:

```sh
git --no-pager diff --stat HEAD~3..HEAD
git --no-pager status --short
```

Expected: committed changes include only `src/licence_audit/cli.gleam`, `test/licence_audit/cli_test.gleam`, and `README.md` for implementation, plus the previously committed design/plan docs. Any pre-existing `gleam.toml` modification remains separate and is not reverted.
