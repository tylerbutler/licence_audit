import gleam/string
import licence_audit/color
import licence_audit/manifest
import licence_audit/policy
import licence_audit/report

const off = color.Palette(enabled: False)

const on = color.Palette(enabled: True)

pub fn audit_report_includes_status_column_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "gleam_stdlib",
          version: "1.0.0",
          licences: ["MIT"],
          status: report.Checked(policy.Allowed),
          kind: manifest.Direct,
          scope: manifest.Prod,
          path: [],
        ),
      ],
      report.Summary(skipped_names: []),
      report.Audit,
      off,
    )

  assert string.starts_with(
    output,
    "PRODUCTION DEPENDENCIES\n  Package       Version  Licences  Status",
  )
  assert string.contains(output, "✓ gleam_stdlib  1.0.0    MIT       allowed")
}

pub fn default_report_omits_status_column_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "gleam_stdlib",
          version: "1.0.0",
          licences: ["MIT"],
          status: report.NotChecked,
          kind: manifest.Direct,
          scope: manifest.Prod,
          path: [],
        ),
      ],
      report.Summary(skipped_names: []),
      report.Default,
      off,
    )

  assert string.starts_with(
    output,
    "PRODUCTION DEPENDENCIES\n  Package       Version  Licences",
  )
  assert !string.contains(output, "Status")
  assert string.contains(output, "? gleam_stdlib  1.0.0    MIT")
}

pub fn licences_are_sorted_and_deduplicated_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "pkg",
          version: "1.0.0",
          licences: ["MIT", "Apache-2.0", "MIT", "BSD-3-Clause"],
          status: report.NotChecked,
          kind: manifest.Direct,
          scope: manifest.Prod,
          path: [],
        ),
      ],
      report.Summary(skipped_names: []),
      report.Default,
      off,
    )

  assert string.contains(output, "Apache-2.0, BSD-3-Clause, MIT")
}

pub fn empty_licences_render_as_dash_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "pkg",
          version: "1.0.0",
          licences: [],
          status: report.NotChecked,
          kind: manifest.Direct,
          scope: manifest.Prod,
          path: [],
        ),
      ],
      report.Summary(skipped_names: []),
      report.Default,
      off,
    )

  assert string.contains(output, "? pkg      1.0.0    -       \n")
}

pub fn fetch_or_read_failures_appear_in_report_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "missing_pkg",
          version: "2.0.0",
          licences: [],
          status: report.Failed("Hex package metadata fetch failed"),
          kind: manifest.Direct,
          scope: manifest.Prod,
          path: [],
        ),
      ],
      report.Summary(skipped_names: []),
      report.Audit,
      off,
    )

  assert string.contains(output, "? missing_pkg")
  assert string.contains(output, "2.0.0")
  assert string.contains(output, "Hex package metadata fetch failed")
}

pub fn skipped_non_hex_package_count_appears_in_summary_test() {
  let output =
    report.format(
      [],
      report.Summary(skipped_names: ["local_dep", "git_dep"]),
      report.Default,
      off,
    )

  assert string.contains(output, "Skipped non-Hex packages: 2")
}

pub fn skipped_non_hex_package_names_appear_in_summary_test() {
  let output =
    report.format(
      [],
      report.Summary(skipped_names: ["local_dep", "git_dep"]),
      report.Default,
      off,
    )

  // Names are listed (sorted) so the user knows what was omitted (issue #3).
  assert string.contains(
    output,
    "Skipped non-Hex packages: 2 (git_dep, local_dep)",
  )
}

pub fn empty_skipped_summary_lists_no_names_test() {
  let output =
    report.format([], report.Summary(skipped_names: []), report.Default, off)

  assert string.contains(output, "Skipped non-Hex packages: 0")
  assert !string.contains(output, "(")
}

pub fn denied_row_has_red_cross_glyph_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "pkg",
          version: "1.0.0",
          licences: ["GPL-3.0"],
          status: report.Checked(policy.DeniedLicence("GPL-3.0")),
          kind: manifest.Direct,
          scope: manifest.Prod,
          path: [],
        ),
      ],
      report.Summary(skipped_names: []),
      report.Audit,
      off,
    )

  assert string.contains(output, "✗ pkg")
}

pub fn enabled_palette_emits_ansi_for_allowed_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "gleam_stdlib",
          version: "1.0.0",
          licences: ["MIT"],
          status: report.Checked(policy.Allowed),
          kind: manifest.Direct,
          scope: manifest.Prod,
          path: [],
        ),
      ],
      report.Summary(skipped_names: []),
      report.Audit,
      on,
    )

  // ANSI green sequence wraps the check glyph.
  assert string.contains(output, "\u{001b}[")
  assert string.contains(output, "✓")
}

pub fn enabled_palette_emits_ansi_for_default_question_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "pkg",
          version: "1.0.0",
          licences: ["MIT"],
          status: report.NotChecked,
          kind: manifest.Direct,
          scope: manifest.Prod,
          path: [],
        ),
      ],
      report.Summary(skipped_names: []),
      report.Default,
      on,
    )

  assert string.contains(output, "\u{001b}[")
  assert string.contains(output, "?")
}

pub fn enabled_palette_styles_production_section_title_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "prod_pkg",
          version: "1.0.0",
          licences: ["MIT"],
          status: report.NotChecked,
          kind: manifest.Direct,
          scope: manifest.Prod,
          path: [],
        ),
      ],
      report.Summary(skipped_names: []),
      report.Default,
      on,
    )

  assert string.contains(output, "\u{001b}[")
  assert string.contains(output, "PRODUCTION DEPENDENCIES")
  assert string.contains(output, "\u{001b}[1m")
  assert string.contains(output, "\u{001b}[4m")
  assert string.contains(output, "\u{001b}[32m")
}

pub fn enabled_palette_styles_development_section_title_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "dev_pkg",
          version: "2.0.0",
          licences: ["MIT"],
          status: report.NotChecked,
          kind: manifest.Direct,
          scope: manifest.Dev,
          path: [],
        ),
      ],
      report.Summary(skipped_names: []),
      report.Default,
      on,
    )

  assert string.contains(output, "\u{001b}[")
  assert string.contains(output, "DEVELOPMENT DEPENDENCIES")
  assert string.contains(output, "\u{001b}[1m")
  assert string.contains(output, "\u{001b}[4m")
  assert string.contains(output, "\u{001b}[36m")
}

pub fn enabled_palette_styles_table_header_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "pkg",
          version: "1.0.0",
          licences: ["MIT"],
          status: report.Checked(policy.Allowed),
          kind: manifest.Direct,
          scope: manifest.Prod,
          path: [],
        ),
      ],
      report.Summary(skipped_names: []),
      report.Audit,
      on,
    )

  assert string.contains(output, "\u{001b}[1m")
  assert string.contains(output, "\u{001b}[4m")
  assert string.contains(output, "\u{001b}[1m  Package")
  assert string.contains(output, "Version")
  assert string.contains(output, "Licences")
  assert string.contains(output, "Status")
}

pub fn disabled_palette_renders_plain_uppercase_section_title_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "prod_pkg",
          version: "1.0.0",
          licences: ["MIT"],
          status: report.NotChecked,
          kind: manifest.Direct,
          scope: manifest.Prod,
          path: [],
        ),
      ],
      report.Summary(skipped_names: []),
      report.Default,
      off,
    )

  assert string.starts_with(output, "PRODUCTION DEPENDENCIES\n  Package")
  assert !string.contains(output, "\u{001b}[")
}

pub fn report_omits_legacy_emoji_column_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "pkg",
          version: "1.0.0",
          licences: ["Apache-2.0"],
          status: report.NotChecked,
          kind: manifest.Direct,
          scope: manifest.Prod,
          path: [],
        ),
      ],
      report.Summary(skipped_names: []),
      report.Default,
      off,
    )

  assert !string.contains(output, "🪶")
}

pub fn report_omits_legacy_joined_emoji_column_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "pkg",
          version: "1.0.0",
          licences: ["MIT", "Apache-2.0"],
          status: report.NotChecked,
          kind: manifest.Direct,
          scope: manifest.Prod,
          path: [],
        ),
      ],
      report.Summary(skipped_names: []),
      report.Default,
      off,
    )

  assert !string.contains(output, "🪶 🎓")
}

pub fn allowed_licences_text_is_green_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "pkg",
          version: "1.0.0",
          licences: ["MIT"],
          status: report.Checked(policy.Allowed),
          kind: manifest.Direct,
          scope: manifest.Prod,
          path: [],
        ),
      ],
      report.Summary(skipped_names: []),
      report.Audit,
      on,
    )

  // ANSI green for both glyph and licences. Two SGR sequences expected.
  let escapes = count_substrings(output, "\u{001b}[")
  assert escapes >= 2
  assert string.contains(output, "MIT")
}

pub fn denied_licences_text_is_red_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "pkg",
          version: "1.0.0",
          licences: ["GPL-3.0"],
          status: report.Checked(policy.DeniedLicence("GPL-3.0")),
          kind: manifest.Direct,
          scope: manifest.Prod,
          path: [],
        ),
      ],
      report.Summary(skipped_names: []),
      report.Audit,
      on,
    )

  let escapes = count_substrings(output, "\u{001b}[")
  assert escapes >= 2
  assert string.contains(output, "GPL-3.0")
}

fn count_substrings(haystack: String, needle: String) -> Int {
  string.split(haystack, on: needle) |> list_length_minus_one
}

fn list_length_minus_one(parts: List(String)) -> Int {
  case parts {
    [] -> 0
    [_, ..rest] -> count_rest(rest, 0)
  }
}

fn count_rest(parts: List(String), acc: Int) -> Int {
  case parts {
    [] -> acc
    [_, ..rest] -> count_rest(rest, acc + 1)
  }
}

pub fn report_groups_prod_and_dev_sections_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "prod_pkg",
          version: "1.0.0",
          licences: ["MIT"],
          status: report.NotChecked,
          kind: manifest.Direct,
          scope: manifest.Prod,
          path: [],
        ),
        report.Row(
          package: "dev_pkg",
          version: "2.0.0",
          licences: ["MIT"],
          status: report.NotChecked,
          kind: manifest.Direct,
          scope: manifest.Dev,
          path: [],
        ),
      ],
      report.Summary(skipped_names: []),
      report.Default,
      off,
    )

  assert string.contains(output, "PRODUCTION DEPENDENCIES")
  assert string.contains(output, "DEVELOPMENT DEPENDENCIES")
  assert string.contains(output, "prod_pkg")
  assert string.contains(output, "dev_pkg")
}

pub fn report_renders_header_inside_each_dependency_group_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "prod_pkg",
          version: "1.0.0",
          licences: ["MIT"],
          status: report.NotChecked,
          kind: manifest.Direct,
          scope: manifest.Prod,
          path: [],
        ),
        report.Row(
          package: "dev_pkg",
          version: "2.0.0",
          licences: ["MIT"],
          status: report.NotChecked,
          kind: manifest.Direct,
          scope: manifest.Dev,
          path: [],
        ),
      ],
      report.Summary(skipped_names: []),
      report.Default,
      off,
    )

  assert string.contains(output, "PRODUCTION DEPENDENCIES\n  Package")
  assert string.contains(output, "DEVELOPMENT DEPENDENCIES\n  Package")
}

pub fn report_separates_dependency_groups_with_blank_line_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "prod_pkg",
          version: "1.0.0",
          licences: ["MIT"],
          status: report.NotChecked,
          kind: manifest.Direct,
          scope: manifest.Prod,
          path: [],
        ),
        report.Row(
          package: "dev_pkg",
          version: "2.0.0",
          licences: ["MIT"],
          status: report.NotChecked,
          kind: manifest.Direct,
          scope: manifest.Dev,
          path: [],
        ),
      ],
      report.Summary(skipped_names: []),
      report.Default,
      off,
    )

  assert string.contains(
    output,
    "? prod_pkg  1.0.0    MIT     \n\nDEVELOPMENT DEPENDENCIES",
  )
}

pub fn report_leaves_blank_line_before_deferred_logs_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "prod_pkg",
          version: "1.0.0",
          licences: ["MIT"],
          status: report.NotChecked,
          kind: manifest.Direct,
          scope: manifest.Prod,
          path: [],
        ),
      ],
      report.Summary(skipped_names: []),
      report.Default,
      off,
    )

  assert string.ends_with(output, "Skipped non-Hex packages: 0\n\n")
}

pub fn report_omits_empty_dev_section_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "prod_pkg",
          version: "1.0.0",
          licences: ["MIT"],
          status: report.NotChecked,
          kind: manifest.Direct,
          scope: manifest.Prod,
          path: [],
        ),
      ],
      report.Summary(skipped_names: []),
      report.Default,
      off,
    )

  assert string.contains(output, "PRODUCTION DEPENDENCIES")
  assert !string.contains(output, "DEVELOPMENT DEPENDENCIES")
}
