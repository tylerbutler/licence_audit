import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import gleeunit/should
import licence_audit/color
import licence_audit/exception
import licence_audit/manifest
import licence_audit/policy
import licence_audit/report

const off = color.Palette(enabled: False)

const on = color.Palette(enabled: True)

fn row(name: String, status: report.Status) -> report.Row {
  report.Row(
    package: name,
    version: "1.0.0",
    licences: ["GPL-3.0-only", "Apache-2.0"],
    status: status,
    scope: manifest.Prod,
    path: [name],
  )
}

fn review(expires: Option(String)) -> exception.Exception {
  exception.Exception(
    number: 1,
    purl: "pkg:hex/reviewed@1.0.0",
    finding: exception.DeniedLicence("GPL-3.0-only"),
    reason: "Reviewed use",
    expires: expires,
  )
}

pub fn counts_partition_unique_packages_and_unaccepted_findings_test() {
  let accepted = exception.Excepted(review(None))
  let rows = [
    row("allowed", report.Checked(policy.Allowed)),
    report.Row(
      ..row("allowed", report.Checked(policy.Allowed)),
      scope: manifest.Dev,
    ),
    row(
      "denied",
      report.Checked(
        policy.audit(policy.Policy(allow: ["MIT"], deny: ["GPL-3.0-only"]), [
          "Apache-2.0",
          "GPL-3.0-only",
          "MIT",
        ]),
      ),
    ),
    row("unknown", report.Checked(policy.UnallowedLicence("Apache-2.0"))),
    row("empty", report.Checked(policy.NoLicencesDeclared)),
    row("invalid", report.Checked(policy.InvalidLicenceExpression("MIT AND"))),
    row(
      "reviewed",
      report.Reviewed([
        #(exception.DeniedLicence("GPL-3.0-only"), accepted),
      ]),
    ),
    row(
      "partial_review",
      report.Reviewed([
        #(exception.DeniedLicence("GPL-3.0-only"), accepted),
        #(exception.UnallowedLicence("Apache-2.0"), exception.Unaccepted),
      ]),
    ),
    row(
      "expired",
      report.Reviewed([
        #(
          exception.DeniedLicence("GPL-3.0-only"),
          exception.Expired(review(Some("2000-01-01"))),
        ),
        #(exception.UnallowedLicence("Apache-2.0"), exception.Unaccepted),
      ]),
    ),
    row("unavailable", report.Failed("metadata unavailable")),
    row("unchecked", report.NotChecked),
    row("git_dep", report.Skipped("git")),
  ]
  let summary =
    report.Summary(skipped_names: ["git_dep", "git_dep", "local_dep"])
  let counts = report.counts(rows, summary)
  should.equal(
    counts,
    report.Counts(
      total: 12,
      allowed: 1,
      denied: 2,
      unknown: 6,
      excepted: 1,
      skipped: 2,
    ),
  )
  let output = report.format_with_counts([], summary, counts, report.Audit, off)
  assert string.contains(
    output,
    "12 packages: 1 allowed, 2 denied, 6 unknown, 1 excepted, 2 skipped",
  )
  assert string.contains(
    output,
    "Skipped non-Hex packages: 2 (git_dep, local_dep)",
  )
}

pub fn empty_and_unchecked_reports_do_not_claim_allowance_test() {
  let empty = report.format([], report.Summary([]), report.Default, off)
  assert string.contains(
    empty,
    "0 packages: 0 allowed, 0 denied, 0 unknown, 0 excepted, 0 skipped",
  )
  let unchecked =
    report.format(
      [row("unchecked", report.NotChecked)],
      report.Summary([]),
      report.Default,
      off,
    )
  assert string.contains(
    unchecked,
    "1 packages: 0 allowed, 0 denied, 1 unknown, 0 excepted, 0 skipped",
  )
}

pub fn findings_footer_reuses_rows_once_and_excludes_accepted_packages_test() {
  let denied =
    row("denied_pkg", report.Checked(policy.DeniedLicence("GPL-3.0-only")))
  let partial =
    row(
      "partial_pkg",
      report.Reviewed([
        #(
          exception.DeniedLicence("GPL-3.0-only"),
          exception.Excepted(review(None)),
        ),
        #(exception.UnallowedLicence("Apache-2.0"), exception.Unaccepted),
      ]),
    )
  let rows = [
    denied,
    report.Row(..denied, path: ["another_root", "denied_pkg"]),
    partial,
    row(
      "accepted_pkg",
      report.Reviewed([
        #(
          exception.DeniedLicence("GPL-3.0-only"),
          exception.Excepted(review(None)),
        ),
      ]),
    ),
    row("allowed_pkg", report.Checked(policy.Allowed)),
    row("skipped_pkg", report.Skipped("git")),
    report.Row(
      ..row("missing_pkg", report.Failed("metadata unavailable")),
      licences: [],
    ),
  ]
  use palette <- list.each([off, on])
  let output = report.format_findings(rows, palette)
  assert string.starts_with(output, "Packages with findings:\n")
  should.equal(count_substrings(output, "denied_pkg"), 1)
  should.equal(count_substrings(output, "partial_pkg"), 1)
  should.equal(count_substrings(output, "missing_pkg"), 1)
  assert string.contains(output, "1.0.0")
  assert string.contains(output, "Apache-2.0, GPL-3.0-only")
  assert string.contains(output, "denied: GPL-3.0-only")
  assert string.contains(output, "unknown: Apache-2.0")
  assert string.contains(output, "Reviewed use")
  assert string.contains(output, "error: metadata unavailable")
  assert !string.contains(output, "accepted_pkg")
  assert !string.contains(output, "allowed_pkg")
  assert !string.contains(output, "skipped_pkg")
  should.equal(string.contains(output, "\u{001b}["), palette.enabled)
}

pub fn audit_report_includes_status_column_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "gleam_stdlib",
          version: "1.0.0",
          licences: ["MIT"],
          status: report.Checked(policy.Allowed),
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

pub fn default_report_does_not_pad_licences_inside_ansi_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "short_licence",
          version: "1.0.0",
          licences: ["MIT"],
          status: report.NotChecked,
          scope: manifest.Prod,
          path: [],
        ),
        report.Row(
          package: "long_licence",
          version: "1.0.0",
          licences: ["Apache-2.0"],
          status: report.NotChecked,
          scope: manifest.Prod,
          path: [],
        ),
      ],
      report.Summary(skipped_names: []),
      report.Default,
      on,
    )

  assert string.contains(output, "MIT\u{001b}[")
  assert !string.contains(output, "MIT       \u{001b}[")
}

pub fn tree_width_uses_rendered_depth_when_intermediate_is_skipped_test() {
  let output =
    report.format(
      [
        report.Row(
          package: "root",
          version: "1.0.0",
          licences: ["MIT"],
          status: report.NotChecked,
          scope: manifest.Prod,
          path: ["root"],
        ),
        report.Row(
          package: "leaf",
          version: "1.1.0",
          licences: ["MIT"],
          status: report.NotChecked,
          scope: manifest.Prod,
          path: ["root", "git_dependency", "leaf"],
        ),
      ],
      report.Summary(skipped_names: []),
      report.Default,
      off,
    )

  assert string.contains(
    output,
    "? root     1.0.0    MIT\n└─ ? leaf  1.1.0    MIT\n",
  )
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
          scope: manifest.Prod,
          path: [],
        ),
      ],
      report.Summary(skipped_names: []),
      report.Default,
      off,
    )

  assert string.contains(output, "? pkg      1.0.0    -\n")
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
          scope: manifest.Prod,
          path: [],
        ),
        report.Row(
          package: "dev_pkg",
          version: "2.0.0",
          licences: ["MIT"],
          status: report.NotChecked,
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
          scope: manifest.Prod,
          path: [],
        ),
        report.Row(
          package: "dev_pkg",
          version: "2.0.0",
          licences: ["MIT"],
          status: report.NotChecked,
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
          scope: manifest.Prod,
          path: [],
        ),
        report.Row(
          package: "dev_pkg",
          version: "2.0.0",
          licences: ["MIT"],
          status: report.NotChecked,
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
    "? prod_pkg  1.0.0    MIT\n\nDEVELOPMENT DEPENDENCIES",
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
