import birch/level
import birch/level_formatter
import birch/record
import gleeunit/should
import gleam/string
import licence_audit/progress
import tty

pub fn stderr_color_enabled_rejects_no_color_test() {
  should.equal(progress.stderr_color_enabled(tty.NoColor), False)
}

pub fn stderr_color_enabled_accepts_any_color_level_test() {
  should.equal(progress.stderr_color_enabled(tty.Basic), True)
  should.equal(progress.stderr_color_enabled(tty.Ansi256), True)
  should.equal(progress.stderr_color_enabled(tty.TrueColor), True)
}

pub fn minimal_level_formatter_is_plain_for_non_error_levels_test() {
  let formatter = progress.minimal_level_formatter()
  should.equal(level_formatter.format_level(formatter, level.Info, True), "")
  should.equal(level_formatter.format_level(formatter, level.Info, False), "")
  should.equal(
    level_formatter.format_level(formatter, level.Debug, False),
    "debug",
  )
}

pub fn minimal_level_formatter_keeps_icons_for_warn_and_error_test() {
  let formatter = progress.minimal_level_formatter()
  should.equal(level_formatter.format_level(formatter, level.Warn, False), "⚠ warn")
  should.equal(level_formatter.format_level(formatter, level.Err, False), "✖ error")
  should.equal(level_formatter.format_level(formatter, level.Fatal, False), "✖ fatal")
}

pub fn format_tty_record_hides_source_and_vertical_bars_test() {
  let record =
    record.new(
      timestamp: "2026-05-26T00:00:00.000Z",
      level: level.Warn,
      logger_name: "check",
      message: "Audit warning",
      metadata: [],
    )
  let line = progress.format_tty_record(record, False)

  should.equal(string.contains(line, "|"), False)
  should.equal(string.contains(line, "check"), False)
  should.equal(line, "⚠ warn Audit warning")
}

pub fn format_standard_record_keeps_category_and_level_test() {
  let record =
    record.new(
      timestamp: "2026-05-26T00:00:00.000Z",
      level: level.Info,
      logger_name: "report",
      message: "Audit complete",
      metadata: [],
    )
  let line = progress.format_standard_record(record, False)

  should.equal(string.contains(line, "|"), True)
  should.equal(string.contains(line, "report"), True)
  should.equal(string.starts_with(line, "INFO"), True)
}
