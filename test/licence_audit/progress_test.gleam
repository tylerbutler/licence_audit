import gleam/string
import gleeunit/should
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
  should.equal(progress.format_level(progress.InfoLevel, True), "")
  should.equal(progress.format_level(progress.InfoLevel, False), "")
  should.equal(progress.format_level(progress.DebugLevel, False), "debug")
}

pub fn minimal_level_formatter_keeps_icons_for_warn_and_error_test() {
  should.equal(progress.format_level(progress.WarnLevel, False), "⚠ warn")
  should.equal(progress.format_level(progress.ErrorLevel, False), "✖ error")
  should.equal(progress.format_level(progress.FatalLevel, False), "✖ fatal")
}

pub fn format_tty_record_hides_source_and_vertical_bars_test() {
  let entry =
    progress.LogEntry(
      level: progress.WarnLevel,
      logger_name: "check",
      message: "Audit warning",
      metadata: [],
    )
  let line = progress.format_tty_record(entry, False)

  should.equal(string.contains(line, "|"), False)
  should.equal(string.contains(line, "check"), False)
  should.equal(line, "⚠ warn Audit warning")
}

pub fn format_tty_info_record_keeps_message_without_level_prefix_test() {
  let entry =
    progress.LogEntry(
      level: progress.InfoLevel,
      logger_name: "check",
      message: "Starting licence audit",
      metadata: [],
    )
  let line = progress.format_tty_record(entry, False)

  should.equal(line, "Starting licence audit")
}

pub fn format_tty_warning_record_uses_colored_semantic_rendering_test() {
  let entry =
    progress.LogEntry(
      level: progress.WarnLevel,
      logger_name: "check",
      message: "Audit warning",
      metadata: [],
    )
  let line = progress.format_tty_record(entry, True)

  should.equal(string.contains(line, "Audit warning"), True)
  should.equal(string.contains(line, "\u{1b}["), True)
}

pub fn format_standard_record_keeps_category_and_level_test() {
  let entry =
    progress.LogEntry(
      level: progress.InfoLevel,
      logger_name: "report",
      message: "Audit complete",
      metadata: [],
    )
  let line = progress.format_standard_record(entry, False)

  should.equal(string.contains(line, "|"), True)
  should.equal(string.contains(line, "report"), True)
  should.equal(line, "INFO  | report | Audit complete")
  should.equal(string.starts_with(line, "INFO"), True)
}
