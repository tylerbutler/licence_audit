import birch/level
import birch/level_formatter
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
  let formatter = progress.minimal_level_formatter()
  should.equal(level_formatter.format_level(formatter, level.Info, False), "info")
  should.equal(level_formatter.format_level(formatter, level.Info, True), "")
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
