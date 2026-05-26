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
