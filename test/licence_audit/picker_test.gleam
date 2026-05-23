import gleeunit/should
import licence_audit/picker

pub fn pick_with_terminal_check_rejects_non_tty_stdin_test() {
  should.equal(
    picker.pick_with_terminal_check(
      "Choose licence policy:",
      [],
      [],
      [],
      stdin_is_tty: fn() { False },
      stdout_is_tty: fn() { True },
    ),
    Error(picker.NotInteractive),
  )
}

pub fn pick_with_terminal_check_rejects_non_tty_stdout_test() {
  should.equal(
    picker.pick_with_terminal_check(
      "Choose licence policy:",
      [],
      [],
      [],
      stdin_is_tty: fn() { True },
      stdout_is_tty: fn() { False },
    ),
    Error(picker.NotInteractive),
  )
}
