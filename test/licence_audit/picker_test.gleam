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

pub fn cycle_at_index_cycles_allow_deny_ignore_and_wraps_test() {
  let state = picker.new_state("Choose licence policy:", ["MIT"], ["MIT"], [])

  let deny = picker.cycle_at_index(state, 0)
  should.equal(picker.state_choices(deny), [#("MIT", picker.Deny)])

  let ignore = picker.cycle_at_index(deny, 0)
  should.equal(picker.state_choices(ignore), [#("MIT", picker.Ignore)])

  let allow = picker.cycle_at_index(ignore, 0)
  should.equal(picker.state_choices(allow), [#("MIT", picker.Allow)])
}

pub fn apply_to_all_keys_set_every_label_test() {
  let state =
    picker.new_state("Choose licence policy:", ["MIT", "GPL-3.0"], [], [])

  should.equal(
    picker.state_choices(picker.handle_picker_key(state, picker.AllowAll)),
    [#("MIT", picker.Allow), #("GPL-3.0", picker.Allow)],
  )
  should.equal(
    picker.state_choices(picker.handle_picker_key(state, picker.DenyAll)),
    [#("MIT", picker.Deny), #("GPL-3.0", picker.Deny)],
  )
  should.equal(
    picker.state_choices(picker.handle_picker_key(state, picker.IgnoreAll)),
    [#("MIT", picker.Ignore), #("GPL-3.0", picker.Ignore)],
  )
}

pub fn build_selection_excludes_ignored_and_prefers_allow_test() {
  let state =
    picker.new_state(
      "Choose licence policy:",
      ["MIT", "Apache-2.0", "GPL-3.0", "BSD-3-Clause"],
      ["MIT", "Apache-2.0"],
      ["Apache-2.0", "GPL-3.0"],
    )

  should.equal(
    picker.state_selection(state),
    picker.Selection(allow: ["MIT", "Apache-2.0"], deny: ["GPL-3.0"]),
  )
}

pub fn cycle_at_index_handles_boundaries_and_empty_lists_test() {
  let state =
    picker.new_state("Choose licence policy:", ["first", "last"], [], [])

  should.equal(picker.state_choices(picker.cycle_at_index(state, 0)), [
    #("first", picker.Allow),
    #("last", picker.Ignore),
  ])
  should.equal(picker.state_choices(picker.cycle_at_index(state, 1)), [
    #("first", picker.Ignore),
    #("last", picker.Allow),
  ])
  should.equal(picker.state_choices(picker.cycle_at_index(state, -1)), [
    #("first", picker.Ignore),
    #("last", picker.Ignore),
  ])
  should.equal(picker.state_choices(picker.cycle_at_index(state, 2)), [
    #("first", picker.Ignore),
    #("last", picker.Ignore),
  ])

  let empty = picker.new_state("Choose licence policy:", [], [], [])
  should.equal(picker.state_choices(picker.cycle_at_index(empty, 0)), [])
}

pub fn movement_keys_wrap_and_leave_empty_cursor_at_zero_test() {
  let state =
    picker.new_state("Choose licence policy:", ["first", "last"], [], [])

  let from_first_to_last = picker.handle_picker_key(state, picker.MoveUp)
  should.equal(picker.state_cursor(from_first_to_last), 1)

  let from_last_to_first =
    picker.handle_picker_key(from_first_to_last, picker.MoveDown)
  should.equal(picker.state_cursor(from_last_to_first), 0)

  let empty = picker.new_state("Choose licence policy:", [], [], [])
  should.equal(
    picker.state_cursor(picker.handle_picker_key(empty, picker.MoveUp)),
    0,
  )
  should.equal(
    picker.state_cursor(picker.handle_picker_key(empty, picker.MoveDown)),
    0,
  )
}
