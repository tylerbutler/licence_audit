//// Interactive tri-state picker built on the `etch` TUI backend.
////
//// Each item is in one of three states: `Allow`, `Deny`, or `Ignore`.
//// Pressing space cycles a single item through the states; `a`/`d`/`i`
//// apply a state to every item.
////
//// Usage:
////
////   case picker.pick("Choose licence policy:", labels, allow, deny) {
////     Ok(picker.Selection(allow, deny)) -> ...
////     Error(picker.Cancelled) -> ...
////   }

import etch/command
import etch/event
import etch/stdout
import etch/terminal
import gleam/dynamic.{type Dynamic}
import gleam/int
import gleam/io
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import tty

const max_read_failures = 3

pub type Choice {
  Allow
  Deny
  Ignore
}

type Item {
  Item(label: String, choice: Choice)
}

pub type Selection {
  Selection(allow: List(String), deny: List(String))
}

pub type PickerError {
  Cancelled
  NotInteractive
}

pub opaque type State {
  State(title: String, items: List(Item), cursor: Int)
}

pub type PickerKey {
  MoveUp
  MoveDown
  CycleCurrent
  AllowAll
  DenyAll
  IgnoreAll
}

type LoopOutcome {
  LoopDone(Result(Selection, PickerError))
  LoopReadFailed
}

type WorkerMessage {
  WorkerFinished(LoopOutcome)
  WorkerDown(Dynamic)
}

type Pid

type Monitor

type Reference

type Selector(payload)

type DoNotLeak

@external(erlang, "erlang", "self")
fn self() -> Pid

@external(erlang, "erlang", "make_ref")
fn make_ref() -> Reference

@external(erlang, "erlang", "send")
fn erlang_send(pid: Pid, message: message) -> message

@external(erlang, "erlang", "spawn_monitor")
fn spawn_monitor(running: fn() -> anything) -> #(Pid, Monitor)

@external(erlang, "gleam_erlang_ffi", "new_selector")
fn new_selector() -> Selector(payload)

@external(erlang, "gleam_erlang_ffi", "insert_selector_handler")
fn insert_selector_handler(
  selector: Selector(payload),
  for tag: tag,
  mapping mapping: fn(message) -> payload,
) -> Selector(payload)

@external(erlang, "gleam_erlang_ffi", "select")
fn selector_receive_forever(selector: Selector(payload)) -> payload

@external(erlang, "gleam_erlang_ffi", "demonitor")
fn demonitor_process(monitor: Monitor) -> DoNotLeak

/// Present an interactive tri-state prompt.
///
/// - `title` is shown above the list.
/// - `labels` are the choices in display order.
/// - Items whose label is in `allow` start as `Allow`.
/// - Items whose label is in `deny` start as `Deny`.
/// - Everything else (including newly discovered licences) starts as `Ignore`.
///
/// Returns a `Selection` containing only the labels marked `Allow` and `Deny`
/// (ignored labels are omitted from both lists), or `Cancelled` on
/// Esc / Ctrl-C / `q`.
pub fn pick(
  title: String,
  labels: List(String),
  allow: List(String),
  deny: List(String),
) -> Result(Selection, PickerError) {
  pick_with_terminal_check(
    title,
    labels,
    allow,
    deny,
    stdin_is_tty: fn() { tty.is_tty(tty.Stdin) },
    stdout_is_tty: fn() { tty.is_tty(tty.Stdout) },
  )
}

pub fn pick_with_terminal_check(
  title: String,
  labels: List(String),
  allow: List(String),
  deny: List(String),
  stdin_is_tty stdin_is_tty: fn() -> Bool,
  stdout_is_tty stdout_is_tty: fn() -> Bool,
) -> Result(Selection, PickerError) {
  case stdin_is_tty(), stdout_is_tty() {
    True, True -> pick_interactive(title, labels, allow, deny)
    _, _ -> Error(NotInteractive)
  }
}

fn pick_interactive(
  title: String,
  labels: List(String),
  allow: List(String),
  deny: List(String),
) -> Result(Selection, PickerError) {
  let state = new_state(title, labels, allow, deny)

  terminal.enter_raw()
  let outcome = run_loop_worker(state)
  stdout.execute([command.ShowCursor, command.Println("")])
  terminal.exit_raw()

  case outcome {
    LoopDone(result) -> result
    LoopReadFailed -> {
      io.println_error("Picker failed to read terminal input repeatedly.")
      Error(Cancelled)
    }
  }
}

pub fn new_state(
  title: String,
  labels: List(String),
  allow: List(String),
  deny: List(String),
) -> State {
  let items =
    list.map(labels, fn(label) {
      let choice = case
        list.contains(allow, label),
        list.contains(deny, label)
      {
        True, _ -> Allow
        False, True -> Deny
        False, False -> Ignore
      }
      Item(label: label, choice: choice)
    })

  State(title: title, items: items, cursor: 0)
}

pub fn handle_picker_key(state: State, key: PickerKey) -> State {
  let count = list.length(state.items)
  case key {
    MoveUp -> State(..state, cursor: wrap(state.cursor - 1, count))
    MoveDown -> State(..state, cursor: wrap(state.cursor + 1, count))
    CycleCurrent -> cycle_at_index(state, state.cursor)
    AllowAll -> State(..state, items: set_all(state.items, Allow))
    DenyAll -> State(..state, items: set_all(state.items, Deny))
    IgnoreAll -> State(..state, items: set_all(state.items, Ignore))
  }
}

pub fn cycle_at_index(state: State, index: Int) -> State {
  State(..state, items: cycle_items_at(state.items, index))
}

pub fn state_choices(state: State) -> List(#(String, Choice)) {
  list.map(state.items, fn(item) { #(item.label, item.choice) })
}

pub fn state_selection(state: State) -> Selection {
  build_selection(state.items)
}

pub fn state_cursor(state: State) -> Int {
  state.cursor
}

fn run_loop_worker(state: State) -> LoopOutcome {
  let parent = self()
  let tag = make_ref()
  let #(_, monitor) =
    spawn_monitor(fn() {
      event.init_event_server()
      stdout.execute([command.HideCursor])
      render(state, first: True)
      send_worker_message(
        parent,
        tag,
        WorkerFinished(loop(state, read_failures: 0)),
      )
    })
  let message =
    new_selector()
    |> select_worker_messages(tag)
    |> select_monitor(monitor)
    |> selector_receive_forever
  let _ = demonitor_process(monitor)

  case message {
    WorkerFinished(outcome) -> outcome
    WorkerDown(_) -> LoopReadFailed
  }
}

fn send_worker_message(
  pid: Pid,
  tag: Reference,
  message: WorkerMessage,
) -> Nil {
  let _ = erlang_send(pid, #(tag, message))
  Nil
}

fn select_worker_messages(
  selector: Selector(WorkerMessage),
  tag: Reference,
) -> Selector(WorkerMessage) {
  insert_selector_handler(
    selector,
    for: #(tag, 2),
    mapping: fn(message: #(Reference, WorkerMessage)) { message.1 },
  )
}

fn select_monitor(
  selector: Selector(WorkerMessage),
  monitor: Monitor,
) -> Selector(WorkerMessage) {
  insert_selector_handler(selector, for: monitor, mapping: fn(down: Dynamic) {
    WorkerDown(down)
  })
}

fn loop(state: State, read_failures read_failures: Int) -> LoopOutcome {
  case event.read() {
    Some(Ok(event.Key(key))) ->
      case key.kind {
        event.Press | event.Repeat -> handle_key(state, key)
        event.Release -> loop(state, read_failures: 0)
      }
    Some(Ok(_)) -> loop(state, read_failures: 0)
    Some(Error(_)) -> handle_read_failure(state, read_failures)
    None -> handle_read_failure(state, read_failures)
  }
}

fn handle_key(state: State, key: event.KeyEvent) -> LoopOutcome {
  case key.code, key.modifiers.control {
    event.Char("c"), True -> LoopDone(Error(Cancelled))
    event.Esc, _ -> LoopDone(Error(Cancelled))
    event.Char("q"), False -> LoopDone(Error(Cancelled))
    event.Enter, _ -> LoopDone(Ok(state_selection(state)))
    event.UpArrow, _ | event.Char("k"), False -> {
      let new = handle_picker_key(state, MoveUp)
      render(new, first: False)
      loop(new, read_failures: 0)
    }
    event.DownArrow, _ | event.Char("j"), False -> {
      let new = handle_picker_key(state, MoveDown)
      render(new, first: False)
      loop(new, read_failures: 0)
    }
    event.Char(" "), _ -> {
      let new = handle_picker_key(state, CycleCurrent)
      render(new, first: False)
      loop(new, read_failures: 0)
    }
    event.Char("a"), False -> {
      let new = handle_picker_key(state, AllowAll)
      render(new, first: False)
      loop(new, read_failures: 0)
    }
    event.Char("d"), False -> {
      let new = handle_picker_key(state, DenyAll)
      render(new, first: False)
      loop(new, read_failures: 0)
    }
    event.Char("i"), False -> {
      let new = handle_picker_key(state, IgnoreAll)
      render(new, first: False)
      loop(new, read_failures: 0)
    }
    _, _ -> loop(state, read_failures: 0)
  }
}

fn handle_read_failure(state: State, read_failures: Int) -> LoopOutcome {
  let read_failures = read_failures + 1
  case read_failures >= max_read_failures {
    True -> LoopReadFailed
    False -> loop(state, read_failures:)
  }
}

fn wrap(i: Int, count: Int) -> Int {
  case count {
    0 -> 0
    _ -> {
      let remainder = i % count
      case remainder < 0 {
        True -> remainder + count
        False -> remainder
      }
    }
  }
}

fn cycle_items_at(items: List(Item), index: Int) -> List(Item) {
  list.index_map(items, fn(item, i) {
    case i == index {
      True -> Item(..item, choice: next_choice(item.choice))
      False -> item
    }
  })
}

fn next_choice(choice: Choice) -> Choice {
  case choice {
    Allow -> Deny
    Deny -> Ignore
    Ignore -> Allow
  }
}

fn set_all(items: List(Item), value: Choice) -> List(Item) {
  list.map(items, fn(item) { Item(..item, choice: value) })
}

fn build_selection(items: List(Item)) -> Selection {
  Selection(
    allow: items
      |> list.filter(fn(i) { i.choice == Allow })
      |> list.map(fn(i) { i.label }),
    deny: items
      |> list.filter(fn(i) { i.choice == Deny })
      |> list.map(fn(i) { i.label }),
  )
}

fn render(state: State, first first: Bool) -> Nil {
  let prelude = case first {
    True -> [command.SavePosition]
    False -> [
      command.RestorePosition,
      command.Clear(terminal.FromCursorDown),
      command.SavePosition,
    ]
  }

  let header = [
    command.Println(state.title),
    command.Println(
      "  ↑/↓ move · space cycle · a/d/i all · enter ok · esc cancel",
    ),
  ]

  let row_commands =
    state.items
    |> list.index_map(fn(item, i) { render_row(item, i == state.cursor) })
    |> list.flatten

  let footer = [
    command.Println(
      "  "
      <> int.to_string(count_choice(state.items, Allow))
      <> " allow · "
      <> int.to_string(count_choice(state.items, Deny))
      <> " deny · "
      <> int.to_string(count_choice(state.items, Ignore))
      <> " ignore",
    ),
  ]

  stdout.execute(list.flatten([prelude, header, row_commands, footer]))
}

fn render_row(item: Item, focused: Bool) -> List(command.Command) {
  let mark = case item.choice {
    Allow -> "[+]"
    Deny -> "[-]"
    Ignore -> "[ ]"
  }
  let pointer = case focused {
    True -> "›"
    False -> " "
  }
  [command.Println(string.join([" ", pointer, mark, item.label], " "))]
}

fn count_choice(items: List(Item), choice: Choice) -> Int {
  items
  |> list.filter(fn(i) { i.choice == choice })
  |> list.length
}
