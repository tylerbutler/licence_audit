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
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import tty

pub type Choice {
  Allow
  Deny
  Ignore
}

pub type Item {
  Item(label: String, choice: Choice)
}

pub type Selection {
  Selection(allow: List(String), deny: List(String))
}

pub type PickerError {
  Cancelled
  NotInteractive
}

type State {
  State(title: String, items: List(Item), cursor: Int)
}

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

@internal
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
  let state = State(title: title, items: items, cursor: 0)

  terminal.enter_raw()
  event.init_event_server()
  stdout.execute([command.HideCursor])
  render(state, first: True)
  let result = loop(state)
  stdout.execute([command.ShowCursor, command.Println("")])
  terminal.exit_raw()
  result
}

fn loop(state: State) -> Result(Selection, PickerError) {
  case event.read() {
    Some(Ok(event.Key(key))) ->
      case key.kind {
        event.Press | event.Repeat -> handle_key(state, key)
        event.Release -> loop(state)
      }
    Some(Ok(_)) -> loop(state)
    Some(Error(_)) -> loop(state)
    None -> loop(state)
  }
}

fn handle_key(
  state: State,
  key: event.KeyEvent,
) -> Result(Selection, PickerError) {
  let count = list.length(state.items)
  case key.code, key.modifiers.control {
    event.Char("c"), True -> Error(Cancelled)
    event.Esc, _ -> Error(Cancelled)
    event.Char("q"), False -> Error(Cancelled)
    event.Enter, _ -> Ok(build_selection(state.items))
    event.UpArrow, _ | event.Char("k"), False -> {
      let new = State(..state, cursor: wrap(state.cursor - 1, count))
      render(new, first: False)
      loop(new)
    }
    event.DownArrow, _ | event.Char("j"), False -> {
      let new = State(..state, cursor: wrap(state.cursor + 1, count))
      render(new, first: False)
      loop(new)
    }
    event.Char(" "), _ -> {
      let new = State(..state, items: cycle_at(state.items, state.cursor))
      render(new, first: False)
      loop(new)
    }
    event.Char("a"), False -> {
      let new = State(..state, items: set_all(state.items, Allow))
      render(new, first: False)
      loop(new)
    }
    event.Char("d"), False -> {
      let new = State(..state, items: set_all(state.items, Deny))
      render(new, first: False)
      loop(new)
    }
    event.Char("i"), False -> {
      let new = State(..state, items: set_all(state.items, Ignore))
      render(new, first: False)
      loop(new)
    }
    _, _ -> loop(state)
  }
}

fn wrap(i: Int, count: Int) -> Int {
  case count {
    0 -> 0
    _ -> {
      let m = i % count
      case m < 0 {
        True -> m + count
        False -> m
      }
    }
  }
}

fn cycle_at(items: List(Item), index: Int) -> List(Item) {
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
  let rows = list.length(state.items) + 3
  // On redraws, move cursor back up to the title row and clear from there.
  let prelude = case first {
    True -> []
    False -> [
      command.MoveToPreviousLine(rows),
      command.Clear(terminal.FromCursorDown),
    ]
  }

  let header = [
    command.Println(state.title),
    command.Println(
      "  ↑/↓ move · space cycle · a allow all · d deny all · i ignore all · enter confirm · esc cancel",
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
