import gleam/bool
import gleam/int
import gleam/io
import gleam/list
import gleam/string
import gleam_community/ansi
import tty

pub type Verbosity {
  Quiet
  Normal
  Verbose
}

pub type EventKind {
  Phase
  Detail
  PackageCount
  Success
  Failure
  Warning
  Error
}

pub type Event {
  Event(kind: EventKind, message: String)
}

pub type Level {
  DebugLevel
  InfoLevel
  WarnLevel
  ErrorLevel
  FatalLevel
}

pub type LogEntry {
  LogEntry(
    level: Level,
    logger_name: String,
    message: String,
    metadata: List(#(String, String)),
  )
}

pub type Reporter {
  Reporter(
    enabled: Bool,
    verbosity: Verbosity,
    emit: Bool,
    events: List(Event),
    deferred: List(Event),
    command: String,
  )
}

pub fn enabled(verbosity: Verbosity, command: String) -> Reporter {
  Reporter(
    enabled: True,
    verbosity: verbosity,
    emit: True,
    events: [],
    deferred: [],
    command: command,
  )
}

pub fn capturing(verbosity: Verbosity, command: String) -> Reporter {
  Reporter(
    enabled: True,
    verbosity: verbosity,
    emit: False,
    events: [],
    deferred: [],
    command: command,
  )
}

pub fn disabled() -> Reporter {
  Reporter(
    enabled: False,
    verbosity: Quiet,
    emit: False,
    events: [],
    deferred: [],
    command: "",
  )
}

pub fn events(reporter: Reporter) -> List(Event) {
  list.reverse(reporter.events)
}

pub fn stderr_color_enabled(level: tty.ColorLevel) -> Bool {
  level != tty.NoColor
}

pub fn format_level(level: Level, _use_color: Bool) -> String {
  case level {
    InfoLevel -> ""
    DebugLevel -> "debug"
    WarnLevel -> "⚠ warn"
    ErrorLevel -> "✖ error"
    FatalLevel -> "✖ fatal"
  }
}

pub fn format_tty_record(record: LogEntry, use_color: Bool) -> String {
  let level = format_level(record.level, use_color)

  let metadata = format_metadata_visible(record.metadata, use_color)
  let metadata_suffix = case metadata {
    "" -> ""
    value -> " " <> value
  }

  case level {
    "" -> record.message <> metadata_suffix
    _ -> level <> " " <> record.message <> metadata_suffix
  }
}

pub fn format_standard_record(record: LogEntry, use_color: Bool) -> String {
  let level = format_standard_level(record.level, use_color)
  let metadata = format_metadata_visible(record.metadata, use_color)
  let metadata_suffix = case metadata {
    "" -> ""
    value -> " | " <> value
  }

  level
  <> " | "
  <> record.logger_name
  <> " | "
  <> record.message
  <> metadata_suffix
}

fn format_standard_level(level: Level, use_color: Bool) -> String {
  let label = case level {
    DebugLevel -> "DEBUG"
    InfoLevel -> "INFO"
    WarnLevel -> "WARN"
    ErrorLevel -> "ERROR"
    FatalLevel -> "FATAL"
  }
  let colored = case use_color {
    True ->
      case level {
        DebugLevel -> ansi.blue(label)
        InfoLevel -> ansi.cyan(label)
        WarnLevel -> ansi.yellow(label)
        ErrorLevel -> ansi.red(label)
        FatalLevel -> ansi.red(label)
      }
    False -> label
  }
  pad_to_width(colored, label, 5)
}

fn pad_to_width(text: String, plain_text: String, width: Int) -> String {
  text
  <> string.repeat(" ", times: int.max(width - string.length(plain_text), 0))
}

fn format_metadata_visible(
  metadata: List(#(String, String)),
  use_color: Bool,
) -> String {
  metadata
  |> list.filter(fn(pair) { !string.starts_with(pair.0, "_") })
  |> list.map(fn(pair) {
    let formatted = pair.0 <> "=" <> escape_metadata_value(pair.1)
    case use_color {
      True -> ansi.cyan(formatted)
      False -> formatted
    }
  })
  |> string.join(" ")
}

fn escape_metadata_value(value: String) -> String {
  use <- bool.guard(
    when: string.contains(value, " ") || string.contains(value, "="),
    return: value,
  )
  "\"" <> value <> "\""
}

pub fn phase(reporter: Reporter, message: String) -> Reporter {
  use <- bool.guard(when: !should_log(reporter), return: reporter)
  case reporter.emit {
    True -> emit(reporter, InfoLevel, message, [])
    False -> Nil
  }
  record(reporter, Phase, message)
}

pub fn detail(reporter: Reporter, message: String) -> Reporter {
  case reporter.enabled, reporter.verbosity {
    True, Verbose -> {
      case reporter.emit {
        True -> emit(reporter, DebugLevel, message, [])
        False -> Nil
      }
      record(reporter, Detail, message)
    }
    _, _ -> reporter
  }
}

pub fn package_count(reporter: Reporter, count: Int) -> Reporter {
  use <- bool.guard(when: !should_log(reporter), return: reporter)
  let message = "Checking Hex package metadata"
  case reporter.emit {
    True ->
      emit(reporter, InfoLevel, message, [
        #("packages", int.to_string(count)),
      ])
    False -> Nil
  }
  record(reporter, PackageCount, message)
}

pub fn success(reporter: Reporter, message: String) -> Reporter {
  use <- bool.guard(when: !should_log(reporter), return: reporter)
  case reporter.emit {
    True -> emit(reporter, InfoLevel, message, [])
    False -> Nil
  }
  record(reporter, Success, message)
}

pub fn fail(reporter: Reporter, message: String) -> Reporter {
  use <- bool.guard(when: !should_log(reporter), return: reporter)
  case reporter.emit {
    True -> emit(reporter, WarnLevel, message, [])
    False -> Nil
  }
  record(reporter, Failure, message)
}

pub fn warn(reporter: Reporter, message: String) -> Reporter {
  use <- bool.guard(when: !should_log(reporter), return: reporter)
  case reporter.emit {
    True -> emit(reporter, WarnLevel, message, [])
    False -> Nil
  }
  record(reporter, Warning, message)
}

fn record(reporter: Reporter, kind: EventKind, message: String) -> Reporter {
  Reporter(..reporter, events: [Event(kind, message), ..reporter.events])
}

/// Record a success event and queue its log emission until `flush` is called.
/// Use this for end-of-run status messages that should appear after report
/// output has been printed to stdout.
pub fn defer_success(reporter: Reporter, message: String) -> Reporter {
  use <- bool.guard(when: !should_log(reporter), return: reporter)
  queue(record(reporter, Success, message), Success, message)
}

/// Record a warning event and queue its log emission until `flush` is called.
pub fn defer_warn(reporter: Reporter, message: String) -> Reporter {
  use <- bool.guard(when: !should_log(reporter), return: reporter)
  queue(record(reporter, Warning, message), Warning, message)
}

/// Record a fatal audit error and queue its log emission until `flush` is
/// called. Mirrors `error` in that it records even when verbosity is Quiet.
pub fn defer_error(reporter: Reporter, message: String) -> Reporter {
  use <- bool.guard(when: !reporter.enabled, return: reporter)
  queue(record(reporter, Error, message), Error, message)
}

/// Emit any deferred log entries (in the order they were deferred) and clear
/// the deferred queue. Safe to call on capturing or disabled reporters.
pub fn flush(reporter: Reporter) -> Reporter {
  case reporter.emit {
    True -> {
      list.each(list.reverse(reporter.deferred), fn(event) {
        emit_event(reporter, event)
      })
    }
    False -> Nil
  }
  Reporter(..reporter, deferred: [])
}

fn queue(reporter: Reporter, kind: EventKind, message: String) -> Reporter {
  Reporter(..reporter, deferred: [Event(kind, message), ..reporter.deferred])
}

fn emit(
  reporter: Reporter,
  level: Level,
  message: String,
  metadata: List(#(String, String)),
) -> Nil {
  let entry =
    LogEntry(
      level: level,
      logger_name: reporter.command,
      message: message,
      metadata: metadata,
    )
  let use_color = stderr_color_enabled(tty.detect_color_level(tty.Stderr))
  case tty.is_tty(tty.Stderr) {
    True -> format_tty_record(entry, use_color)
    False -> format_standard_record(entry, use_color)
  }
  |> io.println_error
}

fn emit_event(reporter: Reporter, event: Event) -> Nil {
  case event.kind {
    Error -> emit(reporter, ErrorLevel, event.message, [])
    Warning -> emit(reporter, WarnLevel, event.message, [])
    Failure -> emit(reporter, WarnLevel, event.message, [])
    Success -> emit(reporter, InfoLevel, event.message, [])
    Phase -> emit(reporter, InfoLevel, event.message, [])
    PackageCount -> emit(reporter, InfoLevel, event.message, [])
    Detail -> emit(reporter, DebugLevel, event.message, [])
  }
}

fn should_log(reporter: Reporter) -> Bool {
  case reporter.enabled, reporter.verbosity {
    True, Quiet -> False
    True, _ -> True
    False, _ -> False
  }
}
