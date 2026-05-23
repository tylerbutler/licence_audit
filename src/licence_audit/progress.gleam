import birch as log
import birch/handler.{Stderr}
import birch/handler/console
import birch/level
import birch/logger.{type Logger}
import gleam/int
import gleam/list

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

/// Set the command name used as the logger name in log output.
pub fn with_command(reporter: Reporter, command: String) -> Reporter {
  Reporter(..reporter, command: command)
}

pub fn events(reporter: Reporter) -> List(Event) {
  list.reverse(reporter.events)
}

pub fn configure(verbosity: Verbosity) -> Nil {
  let config = console.default_fancy_config()
  let stderr_config = console.ConsoleConfig(..config, target: Stderr)
  let threshold = case verbosity {
    Verbose -> level.Debug
    Quiet | Normal -> level.Info
  }

  log.configure([
    log.config_level(threshold),
    log.config_handlers([console.handler_with_config(stderr_config)]),
  ])
}

pub fn phase(reporter: Reporter, message: String) -> Reporter {
  case should_log(reporter) {
    True -> {
      case reporter.emit {
        True -> log.logger_info(logger_for(reporter), message, [])
        False -> Nil
      }
      record(reporter, Phase, message)
    }
    False -> reporter
  }
}

pub fn detail(reporter: Reporter, message: String) -> Reporter {
  case reporter.enabled, reporter.verbosity {
    True, Verbose -> {
      case reporter.emit {
        True -> log.logger_debug(logger_for(reporter), message, [])
        False -> Nil
      }
      record(reporter, Detail, message)
    }
    _, _ -> reporter
  }
}

pub fn package_count(reporter: Reporter, count: Int) -> Reporter {
  case should_log(reporter) {
    True -> {
      let message = "Checking Hex package metadata"
      case reporter.emit {
        True ->
          log.logger_info(logger_for(reporter), message, [
            #("packages", int.to_string(count)),
          ])
        False -> Nil
      }
      record(reporter, PackageCount, message)
    }
    False -> reporter
  }
}

pub fn success(reporter: Reporter, message: String) -> Reporter {
  case should_log(reporter) {
    True -> {
      case reporter.emit {
        True -> log.logger_info(logger_for(reporter), message, [])
        False -> Nil
      }
      record(reporter, Success, message)
    }
    False -> reporter
  }
}

pub fn fail(reporter: Reporter, message: String) -> Reporter {
  case should_log(reporter) {
    True -> {
      case reporter.emit {
        True -> log.logger_warn(logger_for(reporter), message, [])
        False -> Nil
      }
      record(reporter, Failure, message)
    }
    False -> reporter
  }
}

pub fn warn(reporter: Reporter, message: String) -> Reporter {
  case should_log(reporter) {
    True -> {
      case reporter.emit {
        True -> log.logger_warn(logger_for(reporter), message, [])
        False -> Nil
      }
      record(reporter, Warning, message)
    }
    False -> reporter
  }
}

/// Log a fatal audit error. Unlike `fail`/`warn`, this is emitted even in
/// quiet mode so failures are always visible alongside the non-zero exit
/// code.
pub fn error(reporter: Reporter, message: String) -> Reporter {
  case reporter.enabled {
    True -> {
      case reporter.emit {
        True -> log.logger_error(logger_for(reporter), message, [])
        False -> Nil
      }
      record(reporter, Error, message)
    }
    False -> reporter
  }
}

fn record(reporter: Reporter, kind: EventKind, message: String) -> Reporter {
  Reporter(..reporter, events: [Event(kind, message), ..reporter.events])
}

/// Record a success event and queue its log emission until `flush` is called.
/// Use this for end-of-run status messages that should appear after report
/// output has been printed to stdout.
pub fn defer_success(reporter: Reporter, message: String) -> Reporter {
  case should_log(reporter) {
    True -> queue(record(reporter, Success, message), Success, message)
    False -> reporter
  }
}

/// Record a warning event and queue its log emission until `flush` is called.
pub fn defer_warn(reporter: Reporter, message: String) -> Reporter {
  case should_log(reporter) {
    True -> queue(record(reporter, Warning, message), Warning, message)
    False -> reporter
  }
}

/// Record a fatal audit error and queue its log emission until `flush` is
/// called. Mirrors `error` in that it records even when verbosity is Quiet.
pub fn defer_error(reporter: Reporter, message: String) -> Reporter {
  case reporter.enabled {
    True -> queue(record(reporter, Error, message), Error, message)
    False -> reporter
  }
}

/// Emit any deferred log entries (in the order they were deferred) and clear
/// the deferred queue. Safe to call on capturing or disabled reporters.
pub fn flush(reporter: Reporter) -> Reporter {
  case reporter.emit {
    True -> {
      let lgr = logger_for(reporter)
      list.each(list.reverse(reporter.deferred), fn(event) {
        emit_event(lgr, event)
      })
    }
    False -> Nil
  }
  Reporter(..reporter, deferred: [])
}

fn queue(reporter: Reporter, kind: EventKind, message: String) -> Reporter {
  Reporter(..reporter, deferred: [Event(kind, message), ..reporter.deferred])
}

fn logger_for(reporter: Reporter) -> Logger {
  log.new(reporter.command)
}

fn emit_event(lgr: Logger, event: Event) -> Nil {
  case event.kind {
    Error -> log.logger_error(lgr, event.message, [])
    Warning -> log.logger_warn(lgr, event.message, [])
    Failure -> log.logger_warn(lgr, event.message, [])
    Success -> log.logger_info(lgr, event.message, [])
    Phase -> log.logger_info(lgr, event.message, [])
    PackageCount -> log.logger_info(lgr, event.message, [])
    Detail -> log.logger_debug(lgr, event.message, [])
  }
}

fn should_log(reporter: Reporter) -> Bool {
  case reporter.enabled, reporter.verbosity {
    True, Quiet -> False
    True, _ -> True
    False, _ -> False
  }
}
