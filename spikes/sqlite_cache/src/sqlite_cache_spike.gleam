import gleam/dynamic/decode
import gleam/int
import gleam/io
import gleam/result
import sqlight

const upsert =
  "
  INSERT INTO entries (key, value, cached_at) VALUES (?, ?, ?)
  ON CONFLICT(key) DO UPDATE SET
    value = excluded.value, cached_at = excluded.cached_at
"

pub fn main() -> Nil {
  case run(arguments()) {
    Ok(output) -> {
      io.println(output)
      halt(0)
    }
    Error(error) -> {
      io.println_error("SQLite spike failed: " <> error)
      halt(1)
    }
  }
}

fn run(arguments: List(String)) -> Result(String, String) {
  case arguments {
    ["put", path, key, value, cached_at] -> {
      use cached_at <- result.try(
        int.parse(cached_at)
        |> result.map_error(fn(_) { "cached_at must be an integer" }),
      )
      with_cache(path, fn(connection) {
        let started = monotonic_milliseconds()
        case put(connection, key, value, cached_at) {
          Ok(Nil) -> Ok("stored")
          Error(sqlight.SqlightError(code: sqlight.Busy, ..)) -> {
            let elapsed = monotonic_milliseconds() - started
            io.println_error("Warning: cache busy; write skipped")
            Ok("skipped in " <> int.to_string(elapsed) <> " ms")
          }
          Error(error) -> Error(describe_error(error))
        }
      })
    }
    ["get", path, key] ->
      with_cache(path, fn(connection) {
        let decoder = {
          use value <- decode.field(0, decode.string)
          use cached_at <- decode.field(1, decode.int)
          decode.success(#(value, cached_at))
        }
        use rows <- result.try(
          sqlight.query(
            "SELECT value, cached_at FROM entries WHERE key = ?",
            on: connection,
            with: [sqlight.text(key)],
            expecting: decoder,
          )
          |> result.map_error(describe_error),
        )
        case rows {
          [] -> Ok("miss")
          [#(value, cached_at)] -> Ok(int.to_string(cached_at) <> "\t" <> value)
          _ -> Error("duplicate cache keys")
        }
      })
    ["hold", path] ->
      with_cache(path, fn(connection) {
        use _ <- result.try(
          sqlight.exec("BEGIN IMMEDIATE", on: connection)
          |> result.map_error(describe_error),
        )
        use _ <- result.try(
          upsert_entry(connection, "example@1.0.0", "uncommitted", 999)
          |> result.map_error(describe_error),
        )
        io.println("writer locked")
        sleep()
        sqlight.exec("ROLLBACK", on: connection)
        |> result.map(fn(_) { "writer released" })
        |> result.map_error(describe_error)
      })
    _ -> Error("usage: put PATH KEY VALUE CACHED_AT | get PATH KEY | hold PATH")
  }
}

fn with_cache(
  path: String,
  action: fn(sqlight.Connection) -> Result(String, String),
) -> Result(String, String) {
  use connection <- result.try(
    sqlight.open(path)
    |> result.map_error(fn(error) {
      "open " <> path <> ": " <> describe_error(error)
    }),
  )
  let outcome = {
    use _ <- result.try(configure(connection))
    action(connection)
  }
  let closed = sqlight.close(connection)
  case outcome, closed {
    Ok(value), Ok(Nil) -> Ok(value)
    Error(error), Ok(Nil) -> Error(error)
    Ok(_), Error(error) -> Error("close: " <> describe_error(error))
    Error(first), Error(second) ->
      Error(first <> "; close: " <> describe_error(second))
  }
}

fn configure(connection: sqlight.Connection) -> Result(Nil, String) {
  use _ <- result.try(
    sqlight.exec("PRAGMA busy_timeout=0", on: connection)
    |> result.map_error(describe_error),
  )
  use modes <- result.try(
    sqlight.query(
      "PRAGMA journal_mode=WAL",
      on: connection,
      with: [],
      expecting: decode.field(0, decode.string, decode.success),
    )
    |> result.map_error(describe_error),
  )
  use _ <- result.try(case modes {
    ["wal"] -> Ok(Nil)
    _ -> Error("SQLite did not enable WAL")
  })
  sqlight.exec(
    "CREATE TABLE IF NOT EXISTS entries (
       key TEXT PRIMARY KEY,
       value TEXT NOT NULL,
       cached_at INTEGER NOT NULL
     );",
    on: connection,
  )
  |> result.map_error(describe_error)
}

fn put(
  connection: sqlight.Connection,
  key: String,
  value: String,
  cached_at: Int,
) -> Result(Nil, sqlight.Error) {
  // esqlite 0.9.0 crashes on a busy parameterised query; exec returns an error.
  use _ <- result.try(sqlight.exec("BEGIN IMMEDIATE", on: connection))
  let outcome = {
    use _ <- result.try(upsert_entry(connection, key, value, cached_at))
    sqlight.exec("COMMIT", on: connection)
  }
  case outcome {
    Ok(Nil) -> Ok(Nil)
    Error(error) -> {
      case sqlight.exec("ROLLBACK", on: connection) {
        Ok(Nil) -> Nil
        Error(rollback_error) ->
          io.println_error(
            "Rollback failed: " <> describe_error(rollback_error),
          )
      }
      Error(error)
    }
  }
}

fn upsert_entry(
  connection: sqlight.Connection,
  key: String,
  value: String,
  cached_at: Int,
) -> Result(Nil, sqlight.Error) {
  sqlight.query(
    upsert,
    on: connection,
    with: [sqlight.text(key), sqlight.text(value), sqlight.int(cached_at)],
    expecting: decode.success(Nil),
  )
  |> result.map(fn(_) { Nil })
}

fn describe_error(error: sqlight.Error) -> String {
  "SQLite "
  <> int.to_string(sqlight.error_code_to_int(error.code))
  <> ": "
  <> error.message
}

@external(erlang, "sqlite_cache_spike_ffi", "arguments")
fn arguments() -> List(String)

@external(erlang, "sqlite_cache_spike_ffi", "monotonic_milliseconds")
fn monotonic_milliseconds() -> Int

@external(erlang, "sqlite_cache_spike_ffi", "sleep")
fn sleep() -> Nil

@external(erlang, "erlang", "halt")
fn halt(status: Int) -> Nil
