//// Finite network fetch passes. Expected service errors remain values; runtime
//// failures account for the corresponding input instead of dropping it.

import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import weft

type Context

@external(erlang, "network_ffi", "with_command")
pub fn with_command(action: fn() -> a) -> a

@external(erlang, "network_ffi", "context")
fn context() -> Context

@external(erlang, "network_ffi", "with_task")
fn with_task(
  ledger: weft.Ledger,
  context: Context,
  index: Int,
  action: fn() -> a,
) -> a

pub fn fetch(
  inputs: List(a),
  describe: fn(a) -> String,
  fetcher: fn(a) -> b,
) -> List(Result(b, String)) {
  run(inputs, describe, fetcher, None)
}

@internal
pub fn fetch_with_deadline(
  inputs: List(a),
  describe: fn(a) -> String,
  fetcher: fn(a) -> b,
  deadline_ms: Int,
) -> List(Result(b, String)) {
  run(inputs, describe, fetcher, Some(deadline_ms))
}

fn run(
  inputs: List(a),
  describe: fn(a) -> String,
  fetcher: fn(a) -> b,
  deadline_ms: Option(Int),
) -> List(Result(b, String)) {
  with_command(fn() {
    let context = context()
    let outcomes =
      inputs
      |> list.index_map(fn(input, index) {
        weft.managed(fn(ledger) {
          Ok(with_task(ledger, context, index, fn() { fetcher(input) }))
        })
      })
      |> weft.new_prepared
      |> weft.limit(4)
      |> weft.cancel_grace(5000)
    let run = case deadline_ms {
      None -> outcomes
      Some(deadline_ms) -> weft.deadline(outcomes, deadline_ms)
    }
    let outcomes =
      run
      |> weft.start
    list.map2(inputs, outcomes, fn(input, outcome) {
      case outcome {
        weft.Completed(_, value) -> Ok(value)
        weft.Failed(_, _) ->
          Error(incomplete(describe(input), "worker failed without a result"))
        weft.Crashed(_, reason) ->
          Error(incomplete(describe(input), string.inspect(reason)))
        weft.Abandoned(_) ->
          Error(incomplete(
            describe(input),
            "fetch cancelled or deadline expired",
          ))
        weft.NeverStarted(_) ->
          Error(incomplete(describe(input), "fetch was not started"))
        weft.DrainProofLost(_, reason) ->
          Error(incomplete(
            describe(input),
            "HTTP teardown proof lost: " <> string.inspect(reason),
          ))
        weft.CancellationUnconfirmed(_) ->
          Error(incomplete(
            describe(input),
            "HTTP teardown was not confirmed within 5000 ms",
          ))
      }
    })
  })
}

fn incomplete(input: String, reason: String) -> String {
  "Fetch for " <> input <> " is incomplete: " <> reason
}
