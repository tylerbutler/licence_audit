import gleam/http/request.{type Request}
import gleam/http/response.{type Response, Response}
import gleam/list
import gleam/result
import gleam/string
import gleeunit/should
import licence_audit/hex
import licence_audit/httpc_adaptive

@external(erlang, "httpc_adaptive_test_ffi", "with_script")
pub fn with_script(
  responses: List(Result(Response(String), httpc_adaptive.Error)),
  action: fn() -> a,
) -> a

@external(erlang, "httpc_adaptive_test_ffi", "scripted_request")
fn scripted_request(
  req: Request(String),
) -> Result(Response(String), httpc_adaptive.Error)

@external(erlang, "httpc_adaptive_test_ffi", "now_ms")
pub fn now_ms() -> Int

@external(erlang, "httpc_adaptive_test_ffi", "elapsed_ms")
pub fn elapsed_ms() -> Int

@external(erlang, "httpc_adaptive_test_ffi", "sleep")
pub fn sleep(wait_ms: Int) -> Nil

@external(erlang, "httpc_adaptive_test_ffi", "attempts")
fn attempts() -> Int

@external(erlang, "httpc_adaptive_test_ffi", "waits")
fn waits() -> List(Int)

@external(erlang, "httpc_adaptive_test_ffi", "record_request")
pub fn record_request(req: Request(String)) -> Nil

@external(erlang, "httpc_adaptive_test_ffi", "requests")
pub fn requests() -> List(Request(String))

pub fn send(
  req: Request(String),
  retries: Int,
) -> Result(Response(String), httpc_adaptive.Error) {
  httpc_adaptive.dispatch_retry_with(
    req,
    retries,
    scripted_request,
    now_ms,
    elapsed_ms,
    sleep,
  )
}

fn hex_request() -> Request(String) {
  let assert Ok(req) = request.to("https://hex.pm/api/packages/example")
  req
}

pub fn retries_rate_limits_and_transient_failures_with_service_limits_test() {
  use retries <- list.each([1, 2])
  use failure <- list.each([
    Ok(Response(429, [], "")),
    Ok(Response(408, [], "")),
    Ok(Response(500, [], "")),
    Ok(Response(502, [], "")),
    Ok(Response(503, [], "")),
    Ok(Response(504, [], "")),
    Error(httpc_adaptive.ResponseTimeout),
    Error(httpc_adaptive.ConnectionClosed("socket_closed_remotely")),
    Error(httpc_adaptive.ConnectionFailure(
      httpc_adaptive.ConnectionRefused,
      "refused",
    )),
  ])
  with_script(list.repeat(failure, retries + 1), fn() {
    should.equal(send(hex_request(), retries), failure)
    should.equal(attempts(), retries + 1)
    should.equal(waits(), case retries {
      1 -> [1000]
      _ -> [1000, 2000]
    })
  })
  with_script([failure, Ok(Response(200, [], "ok"))], fn() {
    should.equal(send(hex_request(), retries), Ok(Response(200, [], "ok")))
    should.equal(attempts(), 2)
  })
}

pub fn permanent_transport_and_http_errors_are_not_retried_test() {
  use failure <- list.each([
    Error(httpc_adaptive.TlsFailure("unknown_ca")),
    Error(httpc_adaptive.InvalidRequest("bad URL")),
    Error(httpc_adaptive.InvalidUtf8Response),
    Error(httpc_adaptive.RequestFailed("timeout in unrelated diagnostic")),
    Error(httpc_adaptive.FailedToConnect("TLS verification failed")),
    Ok(Response(400, [], "")),
    Ok(Response(404, [], "")),
    Ok(Response(501, [], "")),
  ])
  with_script([failure], fn() {
    should.equal(send(hex_request(), 2), failure)
    should.equal(attempts(), 1)
    should.equal(waits(), [])
  })
}

pub fn retry_headers_honor_exact_deadlines_and_case_test() {
  use #(headers, expected) <- list.each([
    #([#("Retry-After", "3")], 3000),
    #([#("x-ratelimit-reset", "1700000003")], 3000),
    #([#("Retry-After", "Tue, 14 Nov 2023 22:13:23 GMT")], 3000),
    #([#("retry-after", "0")], 0),
    #([#("x-ratelimit-reset", "1699999999")], 0),
    #([#("retry-after", "invalid"), #("x-ratelimit-reset", "1700000003")], 3000),
    #([#("retry-after", "1"), #("x-ratelimit-reset", "1700000003")], 3000),
    #([#("retry-after", "-1")], 1000),
    #([#("retry-after", "invalid"), #("x-ratelimit-reset", "invalid")], 1000),
  ])
  with_script([Ok(Response(429, headers, "")), Ok(Response(200, [], ""))], fn() {
    should.equal(send(hex_request(), 1), Ok(Response(200, [], "")))
    should.equal(waits(), [expected])
    should.equal(now_ms(), 1_700_000_000_000 + expected)
  })
}

pub fn wait_budget_is_total_and_never_retries_before_deadline_test() {
  with_script(
    [
      Ok(Response(429, [#("retry-after", "20")], "")),
      Ok(Response(429, [#("retry-after", "11")], "")),
    ],
    fn() {
      should.equal(
        send(hex_request(), 2),
        Error(httpc_adaptive.RetryWaitExceeded(11_000, 10_000)),
      )
      should.equal(attempts(), 2)
      should.equal(waits(), [20_000])
    },
  )
  with_script(
    [
      Ok(Response(429, [#("retry-after", "20")], "")),
      Ok(Response(429, [#("x-ratelimit-reset", "1700000030")], "")),
      Ok(Response(200, [], "")),
    ],
    fn() {
      should.equal(send(hex_request(), 2), Ok(Response(200, [], "")))
      should.equal(waits(), [20_000, 10_000])
    },
  )
  with_script([Ok(Response(429, [#("retry-after", "31")], ""))], fn() {
    should.equal(
      send(hex_request(), 1),
      Error(httpc_adaptive.RetryWaitExceeded(31_000, 30_000)),
    )
    should.equal(attempts(), 1)
    should.equal(waits(), [])
  })
  with_script(
    [
      Ok(Response(429, [#("retry-after", "30")], "")),
      Ok(Response(200, [], "")),
    ],
    fn() {
      should.equal(send(hex_request(), 1), Ok(Response(200, [], "")))
      should.equal(waits(), [30_000])
    },
  )
}

pub fn cutoff_counts_exhausted_operations_not_attempts_and_is_host_scoped_test() {
  let failure = Error(httpc_adaptive.ResponseTimeout)
  with_script(
    list.append(list.repeat(failure, 9), [Ok(Response(200, [], ""))]),
    fn() {
      let req = hex_request()
      list.each([1, 2, 3], fn(_) { should.equal(send(req, 2), failure) })
      should.equal(attempts(), 9)
      let publication =
        request.set_path(req, "/api/packages/example/releases/1.0.0")
      should.equal(
        send(publication, 1),
        Error(httpc_adaptive.HostUnavailable("hex.pm")),
      )
      should.equal(attempts(), 9)
      let assert Ok(osv) = request.to("https://api.osv.dev/v1/querybatch")
      should.equal(send(osv, 2), Ok(Response(200, [], "")))
      should.equal(attempts(), 10)
      let detail =
        httpc_adaptive.describe_error(
          httpc_adaptive.HostUnavailable("hex.pm"),
          5000,
        )
      assert string.contains(detail, "coverage is incomplete")
    },
  )
}

pub fn success_resets_cutoff_and_rate_limits_neither_increment_nor_reset_test() {
  let failure =
    Error(httpc_adaptive.ConnectionFailure(
      httpc_adaptive.DnsFailure,
      "nxdomain",
    ))
  let limited = Ok(Response(429, [], ""))
  let ok = Ok(Response(200, [], ""))
  with_script([failure, failure, ok, failure, failure, limited, failure], fn() {
    let req = hex_request()
    list.each(
      [failure, failure, ok, failure, failure, limited, failure],
      fn(expected) { should.equal(send(req, 0), expected) },
    )
    should.equal(send(req, 2), Error(httpc_adaptive.HostUnavailable("hex.pm")))
    should.equal(attempts(), 7)
    httpc_adaptive.reset_retry_state()
    should.equal(
      httpc_adaptive.dispatch_retry_with(
        req,
        0,
        fn(_) { ok },
        now_ms,
        elapsed_ms,
        sleep,
      ),
      ok,
    )
  })
}

pub fn advisory_and_batch_calls_share_osv_cutoff_test() {
  let failure = Error(httpc_adaptive.ResponseTimeout)
  with_script(list.repeat(failure, 3), fn() {
    let assert Ok(batch) = request.to("https://api.osv.dev/v1/querybatch")
    let detail = request.set_path(batch, "/v1/vulns/OSV-1")
    list.each([batch, detail, batch], fn(req) {
      should.equal(send(req, 0), failure)
    })
    should.equal(
      send(detail, 2),
      Error(httpc_adaptive.HostUnavailable("api.osv.dev")),
    )
    should.equal(attempts(), 3)
  })
}

pub fn successful_unpublished_lookup_resets_dead_network_streak_test() {
  let timeout = Error(httpc_adaptive.ResponseTimeout)
  with_script(
    [
      timeout,
      timeout,
      Ok(Response(404, [], "")),
      timeout,
      timeout,
      Ok(Response(200, [], "")),
    ],
    fn() {
      let req = hex_request()
      should.equal(send(req, 0), timeout)
      should.equal(send(req, 0), timeout)
      should.equal(
        hex.fetch_publication("example", "1.0.0", fn(req) {
          send(req, 0) |> result.map_error(hex.from_http_error(req, _))
        }),
        Ok(hex.Unpublished),
      )
      should.equal(send(req, 0), timeout)
      should.equal(send(req, 0), timeout)
      should.equal(send(req, 0), Ok(Response(200, [], "")))
      should.equal(attempts(), 6)
    },
  )
}

pub fn final_rate_limit_after_timeout_attempts_does_not_count_as_dead_network_test() {
  let timeout = Error(httpc_adaptive.ResponseTimeout)
  let limited = Ok(Response(429, [], ""))
  with_script([timeout, limited, timeout, limited, timeout, limited], fn() {
    list.each([1, 2, 3], fn(_) { should.equal(send(hex_request(), 1), limited) })
    should.equal(
      httpc_adaptive.dispatch_retry_with(
        hex_request(),
        0,
        fn(_) { Ok(Response(200, [], "")) },
        now_ms,
        elapsed_ms,
        sleep,
      ),
      Ok(Response(200, [], "")),
    )
    should.equal(attempts(), 6)
  })
}

pub fn elapsed_wait_including_oversleep_consumes_budget_test() {
  with_script(
    [
      Ok(Response(429, [#("retry-after", "20")], "")),
      Ok(Response(429, [#("retry-after", "10")], "")),
    ],
    fn() {
      should.equal(
        httpc_adaptive.dispatch_retry_with(
          hex_request(),
          2,
          scripted_request,
          now_ms,
          elapsed_ms,
          fn(wait) { sleep(wait + 1) },
        ),
        Error(httpc_adaptive.RetryWaitExceeded(10_000, 9999)),
      )
      should.equal(attempts(), 2)
    },
  )
}
