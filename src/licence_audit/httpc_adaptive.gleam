//// Keep this client until a replacement provides a bounded IPv6 probe and
//// remembers IPv4 fallback for the rest of the command. These are required
//// behaviors, not redundant wrappers around `gleam_httpc`.
//// An IPv6-only DNS `nxdomain` selects IPv4 silently; other probe failures warn.
////
//// #43 fixed repeated IPv6 timeouts. Removing this client in #61 brought them
//// back: `gleam_httpc`'s `inet6fb4` path can exhaust the five-second Hex timeout
//// before IPv4 succeeds. The same endpoint responds promptly over IPv4.

import gleam/bit_array
import gleam/bool
import gleam/http
import gleam/http/request.{type Request, Request}
import gleam/http/response.{type Response}
import gleam/int
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gleam/string

const ipv6_probe_timeout_ms = 1000

pub type Error {
  InvalidUtf8Response
  ResponseTimeout
  NoIpv6Address
  FailedToConnect(reason: String)
  RequestFailed(reason: String)
  ConnectionFailure(reason: ConnectionReason, detail: String)
  ConnectionClosed(reason: String)
  TlsFailure(detail: String)
  InvalidRequest(detail: String)
  RetryWaitExceeded(wait_ms: Int, remaining_ms: Int)
  HostUnavailable(host: String)
}

pub type ConnectionReason {
  ConnectionTimedOut
  DnsFailure
  ConnectionRefused
  NetworkUnreachable
  HostUnreachable
}

/// Keep transport diagnostics consistent across Hex and OSV.
pub fn describe_error(error: Error, timeout_ms: Int) -> String {
  case error {
    InvalidUtf8Response -> "response body was not valid UTF-8"
    NoIpv6Address -> "IPv6 DNS lookup found no address"
    ResponseTimeout ->
      "HTTP request timed out after "
      <> int.to_string(timeout_ms)
      <> " ms (HTTP client did not report which stage timed out)"
    FailedToConnect(reason) -> "connection setup failed: " <> reason
    RequestFailed(reason) -> "HTTP request failed: " <> reason
    ConnectionFailure(_, detail) -> "connection setup failed: " <> detail
    ConnectionClosed(reason) -> "HTTP request failed: " <> reason
    TlsFailure(detail) -> "connection setup failed: " <> detail
    InvalidRequest(detail) -> "invalid HTTP request: " <> detail
    RetryWaitExceeded(wait_ms, remaining_ms) ->
      "retry deadline requires "
      <> int.to_string(wait_ms)
      <> " ms of waiting, but only "
      <> int.to_string(remaining_ms)
      <> " ms remain in the 30000 ms retry-wait budget; request not retried"
    HostUnavailable(host) ->
      "network calls to "
      <> host
      <> " stopped after three consecutive exhausted timeout/connect operations; coverage is incomplete"
  }
}

@external(erlang, "httpc_adaptive_ffi", "reset_retry_state")
pub fn reset_retry_state() -> Nil

@external(erlang, "httpc_adaptive_ffi", "host_failures")
fn host_failures(host: String) -> Int

@external(erlang, "httpc_adaptive_ffi", "record_host_failure")
pub fn record_host_failure(host: String) -> Nil

@external(erlang, "httpc_adaptive_ffi", "clear_host_failures")
pub fn clear_host_failures(host: String) -> Nil

@external(erlang, "httpc_adaptive_ffi", "now_ms")
fn now_ms() -> Int

@external(erlang, "httpc_adaptive_ffi", "monotonic_ms")
fn monotonic_ms() -> Int

@external(erlang, "httpc_adaptive_ffi", "sleep")
fn sleep(wait_ms: Int) -> Nil

@external(erlang, "network_ffi", "defer_host")
fn defer_host(host: String, deadline_ms: Int) -> Nil

@external(erlang, "network_ffi", "host_wait")
fn host_wait(host: String, now_ms: Int) -> Int

@external(erlang, "network_ffi", "shared_probe")
fn shared_probe(
  host: String,
  probe: fn() -> Result(IpFamily, Error),
) -> Result(IpFamily, Error)

@external(erlang, "httpc_adaptive_ffi", "http_date_ms")
fn http_date_ms(value: String) -> Result(Int, Nil)

/// Archives have their own transport and no added retries, but share admission.
@internal
pub fn admit(host: String) -> Result(Nil, Error) {
  use <- bool.guard(
    when: host_failures(host) >= 3,
    return: Error(HostUnavailable(host)),
  )
  use _ <- result.try(wait_for_host(host, 30_000, monotonic_ms, sleep))
  case host_failures(host) >= 3 {
    True -> Error(HostUnavailable(host))
    False -> Ok(Nil)
  }
}

/// Retry one logical operation, not the IPv6 probe. Callers map errors only
/// after this policy finishes, so retry decisions never inspect diagnostics.
pub fn dispatch_retry(
  request: Request(String),
  timeout_ms: Int,
  retries retries: Int,
) -> Result(Response(String), Error) {
  let request = request.map(request, bit_array.from_string)
  use response <- result.try(dispatch_retry_with(
    request,
    retries,
    dispatch_managed_bits_with(_, timeout_ms, dispatch_without_retry),
    now_ms,
    monotonic_ms,
    sleep,
  ))
  case bit_array.to_string(response.body) {
    Ok(body) -> Ok(response.set_body(response, body))
    Error(_) -> Error(InvalidUtf8Response)
  }
}

/// Inject transport, wall clock, elapsed clock and sleep for deterministic tests.
pub fn dispatch_retry_with(
  request: Request(a),
  retries: Int,
  client: fn(Request(a)) -> Result(Response(b), Error),
  now: fn() -> Int,
  elapsed: fn() -> Int,
  sleep: fn(Int) -> Nil,
) -> Result(Response(b), Error) {
  use <- bool.guard(
    when: host_failures(request.host) >= 3,
    return: Error(HostUnavailable(request.host)),
  )
  let outcome =
    retry_loop(request, retries, client, now, elapsed, sleep, 30_000, 1000)
  record_outcome(request.host, outcome)
  outcome
}

fn record_outcome(host: String, outcome: Result(Response(a), Error)) -> Nil {
  case outcome {
    Ok(response) -> {
      // A release-endpoint 404 is a successful unpublished lookup.
      case
        response.status >= 200
        && response.status < 300
        || response.status == 404
      {
        True -> clear_host_failures(host)
        False -> Nil
      }
    }
    Error(ResponseTimeout) | Error(ConnectionFailure(_, _)) ->
      record_host_failure(host)
    Error(InvalidUtf8Response)
    | Error(NoIpv6Address)
    | Error(FailedToConnect(_))
    | Error(RequestFailed(_))
    | Error(ConnectionClosed(_))
    | Error(TlsFailure(_))
    | Error(InvalidRequest(_))
    | Error(RetryWaitExceeded(_, _))
    | Error(HostUnavailable(_)) -> Nil
  }
}

fn retry_loop(
  request: Request(a),
  retries: Int,
  client: fn(Request(a)) -> Result(Response(b), Error),
  now: fn() -> Int,
  elapsed: fn() -> Int,
  sleep: fn(Int) -> Nil,
  remaining_ms: Int,
  backoff_ms: Int,
) -> Result(Response(b), Error) {
  use <- bool.guard(
    when: host_failures(request.host) >= 3,
    return: Error(HostUnavailable(request.host)),
  )
  use remaining_ms <- result.try(wait_for_host(
    request.host,
    remaining_ms,
    elapsed,
    sleep,
  ))
  use <- bool.guard(
    when: host_failures(request.host) >= 3,
    return: Error(HostUnavailable(request.host)),
  )
  let outcome = client(request)
  let retry = case outcome {
    Ok(response) -> {
      let status = response.status
      status == 429
      || status == 408
      || status == 500
      || status == 502
      || status == 503
      || status == 504
    }
    Error(ResponseTimeout)
    | Error(ConnectionFailure(_, _))
    | Error(ConnectionClosed(_)) -> True
    Error(InvalidUtf8Response)
    | Error(NoIpv6Address)
    | Error(FailedToConnect(_))
    | Error(RequestFailed(_))
    | Error(TlsFailure(_))
    | Error(InvalidRequest(_))
    | Error(RetryWaitExceeded(_, _))
    | Error(HostUnavailable(_)) -> False
  }
  let wait_ms = case outcome {
    Ok(response) -> retry_wait(response, now(), backoff_ms)
    Error(_) -> backoff_ms
  }
  case outcome {
    Ok(_) if retry -> defer_host(request.host, elapsed() + wait_ms)
    _ -> Nil
  }
  use <- bool.guard(when: !retry || retries <= 0, return: outcome)
  use <- bool.guard(
    when: wait_ms > remaining_ms,
    return: Error(RetryWaitExceeded(wait_ms, remaining_ms)),
  )
  let started = elapsed()
  sleep(wait_ms)
  let waited = int.max(wait_ms, elapsed() - started)
  use <- bool.guard(
    when: waited > remaining_ms,
    return: Error(RetryWaitExceeded(waited, remaining_ms)),
  )
  retry_loop(
    request,
    retries - 1,
    client,
    now,
    elapsed,
    sleep,
    remaining_ms - waited,
    backoff_ms * 2,
  )
}

fn wait_for_host(
  host: String,
  remaining_ms: Int,
  elapsed: fn() -> Int,
  sleep: fn(Int) -> Nil,
) -> Result(Int, Error) {
  let wait_ms = host_wait(host, elapsed())
  use <- bool.guard(when: wait_ms <= 0, return: Ok(remaining_ms))
  use <- bool.guard(
    when: wait_ms > remaining_ms,
    return: Error(RetryWaitExceeded(wait_ms, remaining_ms)),
  )
  let started = elapsed()
  sleep(wait_ms)
  let waited = int.max(wait_ms, elapsed() - started)
  use <- bool.guard(
    when: waited > remaining_ms,
    return: Error(RetryWaitExceeded(waited, remaining_ms)),
  )
  wait_for_host(host, remaining_ms - waited, elapsed, sleep)
}

fn retry_wait(response: Response(a), now_ms: Int, backoff_ms: Int) -> Int {
  let waits =
    response.headers
    |> list.filter_map(fn(header) {
      let #(name, value) = header
      let value = string.trim(value)
      case string.lowercase(name) {
        "retry-after" ->
          case int.parse(value) {
            Ok(seconds) if seconds >= 0 -> Ok(seconds * 1000)
            Ok(_) -> Error(Nil)
            Error(_) ->
              http_date_ms(value)
              |> result.map(fn(deadline) { int.max(0, deadline - now_ms) })
          }
        "x-ratelimit-reset" ->
          case int.parse(value) {
            Ok(seconds) if seconds >= 0 ->
              Ok(int.max(0, seconds * 1000 - now_ms))
            _ -> Error(Nil)
          }
        _ -> Error(Nil)
      }
    })
  case waits {
    [] -> backoff_ms
    [first, ..rest] -> list.fold(rest, first, int.max)
  }
}

// OTP 28 httpc retries 503/Retry-After internally with no opt-out. Keep the
// adaptive family selection, but use the installed Gun client with retry=0.
@external(erlang, "httpc_adaptive_ffi", "request_without_retry")
fn request_without_retry(
  host: String,
  port: Int,
  secure: Bool,
  path: String,
  method: String,
  headers: List(#(String, String)),
  body: BitArray,
  timeout_ms: Int,
  family: IpFamily,
  read_error_body: Bool,
) -> Result(Response(BitArray), Error)

fn dispatch_without_retry(
  req: Request(BitArray),
  timeout_ms: Int,
  family: IpFamily,
) -> Result(Response(BitArray), Error) {
  dispatch_with_error_body(req, timeout_ms, family, False)
}

fn dispatch_plain_without_retry(
  req: Request(BitArray),
  timeout_ms: Int,
  family: IpFamily,
) -> Result(Response(BitArray), Error) {
  dispatch_with_error_body(req, timeout_ms, family, True)
}

fn dispatch_with_error_body(
  req: Request(BitArray),
  timeout_ms: Int,
  family: IpFamily,
  read_error_body: Bool,
) -> Result(Response(BitArray), Error) {
  let port =
    option.unwrap(req.port, case req.scheme {
      http.Http -> 80
      http.Https -> 443
    })
  let path = case req.path {
    "" -> "/"
    path -> path
  }
  let path = case req.query {
    option.None -> path
    option.Some(query) -> path <> "?" <> query
  }
  request_without_retry(
    req.host,
    port,
    req.scheme == http.Https,
    path,
    http.method_to_string(req.method),
    req.headers,
    req.body,
    timeout_ms,
    family,
    read_error_body,
  )
}

type SelectedFamily {
  Unknown
  UseIpv4
  UseIpv6
}

pub type IpFamily {
  Ipv4
  Ipv6
}

@external(erlang, "httpc_adaptive_ffi", "selected_family")
fn selected_family() -> SelectedFamily

@external(erlang, "httpc_adaptive_ffi", "ipv6_host_verified")
fn ipv6_host_verified(host: String) -> Bool

@external(erlang, "httpc_adaptive_ffi", "remember_ipv6_host")
fn remember_ipv6_host(host: String) -> Nil

@external(erlang, "httpc_adaptive_ffi", "fallback_to_ipv4")
fn fallback_to_ipv4(warning: String) -> Nil

@external(erlang, "httpc_adaptive_ffi", "select_ipv4")
fn select_ipv4() -> Nil

@external(erlang, "httpc_adaptive_ffi", "take_warning")
pub fn take_warning() -> Option(String)

pub fn dispatch(
  request: Request(String),
  timeout_ms timeout_ms: Int,
) -> Result(Response(String), Error) {
  let request = request.map(request, bit_array.from_string)
  use response <- result.try(dispatch_bits(request, timeout_ms: timeout_ms))

  case bit_array.to_string(response.body) {
    Ok(body) -> Ok(response.set_body(response, body))
    Error(_) -> Error(InvalidUtf8Response)
  }
}

pub fn dispatch_bits(
  request: Request(BitArray),
  timeout_ms timeout_ms: Int,
) -> Result(Response(BitArray), Error) {
  use _ <- result.try(admit(request.host))
  let outcome =
    dispatch_managed_bits_with(
      request,
      timeout_ms,
      dispatch_plain_without_retry,
    )
  record_outcome(request.host, outcome)
  outcome
}

/// Inject the transport so fallback behavior can be tested without network I/O.
pub fn dispatch_bits_with(
  request: Request(BitArray),
  timeout_ms: Int,
  client: fn(Request(BitArray), Int, IpFamily) ->
    Result(Response(BitArray), Error),
) -> Result(Response(BitArray), Error) {
  let family = select_family(request, client)
  client(request, timeout_ms, family)
}

/// Managed metadata calls must not turn TLS/input failures into IPv4 retries.
pub fn dispatch_managed_bits_with(
  request: Request(BitArray),
  timeout_ms: Int,
  client: fn(Request(BitArray), Int, IpFamily) ->
    Result(Response(BitArray), Error),
) -> Result(Response(BitArray), Error) {
  use family <- result.try(select_family_with(request, client))
  client(request, timeout_ms, family)
}

/// Reuse the command's family selection with a bounded transport for the probe.
pub fn select_family(
  request: Request(BitArray),
  client: fn(Request(BitArray), Int, IpFamily) ->
    Result(Response(BitArray), Error),
) -> IpFamily {
  case select_family_with(request, client) {
    Ok(family) -> family
    Error(error) -> {
      fallback_to_ipv4(ipv6_fallback_warning(error))
      Ipv4
    }
  }
}

@internal
pub fn select_family_with(
  request: Request(BitArray),
  client: fn(Request(BitArray), Int, IpFamily) ->
    Result(Response(BitArray), Error),
) -> Result(IpFamily, Error) {
  shared_probe(request.host, fn() { select_family_in_command(request, client) })
}

fn select_family_in_command(
  request: Request(BitArray),
  client: fn(Request(BitArray), Int, IpFamily) ->
    Result(Response(BitArray), Error),
) -> Result(IpFamily, Error) {
  case selected_family() {
    UseIpv4 -> Ok(Ipv4)
    UseIpv6 ->
      case ipv6_host_verified(request.host) {
        True -> Ok(Ipv6)
        False -> probe_ipv6(request, client)
      }
    Unknown -> probe_ipv6(request, client)
  }
}

fn probe_ipv6(
  request: Request(BitArray),
  client: fn(Request(BitArray), Int, IpFamily) ->
    Result(Response(BitArray), Error),
) -> Result(IpFamily, Error) {
  let probe = Request(..request, method: http.Head, body: <<>>)
  case client(probe, ipv6_probe_timeout_ms, Ipv6) {
    Ok(_) -> {
      remember_ipv6_host(request.host)
      Ok(Ipv6)
    }
    Error(NoIpv6Address) -> {
      select_ipv4()
      Ok(Ipv4)
    }
    Error(TlsFailure(detail)) -> Error(TlsFailure(detail))
    Error(InvalidRequest(detail)) -> Error(InvalidRequest(detail))
    Error(InvalidUtf8Response) -> Error(InvalidUtf8Response)
    Error(error) -> {
      fallback_to_ipv4(ipv6_fallback_warning(error))
      Ok(Ipv4)
    }
  }
}

fn ipv6_fallback_warning(error: Error) -> String {
  let reason = case error {
    ResponseTimeout ->
      "probe timed out after " <> int.to_string(ipv6_probe_timeout_ms) <> "ms"
    FailedToConnect(reason) -> "connection failed: " <> reason
    NoIpv6Address -> "DNS lookup found no IPv6 address"
    RequestFailed(reason) -> "request failed: " <> reason
    InvalidUtf8Response -> "probe returned an invalid response"
    ConnectionFailure(_, detail) | TlsFailure(detail) ->
      "connection failed: " <> detail
    ConnectionClosed(reason) -> "request failed: " <> reason
    InvalidRequest(detail) -> "request invalid: " <> detail
    RetryWaitExceeded(_, _) -> "retry wait exceeded"
    HostUnavailable(host) -> "host unavailable: " <> host
  }
  "IPv6 " <> reason <> "; using IPv4 for the remaining Hex and OSV requests"
}
