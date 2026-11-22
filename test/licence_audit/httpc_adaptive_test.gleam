import gleam/http.{Get, Head, Post}
import gleam/http/request
import gleam/http/response.{Response}
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleeunit/should
import licence_audit/httpc_adaptive.{Ipv4, Ipv6}
import licence_audit/network_retry_test

@external(erlang, "httpc_adaptive_test_ffi", "reset")
fn reset() -> Nil

type Family {
  Inet
  Inet6
}

type TlsAlertCode {
  UnknownCa
}

type ConnectReason {
  Nxdomain
  Econnrefused
  Enetunreach
  Ehostunreach
  Timeout
  Etimedout
  Econnreset
  UnrecognizedReason
  TlsAlert(#(TlsAlertCode, String))
}

type RawError {
  FailedConnect(List(#(Family, List(Nil), ConnectReason)))
  SocketClosedRemotely
  InvalidRequest
  Shutdown
  TcpError(String, ConnectReason)
  SslError(String, ConnectReason)
  StreamError(ClosedReason)
}

type ClosedReason {
  Closed(Result(Nil, ConnectReason))
}

@external(erlang, "httpc_adaptive_ffi", "normalise_error")
fn normalise_error(error: RawError) -> httpc_adaptive.Error

@external(erlang, "httpc_adaptive_test_ffi", "with_http_response")
pub fn with_http_response(response: BitArray, client: fn(String) -> a) -> a

@external(erlang, "httpc_adaptive_test_ffi", "request_with_invalid_options")
fn request_with_invalid_options(has_body: Bool) -> httpc_adaptive.Error

pub fn otp_request_exceptions_keep_class_and_reason_test() {
  list.each([False, True], fn(has_body) {
    should.equal(
      request_with_invalid_options(has_body),
      httpc_adaptive.RequestFailed("Erlang error: badarg"),
    )
  })
}

pub fn successful_get_and_post_requests_pass_through_boundary_test() {
  list.each([Get, Post], fn(method) {
    with_http_response(
      <<
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok":utf8,
      >>,
      fn(url) {
        let assert Ok(req) = request.to(url)
        let req = req |> request.set_method(method) |> request.set_body("body")
        let assert Ok(result) = httpc_adaptive.dispatch(req, timeout_ms: 1000)
        should.equal(result.status, 200)
        should.equal(result.body, "ok")
      },
    )
  })
}

pub fn request_failures_return_typed_errors_test() {
  should.equal(
    normalise_error(SocketClosedRemotely),
    httpc_adaptive.ConnectionClosed("socket_closed_remotely"),
  )
  should.equal(
    normalise_error(Shutdown),
    httpc_adaptive.ConnectionClosed("shutdown"),
  )
  should.equal(
    normalise_error(InvalidRequest),
    httpc_adaptive.InvalidRequest("invalid_request"),
  )
  should.equal(
    normalise_error(FailedConnect([])),
    httpc_adaptive.FailedToConnect("{failed_connect,[]}"),
  )
}

pub fn actual_socket_error_tuples_retain_retryable_reasons_but_not_tls_errors_test() {
  let assert Ok(req) = request.to("https://hex.pm/api/packages/example")
  list.each(
    [
      TcpError("socket", Econnreset),
      SslError("socket", Econnreset),
      StreamError(Closed(Error(Econnreset))),
    ],
    fn(raw) {
      let failure = normalise_error(raw)
      should.equal(failure, httpc_adaptive.ConnectionClosed("econnreset"))
      network_retry_test.with_script(
        [
          Error(failure),
          Ok(Response(200, [], "")),
        ],
        fn() {
          should.equal(
            network_retry_test.send(req, 1),
            Ok(Response(200, [], "")),
          )
        },
      )
    },
  )
  list.each(
    [
      SslError("socket", TlsAlert(#(UnknownCa, "untrusted"))),
      StreamError(Closed(Error(TlsAlert(#(UnknownCa, "untrusted"))))),
    ],
    fn(raw) {
      let failure = normalise_error(raw)
      should.equal(
        failure,
        httpc_adaptive.TlsFailure(
          "TLS handshake failed: unknown_ca (untrusted)",
        ),
      )
      network_retry_test.with_script([Error(failure)], fn() {
        should.equal(network_retry_test.send(req, 2), Error(failure))
        should.equal(list.length(network_retry_test.requests()), 1)
      })
    },
  )
}

@external(erlang, "httpc_adaptive_test_ffi", "with_retry_response")
fn with_retry_response(response: BitArray, client: fn(String) -> a) -> #(a, Int)

@external(erlang, "httpc_adaptive_test_ffi", "with_backlog_response")
fn with_backlog_response(
  response: BitArray,
  client: fn(String) -> a,
) -> #(a, Int)

@external(erlang, "httpc_adaptive_test_ffi", "with_retry_responses")
fn with_retry_responses(
  responses: List(BitArray),
  client: fn(String) -> a,
) -> #(a, Int)

@external(erlang, "httpc_adaptive_test_ffi", "with_recorded_response")
fn with_recorded_response(
  response: BitArray,
  client: fn(String) -> a,
) -> #(a, List(String))

pub fn managed_transport_preserves_get_post_path_headers_and_body_test() {
  list.each([#(Get, ""), #(Post, "{\"queries\":[]}")], fn(sample) {
    let #(method, body) = sample
    let #(outcome, requests) =
      with_recorded_response(
        <<
          "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok":utf8,
        >>,
        fn(url) {
          let assert Ok(req) = request.to(url)
          let req = request.Request(..req, query: Some("selected=1"))
          let req =
            req
            |> request.set_method(method)
            |> request.set_path("/metadata")
            |> request.set_body(body)
            |> request.set_header("content-type", "application/json")
            |> request.set_header("x-test", "pinned")
          httpc_adaptive.dispatch_retry(req, 1000, 1)
        },
      )
    let assert Ok(response) = outcome
    should.equal(response.body, "ok")
    let assert [sent] = requests
    assert string.starts_with(
      sent,
      http.method_to_string(method) <> " /metadata?selected=1 HTTP/1.1\r\n",
    )
    assert string.contains(sent, "x-test: pinned\r\n")
    assert string.contains(sent, "content-type: application/json\r\n")
    assert string.ends_with(sent, "\r\n\r\n" <> body)
  })
}

pub fn queued_data_after_deadline_cannot_be_accepted_as_success_test() {
  let #(outcome, count) =
    with_backlog_response(
      <<
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok":utf8,
      >>,
      fn(url) {
        let assert Ok(req) = request.to(url)
        httpc_adaptive.dispatch_retry(req, 50, 0)
      },
    )
  should.equal(outcome, Error(httpc_adaptive.ResponseTimeout))
  should.equal(count, 1)
}

pub fn partial_body_disconnect_retries_at_raw_transport_boundary_test() {
  let #(outcome, count) =
    with_retry_responses(
      [
        <<
          "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nx":utf8,
        >>,
        <<
          "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok":utf8,
        >>,
      ],
      fn(url) {
        let assert Ok(req) = request.to(url)
        httpc_adaptive.dispatch_retry(req, 1000, 1)
      },
    )
  let assert Ok(response) = outcome
  should.equal(response.body, "ok")
  should.equal(count, 2)
}

@external(erlang, "archive_download_test_ffi", "with_untrusted_tls")
fn with_untrusted_tls(client: fn(String) -> a) -> a

pub fn retry_managed_transport_rejects_untrusted_tls_without_retrying_test() {
  with_untrusted_tls(fn(url) {
    let assert Ok(req) = request.to(url)
    let assert Error(httpc_adaptive.TlsFailure(detail)) =
      httpc_adaptive.dispatch_retry(req, 1000, 2)
    assert detail != ""
  })
}

pub fn unverified_host_probe_never_falls_back_or_retries_tls_input_decode_failures_test() {
  let assert Ok(req) = request.to("https://hex.pm/api/packages/example")
  let req = request.map(req, fn(_) { <<>> })
  list.each(
    [
      httpc_adaptive.TlsFailure("unknown_ca"),
      httpc_adaptive.InvalidRequest("invalid input"),
      httpc_adaptive.InvalidUtf8Response,
    ],
    fn(failure) {
      network_retry_test.with_script([], fn() {
        should.equal(
          httpc_adaptive.dispatch_retry_with(
            req,
            2,
            httpc_adaptive.dispatch_managed_bits_with(
              _,
              5000,
              fn(sent, timeout, family) {
                should.equal(sent.method, Head)
                should.equal(family, Ipv6)
                should.equal(timeout, 1000)
                network_retry_test.record_request(
                  request.map(sent, fn(_) { "" }),
                )
                Error(failure)
              },
            ),
            network_retry_test.now_ms,
            network_retry_test.elapsed_ms,
            network_retry_test.sleep,
          ),
          Error(failure),
        )
        should.equal(list.length(network_retry_test.requests()), 1)
        should.equal(httpc_adaptive.take_warning(), None)
      })
    },
  )
}

pub fn managed_probe_keeps_connectivity_and_no_address_fallback_test() {
  let assert Ok(req) = request.to("https://hex.pm/api/packages/example")
  let req = request.map(req, fn(_) { <<>> })
  list.each(
    [httpc_adaptive.ResponseTimeout, httpc_adaptive.NoIpv6Address],
    fn(failure) {
      reset()
      let expected = Response(200, [], <<"ok":utf8>>)
      should.equal(
        httpc_adaptive.dispatch_managed_bits_with(
          req,
          5000,
          fn(sent, timeout, family) {
            case family {
              Ipv6 -> {
                should.equal(sent.method, Head)
                should.equal(timeout, 1000)
                Error(failure)
              }
              Ipv4 -> {
                should.equal(sent, req)
                should.equal(timeout, 5000)
                Ok(expected)
              }
            }
          },
        ),
        Ok(expected),
      )
      should.equal(
        httpc_adaptive.take_warning(),
        case failure == httpc_adaptive.NoIpv6Address {
          True -> None
          False ->
            Some(
              "IPv6 probe timed out after 1000ms; using IPv4 for the remaining Hex and OSV requests",
            )
        },
      )
      reset()
    },
  )
}

pub fn raw_503_responses_do_not_trigger_hidden_transport_retries_test() {
  list.each([1, 2], fn(retries) {
    let #(outcome, count) =
      with_retry_response(
        <<
          "HTTP/1.1 503 Unavailable\r\nRetry-After: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n":utf8,
        >>,
        fn(url) {
          let assert Ok(req) = request.to(url)
          httpc_adaptive.dispatch_retry(req, 1000, retries)
        },
      )
    let assert Ok(response) = outcome
    should.equal(response.status, 503)
    should.equal(count, retries + 1)
  })

  let #(outcome, count) =
    with_retry_response(
      <<
        "HTTP/1.1 503 Unavailable\r\nRetry-After: 31\r\nContent-Length: 0\r\nConnection: close\r\n\r\n":utf8,
      >>,
      fn(url) {
        let assert Ok(req) = request.to(url)
        httpc_adaptive.dispatch_retry(req, 1000, 2)
      },
    )
  should.equal(outcome, Error(httpc_adaptive.RetryWaitExceeded(31_000, 30_000)))
  should.equal(count, 1)
}

pub fn raw_success_resets_streak_before_utf8_decode_failure_test() {
  let #(outcome, count) =
    with_retry_response(
      <<
        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n":utf8,
        255,
      >>,
      fn(url) {
        let assert Ok(req) = request.to(url)
        let timeout = fn() {
          httpc_adaptive.dispatch_retry_with(
            req,
            0,
            fn(_) { Error(httpc_adaptive.ResponseTimeout) },
            fn() { 0 },
            fn() { 0 },
            fn(_) { Nil },
          )
        }
        should.equal(timeout(), Error(httpc_adaptive.ResponseTimeout))
        should.equal(timeout(), Error(httpc_adaptive.ResponseTimeout))
        should.equal(
          httpc_adaptive.dispatch_retry(req, 1000, 1),
          Error(httpc_adaptive.InvalidUtf8Response),
        )
        should.equal(timeout(), Error(httpc_adaptive.ResponseTimeout))
        httpc_adaptive.dispatch_retry_with(
          req,
          0,
          fn(_) { Ok(Response(200, [], "")) },
          fn() { 0 },
          fn() { 0 },
          fn(_) { Nil },
        )
      },
    )
  should.equal(outcome, Ok(Response(200, [], "")))
  should.equal(count, 1)
}

pub fn peer_disconnect_returns_error_instead_of_raising_test() {
  with_http_response(<<>>, fn(url) {
    let assert Ok(req) = request.to(url)
    let assert Error(httpc_adaptive.ConnectionClosed(_)) =
      httpc_adaptive.dispatch(req, timeout_ms: 1000)
  })
}

pub fn ipv6_timeout_has_bounded_probe_and_remembers_ipv4_test() {
  reset()
  let assert Ok(req) = request.to("https://hex.pm/api/packages/collie")
  let req = request.map(req, fn(_) { <<>> })
  let expected = Response(200, [], <<"metadata":utf8>>)
  let client = fn(sent: request.Request(BitArray), timeout_ms, family) {
    case sent.method {
      Head -> {
        should.equal(family, Ipv6)
        should.equal(timeout_ms, 1000)
        should.equal(sent.body, <<>>)
        Error(httpc_adaptive.ResponseTimeout)
      }
      _ -> {
        should.equal(sent, req)
        should.equal(family, Ipv4)
        should.equal(timeout_ms, 5000)
        Ok(expected)
      }
    }
  }
  should.equal(
    httpc_adaptive.dispatch_bits_with(req, 5000, client),
    Ok(expected),
  )
  should.equal(
    httpc_adaptive.take_warning(),
    Some(
      "IPv6 probe timed out after 1000ms; using IPv4 for the remaining Hex and OSV requests",
    ),
  )

  let assert Ok(osv) = request.to("https://api.osv.dev/v1/querybatch")
  let osv =
    osv
    |> request.set_method(Post)
    |> request.set_body(<<"query":utf8>>)
  should.equal(
    httpc_adaptive.dispatch_bits_with(osv, 8000, fn(sent, timeout_ms, family) {
      should.equal(sent, osv)
      should.equal(family, Ipv4)
      should.equal(timeout_ms, 8000)
      Ok(expected)
    }),
    Ok(expected),
  )
  should.equal(httpc_adaptive.take_warning(), None)
  reset()
}

pub fn successful_ipv6_probe_is_reused_only_for_verified_host_test() {
  reset()
  let assert Ok(req) = request.to("https://hex.pm/api/packages/collie")
  let req = request.map(req, fn(_) { <<>> })
  let expected = Response(200, [], <<>>)
  let probe_client = fn(sent: request.Request(BitArray), timeout_ms, family) {
    should.equal(family, Ipv6)
    case sent.method {
      Head -> should.equal(timeout_ms, 1000)
      _ -> should.equal(timeout_ms, 5000)
    }
    Ok(expected)
  }
  should.equal(
    httpc_adaptive.dispatch_bits_with(req, 5000, probe_client),
    Ok(expected),
  )
  should.equal(
    httpc_adaptive.dispatch_bits_with(req, 5000, fn(sent, timeout_ms, family) {
      should.equal(sent.method, Get)
      should.equal(timeout_ms, 5000)
      should.equal(family, Ipv6)
      Ok(expected)
    }),
    Ok(expected),
  )
  should.equal(httpc_adaptive.take_warning(), None)

  let assert Ok(other) = request.to("https://api.osv.dev/v1/querybatch")
  let other = request.map(other, fn(_) { <<>> })
  should.equal(
    httpc_adaptive.dispatch_bits_with(other, 5000, fn(sent, _, family) {
      case family {
        Ipv6 -> {
          should.equal(sent.method, Head)
          Error(httpc_adaptive.FailedToConnect("IPv6: network unreachable"))
        }
        Ipv4 -> {
          should.equal(sent, other)
          Ok(expected)
        }
      }
    }),
    Ok(expected),
  )
  let assert Some(_) = httpc_adaptive.take_warning()
  reset()
}

pub fn ipv4_failure_is_not_hidden_by_probe_failure_test() {
  reset()
  let assert Ok(req) = request.to("https://hex.pm/api/packages/collie")
  let req = request.map(req, fn(_) { <<>> })
  let failure =
    httpc_adaptive.FailedToConnect(
      "IPv4: TCP connection refused (econnrefused)",
    )
  should.equal(
    httpc_adaptive.dispatch_bits_with(req, 5000, fn(_, _, family) {
      case family {
        Ipv6 -> Error(httpc_adaptive.ResponseTimeout)
        Ipv4 -> Error(failure)
      }
    }),
    Error(failure),
  )
  reset()
}

pub fn absent_ipv6_address_selects_ipv4_silently_and_reuses_selection_test() {
  reset()
  let assert Ok(req) = request.to("https://hex.pm/api/packages/collie")
  let req = request.map(req, fn(_) { <<>> })
  let expected = Response(200, [], <<"metadata":utf8>>)
  should.equal(
    httpc_adaptive.dispatch_bits_with(req, 5000, fn(sent, timeout_ms, family) {
      case family {
        Ipv6 -> {
          should.equal(sent.method, Head)
          should.equal(timeout_ms, 1000)
          Error(normalise_error(FailedConnect([#(Inet6, [], Nxdomain)])))
        }
        Ipv4 -> {
          should.equal(sent, req)
          should.equal(timeout_ms, 5000)
          Ok(expected)
        }
      }
    }),
    Ok(expected),
  )
  should.equal(httpc_adaptive.take_warning(), None)

  let assert Ok(other) = request.to("https://api.osv.dev/v1/querybatch")
  let other = other |> request.set_method(Post) |> request.set_body(<<>>)
  list.each([req, other], fn(next) {
    should.equal(
      httpc_adaptive.dispatch_bits_with(
        next,
        8000,
        fn(sent, timeout_ms, family) {
          should.equal(sent, next)
          should.equal(timeout_ms, 8000)
          should.equal(family, Ipv4)
          Ok(expected)
        },
      ),
      Ok(expected),
    )
    should.equal(httpc_adaptive.take_warning(), None)
  })
  let failure = normalise_error(FailedConnect([#(Inet, [], Nxdomain)]))
  should.equal(
    httpc_adaptive.dispatch_bits_with(req, 5000, fn(_, _, family) {
      should.equal(family, Ipv4)
      Error(failure)
    }),
    Error(httpc_adaptive.ConnectionFailure(
      httpc_adaptive.DnsFailure,
      "IPv4: DNS lookup failed (nxdomain)",
    )),
  )
  reset()
}

pub fn ordinary_probe_failures_still_warn_test() {
  let assert Ok(req) = request.to("https://hex.pm/api/packages/collie")
  let req = request.map(req, fn(_) { <<>> })
  list.each(
    [
      normalise_error(FailedConnect([#(Inet6, [], Econnrefused)])),
      normalise_error(
        FailedConnect([
          #(Inet6, [], TlsAlert(#(UnknownCa, "certificate not trusted"))),
        ]),
      ),
      normalise_error(FailedConnect([#(Inet6, [], Timeout)])),
      normalise_error(FailedConnect([#(Inet, [], Nxdomain)])),
      normalise_error(
        FailedConnect([
          #(Inet6, [], Nxdomain),
          #(Inet, [], Nxdomain),
        ]),
      ),
      request_with_invalid_options(False),
      httpc_adaptive.InvalidUtf8Response,
      httpc_adaptive.FailedToConnect("IPv6: DNS lookup failed (nxdomain)"),
    ],
    fn(failure) {
      reset()
      should.equal(
        httpc_adaptive.select_family(req, fn(_, timeout_ms, family) {
          should.equal(timeout_ms, 1000)
          should.equal(family, Ipv6)
          Error(failure)
        }),
        Ipv4,
      )
      let assert Some(_) = httpc_adaptive.take_warning()
      reset()
    },
  )
}

pub fn only_ipv6_dns_nxdomain_has_no_address_error_test() {
  should.equal(
    normalise_error(FailedConnect([#(Inet6, [], Nxdomain)])),
    httpc_adaptive.NoIpv6Address,
  )
  list.each(
    [
      [#(Inet, [], Nxdomain), #(Inet6, [], Nxdomain)],
      [#(Inet6, [], Nxdomain), #(Inet, [], Nxdomain)],
    ],
    fn(options) {
      should.equal(
        normalise_error(FailedConnect(options)),
        httpc_adaptive.ConnectionFailure(
          httpc_adaptive.DnsFailure,
          "IPv4: DNS lookup failed (nxdomain)",
        ),
      )
    },
  )
}

pub fn connection_errors_keep_family_and_stage_details_test() {
  should.equal(
    normalise_error(FailedConnect([#(Inet, [], Nxdomain)])),
    httpc_adaptive.ConnectionFailure(
      httpc_adaptive.DnsFailure,
      "IPv4: DNS lookup failed (nxdomain)",
    ),
  )
  list.each(
    [
      #(
        Econnrefused,
        httpc_adaptive.ConnectionRefused,
        "TCP connection refused (econnrefused)",
      ),
      #(
        Enetunreach,
        httpc_adaptive.NetworkUnreachable,
        "network unreachable (enetunreach)",
      ),
      #(
        Ehostunreach,
        httpc_adaptive.HostUnreachable,
        "host unreachable (ehostunreach)",
      ),
      #(
        Timeout,
        httpc_adaptive.ConnectionTimedOut,
        "connection setup timed out (timeout; HTTP client did not report the DNS/TCP/TLS stage)",
      ),
      #(
        Etimedout,
        httpc_adaptive.ConnectionTimedOut,
        "connection setup timed out (etimedout; HTTP client did not report the DNS/TCP/TLS stage)",
      ),
    ],
    fn(sample) {
      let #(reason, kind, expected) = sample
      list.each([#(Inet, "IPv4"), #(Inet6, "IPv6")], fn(family) {
        should.equal(
          normalise_error(FailedConnect([#(family.0, [], reason)])),
          httpc_adaptive.ConnectionFailure(kind, family.1 <> ": " <> expected),
        )
      })
    },
  )
  list.each([#(Inet, "IPv4"), #(Inet6, "IPv6")], fn(family) {
    should.equal(
      normalise_error(
        FailedConnect([
          #(family.0, [], TlsAlert(#(UnknownCa, "certificate not trusted"))),
        ]),
      ),
      httpc_adaptive.TlsFailure(
        family.1
        <> ": TLS handshake failed: unknown_ca (certificate not trusted)",
      ),
    )
    should.equal(
      normalise_error(FailedConnect([#(family.0, [], UnrecognizedReason)])),
      httpc_adaptive.FailedToConnect(
        family.1 <> ": connection error (unrecognized_reason)",
      ),
    )
  })
}
