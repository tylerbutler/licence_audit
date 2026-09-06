import gleam/http.{Get, Head, Post}
import gleam/http/request
import gleam/http/response.{Response}
import gleam/list
import gleam/option.{None, Some}
import gleeunit/should
import licence_audit/httpc_adaptive.{Ipv4, Ipv6}

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
  UnrecognizedReason
  TlsAlert(#(TlsAlertCode, String))
}

type RawError {
  FailedConnect(List(#(Family, List(Nil), ConnectReason)))
}

@external(erlang, "httpc_adaptive_ffi", "normalise_error")
fn normalise_error(error: RawError) -> httpc_adaptive.Error

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

pub fn connection_errors_keep_family_and_stage_details_test() {
  list.each(
    [
      #(Nxdomain, "DNS lookup failed (nxdomain)"),
      #(Econnrefused, "TCP connection refused (econnrefused)"),
      #(Enetunreach, "network unreachable (enetunreach)"),
      #(Ehostunreach, "host unreachable (ehostunreach)"),
      #(
        Timeout,
        "connection setup timed out (timeout; HTTP client did not report the DNS/TCP/TLS stage)",
      ),
      #(
        Etimedout,
        "connection setup timed out (etimedout; HTTP client did not report the DNS/TCP/TLS stage)",
      ),
      #(UnrecognizedReason, "connection error (unrecognized_reason)"),
      #(
        TlsAlert(#(UnknownCa, "certificate not trusted")),
        "TLS handshake failed: unknown_ca (certificate not trusted)",
      ),
    ],
    fn(sample) {
      let #(reason, expected) = sample
      list.each([#(Inet, "IPv4"), #(Inet6, "IPv6")], fn(family) {
        should.equal(
          normalise_error(FailedConnect([#(family.0, [], reason)])),
          httpc_adaptive.FailedToConnect(family.1 <> ": " <> expected),
        )
      })
    },
  )
}
