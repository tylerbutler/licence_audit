import gleam/bit_array
import gleam/dynamic.{type Dynamic}
import gleam/http.{type Method}
import gleam/http/request.{type Request, Request}
import gleam/http/response.{type Response, Response}
import gleam/int
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gleam/uri

const ipv6_probe_timeout_ms = 1000

pub type Error {
  InvalidUtf8Response
  ResponseTimeout
  FailedToConnect(reason: String)
}

type SelectedFamily {
  Unknown
  UseIpv4
  UseIpv6
}

type IpFamily {
  Ipv4
  Ipv6
}

type Charlist

type ErlHttpOption {
  Autoredirect(Bool)
  ConnectTimeout(Int)
  Timeout(Int)
}

type BodyFormat {
  Binary
}

type ErlOption {
  BodyFormat(BodyFormat)
  SocketOpts(List(SocketOpt))
}

type SocketOpt {
  Ipfamily(InetFamily)
}

type InetFamily {
  Inet
  Inet6
}

@external(erlang, "httpc_adaptive_ffi", "normalise_error")
fn normalise_error(error: Dynamic) -> Error

@external(erlang, "httpc_adaptive_ffi", "selected_family")
fn selected_family() -> SelectedFamily

@external(erlang, "httpc_adaptive_ffi", "ipv6_host_verified")
fn ipv6_host_verified(host: String) -> Bool

@external(erlang, "httpc_adaptive_ffi", "remember_ipv6_host")
fn remember_ipv6_host(host: String) -> Nil

@external(erlang, "httpc_adaptive_ffi", "fallback_to_ipv4")
fn fallback_to_ipv4(warning: String) -> Nil

@external(erlang, "httpc_adaptive_ffi", "take_warning")
pub fn take_warning() -> Option(String)

@external(erlang, "erlang", "binary_to_list")
fn charlist_from_string(value: String) -> Charlist

@external(erlang, "unicode", "characters_to_binary")
fn charlist_to_string(value: Charlist) -> String

@external(erlang, "httpc", "request")
fn erl_request(
  method: Method,
  request: #(Charlist, List(#(Charlist, Charlist)), Charlist, BitArray),
  http_options: List(ErlHttpOption),
  options: List(ErlOption),
) -> Result(
  #(#(Charlist, Int, Charlist), List(#(Charlist, Charlist)), BitArray),
  Dynamic,
)

@external(erlang, "httpc", "request")
fn erl_request_no_body(
  method: Method,
  request: #(Charlist, List(#(Charlist, Charlist))),
  http_options: List(ErlHttpOption),
  options: List(ErlOption),
) -> Result(
  #(#(Charlist, Int, Charlist), List(#(Charlist, Charlist)), BitArray),
  Dynamic,
)

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

fn dispatch_bits(
  request: Request(BitArray),
  timeout_ms timeout_ms: Int,
) -> Result(Response(BitArray), Error) {
  use family <- result.try(select_family(request))
  dispatch_with_family(
    request,
    timeout_ms: timeout_ms,
    connect_timeout_ms: timeout_ms,
    family: family,
  )
}

fn select_family(request: Request(BitArray)) -> Result(IpFamily, Error) {
  case selected_family() {
    UseIpv4 -> Ok(Ipv4)
    UseIpv6 ->
      case ipv6_host_verified(request.host) {
        True -> Ok(Ipv6)
        False -> probe_ipv6(request)
      }
    Unknown -> probe_ipv6(request)
  }
}

fn probe_ipv6(request: Request(BitArray)) -> Result(IpFamily, Error) {
  let probe = Request(..request, method: http.Head, body: <<>>)
  case
    dispatch_with_family(
      probe,
      timeout_ms: ipv6_probe_timeout_ms,
      connect_timeout_ms: ipv6_probe_timeout_ms,
      family: Ipv6,
    )
  {
    Ok(_) -> {
      remember_ipv6_host(request.host)
      Ok(Ipv6)
    }
    Error(error) -> {
      fallback_to_ipv4(ipv6_fallback_warning(error))
      Ok(Ipv4)
    }
  }
}

fn ipv6_fallback_warning(error: Error) -> String {
  let reason = case error {
    ResponseTimeout ->
      "connection timed out after "
      <> int.to_string(ipv6_probe_timeout_ms)
      <> "ms"
    FailedToConnect(reason) -> "connection failed: " <> reason
    InvalidUtf8Response -> "probe returned an invalid response"
  }
  "IPv6 " <> reason <> "; using IPv4 for the remaining network requests"
}

fn dispatch_with_family(
  request: Request(BitArray),
  timeout_ms timeout_ms: Int,
  connect_timeout_ms connect_timeout_ms: Int,
  family family: IpFamily,
) -> Result(Response(BitArray), Error) {
  let url =
    request
    |> request.to_uri
    |> uri.to_string
    |> charlist_from_string
  let headers =
    list.map(request.headers, fn(header) {
      #(charlist_from_string(header.0), charlist_from_string(header.1))
    })
  let http_options = [
    Autoredirect(False),
    ConnectTimeout(connect_timeout_ms),
    Timeout(timeout_ms),
  ]
  let inet_family = case family {
    Ipv4 -> Inet
    Ipv6 -> Inet6
  }
  let options = [BodyFormat(Binary), SocketOpts([Ipfamily(inet_family)])]

  use raw_response <- result.try(
    case request.method {
      http.Options | http.Head | http.Get ->
        erl_request_no_body(
          request.method,
          #(url, headers),
          http_options,
          options,
        )
      _ -> {
        let content_type =
          request
          |> request.get_header("content-type")
          |> result.unwrap("application/octet-stream")
          |> charlist_from_string
        erl_request(
          request.method,
          #(url, headers, content_type, request.body),
          http_options,
          options,
        )
      }
    }
    |> result.map_error(normalise_error),
  )

  let #(#(_version, status, _reason), response_headers, body) = raw_response
  Ok(Response(
    status: status,
    headers: list.map(response_headers, fn(header) {
      #(charlist_to_string(header.0), charlist_to_string(header.1))
    }),
    body: body,
  ))
}
