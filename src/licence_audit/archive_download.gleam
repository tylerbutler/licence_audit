import gleam/bit_array
import gleam/bool
import gleam/http
import gleam/http/request as http_request
import gleam/http/response.{type Response, Response}
import gleam/int
import gleam/list
import gleam/option
import gleam/result
import gleam/string
import gluegun/connection
import gluegun/error
import gluegun/fin
import gluegun/message
import gluegun/request
import licence_audit/httpc_adaptive

pub const max_download_bytes = 67_108_864

pub type Error {
  NetworkFailure(reason: error.GluegunError)
  Timeout
  UnexpectedResponse(status: Int)
  DownloadTooLarge(limit: Int)
}

type TimeUnit {
  Millisecond
}

@external(erlang, "erlang", "monotonic_time")
fn monotonic_time(unit: TimeUnit) -> Int

pub fn fetch(
  request: http_request.Request(BitArray),
  timeout_ms: Int,
) -> Result(BitArray, Error) {
  fetch_with_limit(request, timeout_ms, max_download_bytes)
}

/// Small limits let loopback tests exercise the same byte checks and teardown.
pub fn fetch_with_limit(
  request: http_request.Request(BitArray),
  timeout_ms: Int,
  limit: Int,
) -> Result(BitArray, Error) {
  let deadline = monotonic_time(Millisecond) + timeout_ms
  let family =
    httpc_adaptive.select_family(request, fn(probe, probe_timeout, family) {
      send(
        probe,
        int.min(deadline, monotonic_time(Millisecond) + probe_timeout),
        family,
        limit,
      )
      |> result.map_error(fn(error) {
        case error {
          Timeout -> httpc_adaptive.ResponseTimeout
          NetworkFailure(reason) -> probe_error(reason)
          UnexpectedResponse(status) ->
            httpc_adaptive.RequestFailed(
              "unexpected HTTP response " <> int.to_string(status),
            )
          DownloadTooLarge(limit) ->
            httpc_adaptive.RequestFailed(
              "archive exceeds " <> int.to_string(limit) <> " bytes",
            )
        }
      })
    })
  send(request, deadline, family, limit)
  |> result.map(fn(response) { response.body })
}

fn probe_error(reason: error.GluegunError) -> httpc_adaptive.Error {
  case reason {
    error.Timeout -> httpc_adaptive.ResponseTimeout
    error.ConnectionDown(reason) | error.ConnectionError(reason) ->
      httpc_adaptive.FailedToConnect(reason)
    error.StreamError(reason)
    | error.InvalidOptions(reason)
    | error.InvalidMessage(reason)
    | error.UnsupportedFeature(reason)
    | error.ErlangError(reason)
    | error.DecodeError(reason) -> httpc_adaptive.RequestFailed(reason)
  }
}

fn remaining_timeout(deadline: Int) -> Result(connection.Timeout, Error) {
  let remaining = deadline - monotonic_time(Millisecond)
  use <- bool.guard(when: remaining <= 0, return: Error(Timeout))
  connection.milliseconds(remaining)
  |> result.map_error(NetworkFailure)
}

fn send(
  request: http_request.Request(BitArray),
  deadline: Int,
  family: httpc_adaptive.IpFamily,
  limit: Int,
) -> Result(Response(BitArray), Error) {
  use timeout <- result.try(remaining_timeout(deadline))
  use retries <- result.try(
    connection.retry_count(0) |> result.map_error(NetworkFailure),
  )
  let transport = case request.scheme {
    http.Http -> connection.Tcp
    http.Https -> connection.Tls
  }
  let family = case family {
    httpc_adaptive.Ipv4 -> connection.Ipv4
    httpc_adaptive.Ipv6 -> connection.Ipv6
  }
  let port =
    option.unwrap(request.port, case request.scheme {
      http.Http -> 80
      http.Https -> 443
    })
  use socket <- result.try(
    connection.options()
    |> connection.with_transport(transport)
    |> connection.with_protocols([connection.Http1])
    |> connection.with_address_family(family)
    |> connection.with_retry(retries)
    |> connection.with_domain_lookup_timeout(timeout)
    |> connection.with_connect_timeout(timeout)
    |> connection.with_tls_handshake_timeout(timeout)
    |> connection.open(host: request.host, port: port)
    |> result.map_error(NetworkFailure),
  )
  let outcome = receive_response(socket, request, deadline, limit)
  let closed = case outcome {
    Ok(_) -> connection.close(socket)
    Error(_) -> Ok(Nil)
  }
  // Stop the sender before flushing, including on header/body rejection.
  let terminated = connection.terminate(socket)
  case closed, terminated {
    Ok(_), Ok(_) -> outcome
    Error(reason), _ | _, Error(reason) -> Error(NetworkFailure(reason))
  }
}

fn receive_response(
  socket: connection.Connection,
  request: http_request.Request(BitArray),
  deadline: Int,
  limit: Int,
) -> Result(Response(BitArray), Error) {
  use timeout <- result.try(remaining_timeout(deadline))
  use _protocol <- result.try(
    connection.await_up(socket, timeout) |> result.map_error(transport_error),
  )
  use options <- result.try(
    request.options()
    |> request.with_initial_flow(1)
    |> result.map_error(NetworkFailure),
  )
  let path = case request.path {
    "" -> "/"
    path -> path
  }
  let path = case request.query {
    option.None -> path
    option.Some(query) -> path <> "?" <> query
  }
  use stream <- result.try(
    request.request(
      socket,
      request.method,
      path,
      request.headers,
      request.body,
      options,
    )
    |> result.map_error(transport_error),
  )
  use #(finished, status, headers) <- result.try(receive_headers(
    socket,
    stream,
    deadline,
  ))
  // HEAD probes check connectivity only and cannot collect response bodies.
  case request.method {
    http.Head -> Ok(Response(status: status, headers: headers, body: <<>>))
    _ -> {
      use <- bool.guard(
        when: status < 200 || status >= 300,
        return: Error(UnexpectedResponse(status)),
      )
      use _ <- result.try(check_content_length(headers, limit))
      use body <- result.try(case finished {
        fin.Fin -> Ok(<<>>)
        fin.NoFin -> receive_body(socket, stream, deadline, limit, 0, [])
      })
      Ok(Response(status: status, headers: headers, body: body))
    }
  }
}

fn await(
  socket: connection.Connection,
  stream: request.Stream,
  deadline: Int,
) -> Result(message.Message, Error) {
  use timeout <- result.try(remaining_timeout(deadline))
  message.await(socket, stream, timeout)
  |> result.map_error(transport_error)
}

fn receive_headers(
  socket: connection.Connection,
  stream: request.Stream,
  deadline: Int,
) -> Result(#(fin.Fin, Int, List(request.Header)), Error) {
  use event <- result.try(await(socket, stream, deadline))
  case event {
    message.Inform(_, _) -> receive_headers(socket, stream, deadline)
    message.Response(finished, status, headers) ->
      Ok(#(finished, status, headers))
    message.Data(_, _)
    | message.Trailers(_)
    | message.Push(_, _, _, _)
    | message.Upgrade(_, _)
    | message.WebSocket(_) ->
      Error(NetworkFailure(error.InvalidMessage("expected response headers")))
  }
}

fn check_content_length(
  headers: List(request.Header),
  limit: Int,
) -> Result(Nil, Error) {
  use _, header <- list.try_fold(headers, Nil)
  let #(name, value) = header
  case string.lowercase(name) {
    "content-length" ->
      case int.parse(string.trim(value)) {
        Ok(size) if size > limit -> Error(DownloadTooLarge(limit))
        Ok(_) | Error(_) -> Ok(Nil)
      }
    _ -> Ok(Nil)
  }
}

fn receive_body(
  socket: connection.Connection,
  stream: request.Stream,
  deadline: Int,
  limit: Int,
  received: Int,
  chunks: List(BitArray),
) -> Result(BitArray, Error) {
  use event <- result.try(await(socket, stream, deadline))
  case event {
    message.Data(finished, data) -> {
      let received = received + bit_array.byte_size(data)
      use <- bool.guard(
        when: received > limit,
        return: Error(DownloadTooLarge(limit)),
      )
      let chunks = [data, ..chunks]
      case finished {
        fin.Fin -> Ok(bit_array.concat(list.reverse(chunks)))
        fin.NoFin -> {
          use _ <- result.try(
            request.update_flow(socket, stream, 1)
            |> result.map_error(transport_error),
          )
          receive_body(socket, stream, deadline, limit, received, chunks)
        }
      }
    }
    message.Trailers(_) -> Ok(bit_array.concat(list.reverse(chunks)))
    message.Inform(_, _)
    | message.Response(_, _, _)
    | message.Push(_, _, _, _)
    | message.Upgrade(_, _)
    | message.WebSocket(_) ->
      Error(NetworkFailure(error.InvalidMessage("expected response body")))
  }
}

fn transport_error(reason: error.GluegunError) -> Error {
  case reason {
    error.Timeout -> Timeout
    error.ConnectionDown(_)
    | error.ConnectionError(_)
    | error.StreamError(_)
    | error.InvalidOptions(_)
    | error.InvalidMessage(_)
    | error.UnsupportedFeature(_)
    | error.ErlangError(_)
    | error.DecodeError(_) -> NetworkFailure(reason)
  }
}
