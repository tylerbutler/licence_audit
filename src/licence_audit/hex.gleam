import gleam/dynamic/decode
import gleam/http.{Get, Https}
import gleam/http/request.{type Request, Request}
import gleam/http/response.{type Response, Response}
import gleam/json
import gleam/option.{None}
import gluegun/client
import gluegun/connection
import gluegun/error as gluegun_error
import gluegun/request as glue_request
import gluegun/response as glue_response

pub type PackageMetadata {
  PackageMetadata(licences: List(String))
}

pub type Error {
  InvalidJson(String)
  InvalidMetadata(String)
  NotFound
  RateLimited
  UnexpectedResponse(status: Int)
  NetworkFailure
}

pub fn decode_package(input: String) -> Result(PackageMetadata, Error) {
  case json.parse(input, using: package_decoder()) {
    Ok(metadata) -> Ok(metadata)
    Error(json.UnableToDecode(_)) ->
      Error(InvalidMetadata("Invalid Hex package metadata"))
    Error(_) -> Error(InvalidJson("Invalid JSON"))
  }
}

pub fn fetch_package_metadata(
  name: String,
  client: fn(Request(String)) -> Result(Response(String), Error),
) -> Result(PackageMetadata, Error) {
  let request = package_request(name)

  case client(request) {
    Error(_) -> Error(NetworkFailure)
    Ok(response) -> decode_response(response)
  }
}

pub fn fetch_package_metadata_from_hex(
  name: String,
) -> Result(PackageMetadata, Error) {
  let timeout = connection.Milliseconds(5000)
  let options =
    connection.options()
    |> connection.with_transport(connection.Tls)

  case connection.open(options, host: "hex.pm", port: 443) {
    Ok(conn) -> fetch_package_metadata_with_connection(conn, name, timeout)
    Error(_) -> Error(NetworkFailure)
  }
}

fn fetch_package_metadata_with_connection(
  conn: connection.Connection,
  name: String,
  timeout: connection.Timeout,
) -> Result(PackageMetadata, Error) {
  let result = case connection.await_up(conn, timeout) {
    Ok(_) -> send_package_request(conn, name, timeout)
    Error(_) -> Error(NetworkFailure)
  }

  let _ = connection.close(conn)
  result
}

fn package_request(name: String) -> Request(String) {
  Request(
    method: Get,
    headers: [],
    body: "",
    scheme: Https,
    host: "hex.pm",
    port: None,
    path: "/api/packages/" <> name,
    query: None,
  )
}

fn send_package_request(
  conn: connection.Connection,
  name: String,
  timeout: connection.Timeout,
) -> Result(PackageMetadata, Error) {
  client.new(glue_request.Get, "/api/packages/" <> name)
  |> client.with_header(name: "user-agent", value: "licence_audit")
  |> client.with_timeout(timeout:)
  |> client.send(conn)
  |> decode_gluegun_response
}

fn decode_gluegun_response(
  response: Result(glue_response.Response, gluegun_error.GluegunError),
) -> Result(PackageMetadata, Error) {
  case response {
    Ok(response) -> {
      case glue_response.body_text(response) {
        Ok(body) ->
          decode_response(Response(
            status: glue_response.status(response),
            headers: [],
            body: body,
          ))
        Error(_) -> Error(NetworkFailure)
      }
    }
    Error(_) -> Error(NetworkFailure)
  }
}

fn decode_response(
  response: Response(String),
) -> Result(PackageMetadata, Error) {
  case response.status {
    404 -> Error(NotFound)
    429 -> Error(RateLimited)
    status if status >= 200 && status < 300 -> decode_package(response.body)
    status -> Error(UnexpectedResponse(status: status))
  }
}

fn package_decoder() -> decode.Decoder(PackageMetadata) {
  use metadata <- decode.optional_field(
    "meta",
    PackageMetadata(licences: []),
    package_metadata_decoder(),
  )

  decode.success(metadata)
}

fn package_metadata_decoder() -> decode.Decoder(PackageMetadata) {
  use upstream_licences <- decode.optional_field(
    "licenses",
    [],
    decode.list(of: decode.string),
  )
  use licences <- decode.optional_field(
    "licences",
    [],
    decode.list(of: decode.string),
  )

  let licences = case upstream_licences {
    [] -> licences
    _ -> upstream_licences
  }

  decode.success(PackageMetadata(licences:))
}
