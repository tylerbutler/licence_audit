import gleam/dynamic/decode
import gleam/http.{Get, Https}
import gleam/http/request.{type Request, Request}
import gleam/http/response.{type Response}
import gleam/httpc
import gleam/json
import gleam/option.{None}

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
  fetch_package_metadata(name, send)
}

/// Default HTTP client: dispatches the request synchronously via Erlang's
/// built-in `httpc` (TLS verified by default).
fn send(req: Request(String)) -> Result(Response(String), Error) {
  let req = request.set_header(req, "user-agent", "licence_audit")
  case
    httpc.configure()
    |> httpc.timeout(5000)
    |> httpc.dispatch(req)
  {
    Ok(response) -> Ok(response)
    Error(_) -> Error(NetworkFailure)
  }
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
