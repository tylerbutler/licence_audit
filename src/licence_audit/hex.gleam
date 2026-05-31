import gleam/dict
import gleam/dynamic/decode
import gleam/http.{Get, Https}
import gleam/http/request.{type Request, Request}
import gleam/http/response.{type Response}
import gleam/httpc
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string

pub type PackageMetadata {
  PackageMetadata(
    licences: List(String),
    /// Short package summary from Hex `meta.description`, when present.
    description: Option(String),
    /// `meta.links` as `#(label, url)` pairs, sorted by label for
    /// deterministic output (e.g. `#("GitHub", "https://...")`).
    links: List(#(String, String)),
    /// Display name of who published the package, derived best-effort from
    /// Hex `owners` (preferred) or `meta.maintainers` (fallback). Multiple
    /// names are joined with `", "` in stable, alphabetical order. `None`
    /// when Hex exposes neither for the package (a common case).
    publisher: Option(String),
  )
}

/// Construct metadata carrying only licences, with no description, links, or
/// publisher. Used where only licence policy matters (the `check`/`update`
/// paths) and by tests that don't exercise SBOM enrichment.
pub fn licences_only(licences: List(String)) -> PackageMetadata {
  PackageMetadata(licences:, description: None, links: [], publisher: None)
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
    licences_only([]),
    package_metadata_decoder(),
  )
  use owners <- decode.optional_field(
    "owners",
    [],
    decode.list(owner_decoder()),
  )

  // Hex `owners` (top-level) is the authoritative list of people allowed to
  // publish the package; prefer it over `meta.maintainers` (which is often
  // empty or out of date). Fall back to maintainers when owners is absent so
  // we still surface something when Hex hides owners (e.g. for organisations).
  let publisher = case owners {
    [] -> metadata.publisher
    _ -> publisher_from_names(owners)
  }

  decode.success(PackageMetadata(..metadata, publisher: publisher))
}

fn owner_decoder() -> decode.Decoder(String) {
  use username <- decode.field("username", decode.string)
  decode.success(username)
}

/// Join a list of publisher display names into a stable, comma-separated
/// string, dropping blanks and sorting alphabetically so the rendered SBOM
/// is order-independent.
fn publisher_from_names(names: List(String)) -> Option(String) {
  let cleaned =
    names
    |> list.map(string.trim)
    |> list.filter(fn(name) { name != "" })
    |> list.sort(string.compare)
  case cleaned {
    [] -> None
    _ -> Some(string.join(cleaned, ", "))
  }
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
  use description <- decode.optional_field(
    "description",
    None,
    decode.map(decode.string, Some),
  )
  use links <- decode.optional_field(
    "links",
    dict.new(),
    decode.dict(decode.string, decode.string),
  )
  use maintainers <- decode.optional_field(
    "maintainers",
    [],
    decode.list(decode.string),
  )

  let licences = case upstream_licences {
    [] -> licences
    _ -> upstream_licences
  }

  decode.success(PackageMetadata(
    licences:,
    description:,
    links: sorted_links(links),
    publisher: publisher_from_names(maintainers),
  ))
}

fn sorted_links(links: dict.Dict(String, String)) -> List(#(String, String)) {
  links
  |> dict.to_list
  |> list.sort(fn(a, b) { string.compare(a.0, b.0) })
}

/// Serialise metadata for the on-disk cache as a compact JSON object. The
/// cache format is independent of the Hex API shape so it can evolve without
/// reparsing upstream responses; bump the cache filename when it changes.
pub fn encode_cache_entry(metadata: PackageMetadata) -> String {
  let base = [
    #("licences", json.array(metadata.licences, json.string)),
    #(
      "links",
      json.array(metadata.links, fn(pair) {
        json.object([
          #("name", json.string(pair.0)),
          #("url", json.string(pair.1)),
        ])
      }),
    ),
  ]
  let with_description = case metadata.description {
    Some(description) -> [#("description", json.string(description)), ..base]
    None -> base
  }
  let fields = case metadata.publisher {
    Some(publisher) -> [
      #("publisher", json.string(publisher)),
      ..with_description
    ]
    None -> with_description
  }
  json.to_string(json.object(fields))
}

/// Parse a cache entry written by `encode_cache_entry`. Returns `Error(Nil)`
/// on any malformed entry so the caller can treat it as a cache miss.
pub fn decode_cache_entry(encoded: String) -> Result(PackageMetadata, Nil) {
  json.parse(encoded, cache_entry_decoder())
  |> result.replace_error(Nil)
}

fn cache_entry_decoder() -> decode.Decoder(PackageMetadata) {
  use licences <- decode.field("licences", decode.list(decode.string))
  use description <- decode.optional_field(
    "description",
    None,
    decode.map(decode.string, Some),
  )
  use links <- decode.field("links", decode.list(link_decoder()))
  use publisher <- decode.optional_field(
    "publisher",
    None,
    decode.map(decode.string, Some),
  )
  decode.success(PackageMetadata(licences:, description:, links:, publisher:))
}

fn link_decoder() -> decode.Decoder(#(String, String)) {
  use name <- decode.field("name", decode.string)
  use url <- decode.field("url", decode.string)
  decode.success(#(name, url))
}
