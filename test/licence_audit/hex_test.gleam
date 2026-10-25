import gleam/bit_array
import gleam/http.{Get}
import gleam/http/request
import gleam/http/response.{Response}
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleam/time/duration
import gleam/time/timestamp
import gleam/uri
import gleeunit/should
import licence_audit/env
import licence_audit/hex
import licence_audit/httpc_adaptive
import simplifile

const british_licences_json =
  "{\"name\":\"example\",\"meta\":{\"licences\":[\"BSD-3-Clause\"]}}"

const missing_licences_json =
  "{\"name\":\"example\",\"meta\":{\"description\":\"Example package\"}}"

const invalid_metadata_json =
  "{\"name\":\"example\",\"meta\":{\"licences\":\"MIT\"}}"

fn package_fixture() -> String {
  let assert Ok(contents) =
    simplifile.read(from: "test/fixtures/hex_package.json")
  contents
}

pub fn decode_package_response_with_upstream_licences_test() {
  let assert Ok(metadata) = hex.decode_package(package_fixture())

  should.equal(
    metadata,
    hex.PackageMetadata(
      licences: ["Apache-2.0", "MIT"],
      description: Some("Example package"),
      links: [#("HexDocs", "https://hexdocs.pm/example/")],
      publisher: Some("alice, bob"),
    ),
  )
}

pub fn decode_package_response_falls_back_to_maintainers_test() {
  let json =
    "{\"meta\":{\"licences\":[\"MIT\"],\"maintainers\":[\"Carol\",\"Dan\"]}}"
  let assert Ok(metadata) = hex.decode_package(json)

  should.equal(metadata.publisher, Some("Carol, Dan"))
}

pub fn decode_package_response_publisher_none_when_unavailable_test() {
  let json = "{\"meta\":{\"licences\":[\"MIT\"]}}"
  let assert Ok(metadata) = hex.decode_package(json)

  should.equal(metadata.publisher, None)
}

pub fn decode_archive_metadata_uses_immutable_fields_test() {
  let assert Ok(contents) =
    simplifile.read_bits("test/fixtures/sbom_metadata/hex/metadata.config")
  let assert Ok(metadata) = hex.package_metadata_from_archive(contents)

  should.equal(metadata.licences, ["Apache-2.0"])
  should.equal(
    metadata.description,
    Some("Metadata from the locked Hex archive 中文"),
  )
  should.equal(metadata.links, [
    #("Documentation", "https://hexdocs.pm/hex_dep"),
    #("Repository", "https://github.com/example/hex_dep"),
  ])
  should.equal(metadata.publisher, None)
}

pub fn decode_archive_metadata_rejects_invalid_terms_test() {
  should.equal(
    hex.package_metadata_from_archive(<<"not erlang terms":utf8>>),
    Error(Nil),
  )
}

pub fn decode_archive_metadata_converts_latin1_strings_test() {
  let input = <<
    "{<<\"description\">>, <<\"Caf\\351\">>}.\n{<<\"licenses\">>, []}.\n":utf8,
  >>
  let assert Ok(metadata) = hex.package_metadata_from_archive(input)
  let assert Some(description) = metadata.description

  should.equal(bit_array.from_string(description), <<67, 97, 102, 195, 169>>)
}

pub fn decode_archive_metadata_preserves_binary_literals_test() {
  list.each(
    [
      #("<<\"\\x{4E2D}\\x{6587}\"/utf8>>", "中文"),
      #("<<\"中文\"/utf8>>", "中文"),
      #("<<228,184,173,230,150,135>>", "中文"),
      #("<<\"M\",73,\"T\">>", "MIT"),
      #("<<67,97,102,233>>", "Café"),
      #("<<\"Caf\\351\"/utf8>>", "Café"),
      #("<<>>", ""),
      #("<<\"a]}.b,\\\"c\">>", "a]}.b,\"c"),
    ],
    fn(test_case) {
      let #(literal, expected) = test_case
      let input =
        "{<<\"licenses\">>, ["
        <> literal
        <> "]}.\n"
        <> "{<<\"description\">>, "
        <> literal
        <> "}.\n"
        <> "{<<\"links\">>, [{"
        <> literal
        <> ", "
        <> literal
        <> "}]}.\n"
      let assert Ok(metadata) =
        hex.package_metadata_from_archive(bit_array.from_string(input))
      should.equal(metadata.licences, [expected])
      should.equal(metadata.description, Some(expected))
      should.equal(metadata.links, [#(expected, expected)])
    },
  )
}

pub fn decode_archive_metadata_rejects_unsupported_binary_forms_test() {
  list.each(
    [
      "<<256>>",
      "<<1:16>>",
      "<<65/integer>>",
      "<<65/utf8>>",
      "<<\"MIT\"/utf16>>",
      "<<\"\\x{4E2D}\">>",
      "<<\"\\x{D800}\"/utf8>>",
      "<<\"MIT\",>>",
      "<<16#4D,16#49,16#54>>",
      "<<unknown_atom>>",
      "not_a_binary",
    ],
    fn(literal) {
      list.each(["licenses", "description", "links"], fn(field) {
        let value = case field {
          "licenses" -> "[" <> literal <> "]"
          "links" -> "[{<<\"Repository\">>, " <> literal <> "}]"
          _ -> literal
        }
        let input = case field {
          "licenses" -> ""
          _ -> "{<<\"licenses\">>, [<<\"MIT\">>]}.\n"
        }
        should.equal(
          hex.package_metadata_from_archive(bit_array.from_string(
            input <> "{<<\"" <> field <> "\">>, " <> value <> "}.\n",
          )),
          Error(Nil),
        )
      })
    },
  )
}

pub fn decode_archive_metadata_enforces_resource_limits_test() {
  list.each(
    [
      string.repeat(" ", 1_048_577),
      "{<<\"licenses\">>, []}.\n{<<\"nested\">>, "
        <> string.repeat("[", 65)
        <> string.repeat("]", 65)
        <> "}.\n",
    ],
    fn(input) {
      should.equal(
        hex.package_metadata_from_archive(bit_array.from_string(input)),
        Error(Nil),
      )
    },
  )
}

pub fn decode_archive_metadata_does_not_extract_partial_fields_test() {
  list.each(
    [
      "{<<\"licenses\">>, [<<\"MIT\">>, unsupported]}.\n",
      "{<<\"licenses\">>, [<<\"MIT\">>,]}.\n",
      "{<<\"licenses\">>, []}.\n{<<\"description\">>, <<\"ok\">>, extra}.\n",
      "{<<\"licenses\">>, []}.\n{<<\"links\">>, [{<<\"ok\">>, <<\"url\">>}, unsupported]}.\n",
      "{<<\"licenses\">>, []}.\n{<<\"licenses\">>, [<<\"MIT\">>]}.\n",
    ],
    fn(input) {
      should.equal(
        hex.package_metadata_from_archive(bit_array.from_string(input)),
        Error(Nil),
      )
    },
  )
}

pub fn cache_entry_round_trips_full_metadata_test() {
  let metadata =
    hex.PackageMetadata(
      licences: ["MIT", "Apache-2.0"],
      description: Some("A package"),
      links: [#("GitHub", "https://github.com/x/y")],
      publisher: Some("alice, bob"),
    )

  let assert Ok(decoded) =
    hex.decode_cache_entry(hex.encode_cache_entry(metadata))

  should.equal(decoded, metadata)
}

pub fn cache_entry_round_trips_licences_only_test() {
  let metadata = hex.licences_only(["MIT"])

  let assert Ok(decoded) =
    hex.decode_cache_entry(hex.encode_cache_entry(metadata))

  should.equal(decoded, metadata)
}

pub fn decode_cache_entry_rejects_garbage_test() {
  should.equal(hex.decode_cache_entry("not json"), Error(Nil))
}

pub fn decode_package_response_with_licences_test() {
  let assert Ok(metadata) = hex.decode_package(british_licences_json)

  should.equal(metadata.licences, ["BSD-3-Clause"])
}

pub fn decode_package_response_missing_licences_as_empty_list_test() {
  let assert Ok(metadata) = hex.decode_package(missing_licences_json)

  should.equal(metadata.licences, [])
}

pub fn decode_package_response_invalid_json_returns_typed_error_test() {
  let assert Error(error) = hex.decode_package("{")

  case error {
    hex.InvalidJson(_) -> Nil
    _ -> panic as "expected InvalidJson"
  }
}

pub fn decode_package_response_invalid_metadata_returns_typed_error_test() {
  let assert Error(error) = hex.decode_package(invalid_metadata_json)

  case error {
    hex.InvalidMetadata(_) -> Nil
    _ -> panic as "expected InvalidMetadata"
  }
}

pub fn injected_http_success_fetches_hex_package_url_and_decodes_metadata_test() {
  let client = fn(req: request.Request(String)) {
    should.equal(req.method, Get)
    should.equal(
      req |> request.to_uri |> uri.to_string,
      "https://hex.pm/api/packages/example",
    )
    Ok(Response(status: 200, headers: [], body: package_fixture()))
  }

  let assert Ok(metadata) = hex.fetch_package_metadata("example", client)

  should.equal(metadata.licences, ["Apache-2.0", "MIT"])
}

pub fn http_404_maps_to_not_found_test() {
  let client = fn(_req) { Ok(Response(status: 404, headers: [], body: "")) }

  let assert Error(error) = hex.fetch_package_metadata("missing", client)

  should.equal(error, hex.NotFound)
}

pub fn http_429_maps_to_rate_limited_test() {
  let client = fn(_req) { Ok(Response(status: 429, headers: [], body: "")) }

  let assert Error(error) = hex.fetch_package_metadata("example", client)

  should.equal(error, hex.RateLimited)
}

pub fn unexpected_http_status_preserves_status_test() {
  let client = fn(_req) { Ok(Response(status: 500, headers: [], body: "oops")) }

  let assert Error(error) = hex.fetch_package_metadata("example", client)

  should.equal(error, hex.UnexpectedResponse(status: 500))
}

pub fn injected_network_failure_maps_to_network_failure_test() {
  let client = fn(_req) { Error(hex.NetworkFailure("connection refused")) }

  let assert Error(error) = hex.fetch_package_metadata("example", client)

  should.equal(error, hex.NetworkFailure("connection refused"))
}

pub fn http_failures_include_request_and_connection_details_test() {
  let assert Ok(req) = request.to("https://hex.pm/api/packages/example")
  list.each(
    [
      #(
        httpc_adaptive.ResponseTimeout,
        "HTTP request timed out after 5000 ms (HTTP client did not report which stage timed out)",
      ),
      #(httpc_adaptive.InvalidUtf8Response, "response body was not valid UTF-8"),
      #(
        httpc_adaptive.RequestFailed("socket_closed_remotely"),
        "HTTP request failed: socket_closed_remotely",
      ),
      #(
        httpc_adaptive.FailedToConnect("IPv4: DNS lookup failed (nxdomain)"),
        "connection setup failed: IPv4: DNS lookup failed (nxdomain)",
      ),
      #(
        httpc_adaptive.FailedToConnect(
          "IPv4: TCP connection refused (econnrefused)",
        ),
        "connection setup failed: IPv4: TCP connection refused (econnrefused)",
      ),
      #(
        httpc_adaptive.FailedToConnect(
          "IPv4: connection setup timed out (timeout; HTTP client did not report the DNS/TCP/TLS stage)",
        ),
        "connection setup failed: IPv4: connection setup timed out (timeout; HTTP client did not report the DNS/TCP/TLS stage)",
      ),
      #(
        httpc_adaptive.FailedToConnect(
          "IPv4: TLS handshake failed: unknown_ca (certificate not trusted)",
        ),
        "connection setup failed: IPv4: TLS handshake failed: unknown_ca (certificate not trusted)",
      ),
    ],
    fn(test_case) {
      let #(error, detail) = test_case
      should.equal(
        hex.from_http_error(req, error),
        hex.NetworkFailure(
          "GET https://hex.pm/api/packages/example: " <> detail,
        ),
      )
    },
  )
}

pub fn hex_metadata_fetch_returns_without_ipv6_fallback_delay_test() {
  case env.get("LICENCE_AUDIT_NET_TESTS") {
    Ok(value) if value != "" -> {
      let started = timestamp.system_time()

      list.each(["collie", "gleam_stdlib"], fn(name) {
        let assert Ok(metadata) = hex.fetch_package_metadata_from_hex(name)
        assert metadata.licences != []
      })
      assert timestamp.difference(started, timestamp.system_time())
        |> duration.to_milliseconds
        < 5000
    }
    _ -> Nil
  }
}
