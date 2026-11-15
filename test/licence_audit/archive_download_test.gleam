import gleam/bit_array
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/list
import gleam/option
import gleam/string
import gleeunit/should
import gluegun/error
import licence_audit/archive_download
import licence_audit/httpc_adaptive
import licence_audit/notice

@external(erlang, "archive_download_test_ffi", "with_response")
fn with_response(
  headers: String,
  chunks: List(BitArray),
  delay: Int,
  check: fn(String) -> a,
) -> #(a, Int)

@external(erlang, "archive_download_test_ffi", "with_untrusted_tls")
fn with_untrusted_tls(check: fn(String) -> a) -> a

@external(erlang, "httpc_adaptive_test_ffi", "reset")
fn reset() -> Nil

fn fetch(
  url: String,
  timeout: Int,
  limit: Int,
) -> Result(BitArray, archive_download.Error) {
  let assert Ok(request) = request.to(url)
  archive_download.fetch_with_limit(
    request.map(request, bit_array.from_string),
    timeout,
    limit,
  )
}

pub fn fixed_download_limit_and_error_description_test() {
  should.equal(archive_download.max_download_bytes, 67_108_864)
  should.equal(
    notice.describe_fetch_error(notice.FetchDownloadTooLarge(67_108_864)),
    "source archive download exceeds 67108864 bytes",
  )
}

pub fn content_length_limit_closes_before_body_test() {
  let #(outcome, sent) =
    with_response(
      "HTTP/1.1 200 OK\r\nContent-Length: 65\r\n\r\n",
      [],
      0,
      fn(url) { fetch(url, 1000, 64) },
    )
  should.equal(outcome, Error(archive_download.DownloadTooLarge(64)))
  should.equal(sent, 0)
}

pub fn non_success_status_closes_before_body_test() {
  list.each([302, 404, 500], fn(status) {
    let #(outcome, sent) =
      with_response(
        "HTTP/1.1 "
          <> int.to_string(status)
          <> " Rejected\r\nContent-Length: 2000000000\r\n\r\n",
        [],
        0,
        fn(url) { fetch(url, 1000, 64) },
      )
    should.equal(outcome, Error(archive_download.UnexpectedResponse(status)))
    should.equal(sent, 0)
  })
}

pub fn content_length_and_actual_byte_boundaries_test() {
  list.each([63, 64, 65], fn(size) {
    let body = bit_array.from_string(string.repeat("x", size))
    let expected = case size > 64 {
      True -> Error(archive_download.DownloadTooLarge(64))
      False -> Ok(body)
    }
    list.each(
      [
        "Content-Length: " <> int.to_string(size) <> "\r\n",
        "Connection: close\r\n",
        "Transfer-Encoding: chunked\r\n",
      ],
      fn(framing) {
        let chunks = case string.starts_with(framing, "Transfer-Encoding") {
          True -> [
            bit_array.from_string(int.to_base16(size) <> "\r\n"),
            body,
            <<"\r\n0\r\n\r\n":utf8>>,
          ]
          False -> [body]
        }
        let #(outcome, _) =
          with_response(
            "HTTP/1.1 200 OK\r\n" <> framing <> "\r\n",
            chunks,
            1,
            fn(url) { fetch(url, 1000, 64) },
          )
        should.equal(outcome, expected)
      },
    )
  })
}

pub fn actual_byte_limit_stops_one_large_http_chunk_test() {
  let body = bit_array.from_string(string.repeat("x", 4096))
  let parts = list.repeat(body, 512)
  let #(outcome, sent) =
    with_response(
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n200000\r\n",
      list.append(parts, [<<"\r\n0\r\n\r\n":utf8>>]),
      1,
      fn(url) { fetch(url, 1000, 64) },
    )
  should.equal(outcome, Error(archive_download.DownloadTooLarge(64)))
  assert sent < 2_097_152
}

pub fn actual_byte_limit_stops_many_small_chunks_test() {
  let #(outcome, sent) =
    with_response(
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
      list.append(list.repeat(<<"1\r\nx\r\n":utf8>>, 1024), [
        <<"0\r\n\r\n":utf8>>,
      ]),
      1,
      fn(url) { fetch(url, 1000, 64) },
    )
  should.equal(outcome, Error(archive_download.DownloadTooLarge(64)))
  assert sent < 6144
}

pub fn total_deadline_does_not_reset_after_each_chunk_test() {
  let #(outcome, sent) =
    with_response(
      "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
      list.repeat(<<"x":utf8>>, 64),
      10,
      fn(url) { fetch(url, 50, 64) },
    )
  should.equal(outcome, Error(archive_download.Timeout))
  assert sent < 64
}

pub fn tls_setup_stall_stops_at_total_deadline_test() {
  let #(outcome, _) =
    with_response("", [], 0, fn(url) {
      fetch(string.replace(url, "http://", "https://"), 300, 64)
    })
  should.equal(outcome, Error(archive_download.Timeout))
}

pub fn source_download_preserves_tls_peer_verification_test() {
  with_untrusted_tls(fn(url) {
    let reason = case fetch(url, 2000, 64) {
      Error(archive_download.NetworkFailure(error.ConnectionError(reason)))
      | Error(archive_download.NetworkFailure(error.ConnectionDown(reason))) ->
        reason
      _ -> panic as "expected TLS connection failure"
    }
    assert string.contains(string.lowercase(reason), "unknownca")
      || string.contains(string.lowercase(reason), "unknown_ca")
  })
}

pub fn archive_probe_reuses_command_ipv4_fallback_test() {
  let #(outcome, _) =
    with_response(
      "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n",
      [<<"text":utf8>>],
      0,
      fn(url) {
        reset()
        let outcome =
          fetch(string.replace(url, "127.0.0.1", "localhost"), 2000, 64)
        let assert option.Some(_) = httpc_adaptive.take_warning()
        let assert Ok(metadata_request) = request.to(url)
        let metadata_request =
          request.map(metadata_request, bit_array.from_string)
        let assert Ok(_) =
          httpc_adaptive.dispatch_bits_with(
            metadata_request,
            1000,
            fn(sent, _, family) {
              should.equal(sent, metadata_request)
              should.equal(family, httpc_adaptive.Ipv4)
              Ok(response.Response(200, [], <<>>))
            },
          )
        outcome
      },
    )
  should.equal(outcome, Ok(<<"text":utf8>>))
}

pub fn informational_headers_and_trailers_preserve_body_test() {
  let #(outcome, _) =
    with_response(
      "HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
      [<<"4\r\ntext\r\n0\r\nX-Checksum: fixture\r\n\r\n":utf8>>],
      0,
      fn(url) { fetch(url, 1000, 64) },
    )
  should.equal(outcome, Ok(<<"text":utf8>>))
}
