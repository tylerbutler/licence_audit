import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/json
import gleam/list
import gleam/result
import gleam/string
import gleeunit/should
import licence_audit
import licence_audit/config
import licence_audit/error
import licence_audit/hex
import licence_audit/httpc_adaptive
import licence_audit/network_retry_test
import licence_audit/osv
import licence_audit/progress
import licence_audit/source_archive_test
import simplifile

const commit = "0123456789abcdef0123456789abcdef01234567"

const critical_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

const low_vector = "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"

@external(erlang, "integration_test_ffi", "record_detail_fetch")
fn record_detail_fetch(id: String) -> Int

@external(erlang, "integration_test_ffi", "reset_detail_fetch")
fn reset_detail_fetch(id: String) -> Nil

fn prepare_project(directory: String, packages: String) -> String {
  let root = "build/osv-regression-" <> directory
  let assert Ok(_) = simplifile.create_directory_all(root)
  let assert Ok(_) =
    simplifile.write(
      root <> "/gleam.toml",
      "name = \"osv_fixture\"
version = \"1.0.0\"
[tools.licence_audit]
allow = [\"MIT\"]
",
    )
  let assert Ok(_) =
    simplifile.write(
      root <> "/manifest.toml",
      "packages = [\n" <> packages <> "\n]\n",
    )
  root
}

fn clients() -> licence_audit.Clients {
  let metadata = fn(_) { Ok(hex.licences_only(["MIT"])) }
  licence_audit.Clients(
    ..licence_audit.default_clients(),
    fetcher: metadata,
    notice_clients: source_archive_test.metadata_clients(metadata),
    publication_fetcher: fn(_, _) { Ok(hex.Unpublished) },
  )
}

fn run(
  root: String,
  command: List(String),
  clients: licence_audit.Clients,
) -> licence_audit.RunResult {
  licence_audit.run_configured(
    list.append(command, ["--manifest=" <> root <> "/manifest.toml"]),
    clients,
    progress.disabled(),
  ).0
}

fn hex_package(name: String, version: String) -> String {
  "{ name = \""
  <> name
  <> "\", version = \""
  <> version
  <> "\", source = \"hex\", outer_checksum = \"4C4C81A8F753EE1917FCC9C611745DBB1F8730F2A8B7A1BBDBC9A6B1C69F7A66\" },"
}

pub fn rate_limit_then_success_completes_both_gates_with_exit_zero_test() {
  let root = prepare_project("retry-success", hex_package("first", "1.0.0"))
  network_retry_test.with_script(
    [
      Ok(response.Response(429, [#("retry-after", "1")], "")),
      Ok(response.Response(200, [], "{\"meta\":{\"licenses\":[\"MIT\"]}}")),
      Ok(response.Response(429, [#("x-ratelimit-reset", "1700000002")], "")),
      Ok(response.Response(200, [], "{\"results\":[{}]}")),
    ],
    fn() {
      let result =
        run(
          root,
          ["check", "--checks=all"],
          licence_audit.Clients(
            ..clients(),
            notice_clients: source_archive_test.metadata_clients(fn(name) {
              hex.fetch_package_metadata(name, fn(req) {
                network_retry_test.send(req, 1)
                |> result.map_error(hex.from_http_error(req, _))
              })
            }),
            osv_batch_fetcher: fn(purls) {
              osv.query_batch(purls, fn(req) {
                network_retry_test.send(req, 2)
                |> result.map_error(osv.from_http_error(req, _))
              })
            },
          ),
        )
      should.equal(result.exit_code, 0)
      should.equal(list.length(network_retry_test.requests()), 4)
    },
  )
}

pub fn later_chunk_pagination_failure_is_incomplete_with_exit_two_test() {
  let packages =
    list.repeat(Nil, 1001)
    |> list.index_map(fn(_, index) {
      hex_package("package" <> int.to_string(index + 1), "1.0.0")
    })
    |> string.join("\n")
  let root = prepare_project("retry-chunks", packages)
  network_retry_test.with_script([], fn() {
    let #(result, events) =
      licence_audit.run_configured(
        ["check", "--checks=vulns", "--manifest=" <> root <> "/manifest.toml"],
        licence_audit.Clients(..clients(), osv_batch_fetcher: fn(purls) {
          osv.query_batch(purls, fn(req) {
            network_retry_test.record_request(req)
            case string.contains(req.body, "page_token") {
              True -> Error(osv.NetworkFailure("late pagination failed"))
              False -> {
                let decoder = {
                  use queries <- decode.field(
                    "queries",
                    decode.list(decode.dynamic),
                  )
                  decode.success(list.length(queries))
                }
                let assert Ok(count) = json.parse(req.body, decoder)
                let entries = case count {
                  1 -> [
                    json.object([#("next_page_token", json.string("late"))]),
                  ]
                  _ -> list.repeat(json.object([]), count)
                }
                Ok(response.Response(
                  200,
                  [],
                  json.to_string(
                    json.object([
                      #("results", json.preprocessed_array(entries)),
                    ]),
                  ),
                ))
              }
            }
          })
        }),
        progress.capturing(progress.Normal, "test"),
      )
    should.equal(result.exit_code, 2)
    assert list.any(events, fn(event) {
      string.contains(event.message, "late pagination failed")
    })
    assert !string.contains(result.output, "No known vulnerabilities")
    should.equal(list.length(network_retry_test.requests()), 3)
  })
}

pub fn exhausted_host_operations_fail_incomplete_and_reset_for_next_command_test() {
  let packages =
    list.repeat(Nil, 4)
    |> list.index_map(fn(_, index) {
      hex_package("package" <> int.to_string(index + 1), "1.0.0")
    })
    |> string.join("\n")
  let root = prepare_project("retry-cutoff", packages)
  let timeouts = list.repeat(Error(httpc_adaptive.ResponseTimeout), 6)
  let successes =
    list.repeat(
      Ok(response.Response(200, [], "{\"meta\":{\"licenses\":[\"MIT\"]}}")),
      4,
    )
  network_retry_test.with_script(list.append(timeouts, successes), fn() {
    let clients =
      licence_audit.Clients(
        ..clients(),
        notice_clients: source_archive_test.metadata_clients(fn(name) {
          hex.fetch_package_metadata(name, fn(req) {
            network_retry_test.send(req, 1)
            |> result.map_error(hex.from_http_error(req, _))
          })
        }),
      )
    let failed = run(root, ["report"], clients)
    should.equal(failed.exit_code, 2)
    assert string.contains(failed.output, "network failure")
    should.equal(list.length(network_retry_test.requests()), 6)
    should.equal(run(root, ["report"], clients).exit_code, 0)
    should.equal(list.length(network_retry_test.requests()), 10)
  })
}

fn affected(name: String, versions: String, vector: String) -> json.Json {
  json.object([
    #(
      "package",
      json.object([
        #("ecosystem", json.string("Hex")),
        #("name", json.string(name)),
      ]),
    ),
    #("versions", json.array(string.split(versions, ","), json.string)),
    #(
      "severity",
      json.array([vector], fn(vector) {
        json.object([
          #("type", json.string("CVSS_V3")),
          #("score", json.string(vector)),
        ])
      }),
    ),
  ])
}

fn package_severity_detail(id: String) -> Result(osv.Vulnerability, osv.Error) {
  osv.decode_vuln_body(
    json.to_string(
      json.object([
        #("id", json.string(id)),
        #("aliases", json.array(["CVE-alias"], json.string)),
        #(
          "affected",
          json.preprocessed_array([
            affected("first", "1.0.0", critical_vector),
            affected("first", "2.0.0", low_vector),
            affected("second", "1.0.0", low_vector),
            affected("unselected", "1.0.0", critical_vector),
          ]),
        ),
      ]),
    ),
    id,
  )
}

fn shared_batch(
  purls: List(String),
) -> Result(List(osv.BatchEntry), osv.Error) {
  Ok(list.map(purls, fn(purl) { osv.BatchEntry(purl, ["OSV-shared"]) }))
}

pub fn package_severity_applies_before_both_gates_and_report_test() -> Nil {
  use #(name, version, severity, exit_code) <- list.each([
    #("first", "1.0.0", "CRITICAL", 1),
    #("first", "2.0.0", "LOW", 0),
    #("second", "1.0.0", "LOW", 0),
  ])
  let root = prepare_project("severity", hex_package(name, version))
  use command <- list.each([
    ["vulns"],
    ["check", "--checks=vulns"],
    ["check", "--checks=all"],
  ])
  let result =
    run(
      root,
      command,
      licence_audit.Clients(
        ..clients(),
        osv_batch_fetcher: shared_batch,
        osv_detail_fetcher: package_severity_detail,
      ),
    )
  let expected_exit = case command {
    ["vulns"] -> 0
    _ -> exit_code
  }
  should.equal(result.exit_code, expected_exit)
  assert string.contains(result.output, "[" <> severity)
  assert !string.contains(result.output, "[UNKNOWN")
  case command {
    ["vulns"] -> Nil
    _ -> {
      assert string.contains(result.output, "(of 1 total reported)")
    }
  }
}

pub fn advisory_counts_remain_deduplicated_with_distinct_package_ratings_test() -> Nil {
  let root =
    prepare_project(
      "counts",
      hex_package("first", "1.0.0") <> "\n" <> hex_package("second", "1.0.0"),
    )
  use command <- list.each([
    ["check", "--checks=vulns"],
    ["check", "--checks=all"],
  ])
  use threshold <- list.each(["high", "low"])
  reset_detail_fetch("OSV-shared")
  let result =
    run(
      root,
      list.append(command, ["--vuln-severity=" <> threshold]),
      licence_audit.Clients(
        ..clients(),
        osv_batch_fetcher: shared_batch,
        osv_detail_fetcher: fn(id) {
          should.equal(record_detail_fetch(id), 1)
          package_severity_detail(id)
        },
      ),
    )
  should.equal(result.exit_code, 1)
  assert string.contains(result.output, "[CRITICAL]  OSV-shared  first@1.0.0")
  assert string.contains(result.output, "[LOW     ]  OSV-shared  second@1.0.0")
  assert string.contains(
    result.output,
    "1 advisory/advisories at or above "
      <> threshold
      <> " (of 1 total reported)",
  )
}

pub fn scoped_severities_preserve_alias_exceptions_and_failed_detail_priority_test() -> Nil {
  let root =
    prepare_project(
      "exceptions",
      hex_package("first", "1.0.0") <> "\n" <> hex_package("second", "1.0.0"),
    )
  let assert Ok(contents) = simplifile.read(root <> "/gleam.toml")
  let assert Ok(_) = simplifile.write(root <> "/gleam.toml", contents <> "
[[tools.licence_audit.exceptions]]
purl = \"pkg:hex/first@1.0.0\"
finding = \"advisory\"
advisory = \"CVE-alias\"
reason = \"Reviewed package occurrence\"
")
  use command <- list.each([
    ["check", "--checks=vulns"],
    ["check", "--checks=all"],
  ])
  let selected_clients =
    licence_audit.Clients(
      ..clients(),
      osv_batch_fetcher: shared_batch,
      osv_detail_fetcher: package_severity_detail,
    )
  let result = run(root, command, selected_clients)
  should.equal(result.exit_code, 0)
  assert string.contains(
    result.output,
    "[CRITICAL]  OSV-shared  first@1.0.0 [excepted #1",
  )
  assert string.contains(result.output, "[LOW     ]  OSV-shared  second@1.0.0")
  assert string.contains(
    result.output,
    "0 blocking advisory/advisories; 1 excepted finding(s) of 2 package/advisory finding(s)",
  )
  let result =
    run(
      root,
      list.append(command, ["--vuln-block-unknown"]),
      licence_audit.Clients(..selected_clients, osv_detail_fetcher: fn(_) {
        Error(osv.NetworkFailure("TLS handshake failed: unknown_ca"))
      }),
    )
  should.equal(result.exit_code, 2)
  assert !string.contains(result.output, "excepted #1")
}

pub fn transport_reasons_reach_all_consumer_diagnostics_test() -> Nil {
  let root = prepare_project("transport", hex_package("first", "1.0.0"))
  let assert Ok(req) = request.to("https://api.osv.dev/v1/querybatch")
  let failure =
    osv.from_http_error(
      request.set_method(req, http.Post),
      httpc_adaptive.FailedToConnect("TLS handshake failed: unknown_ca"),
    )
  use detail_failure <- list.each([False, True])
  use command <- list.each([
    ["vulns"],
    ["check", "--checks=vulns"],
    ["check", "--checks=all"],
    ["sbom", "--vulns"],
  ])
  let #(result, events) =
    licence_audit.run_configured(
      list.append(command, ["--manifest=" <> root <> "/manifest.toml"]),
      licence_audit.Clients(
        ..clients(),
        osv_batch_fetcher: fn(purls) {
          case detail_failure {
            True -> shared_batch(purls)
            False -> Error(failure)
          }
        },
        osv_detail_fetcher: fn(_) { Error(failure) },
      ),
      progress.capturing(progress.Normal, "test"),
    )
  let expected_exit = case detail_failure, command {
    True, ["vulns"] | True, ["sbom", ..] -> 0
    _, _ -> 2
  }
  should.equal(result.exit_code, expected_exit)
  let diagnostics =
    result.output
    <> string.join(list.map(events, fn(event) { event.message }), "\n")
  assert string.contains(
    diagnostics,
    "POST https://api.osv.dev/v1/querybatch: connection setup failed: TLS handshake failed: unknown_ca",
  )
}

pub fn sbom_ratings_use_only_queried_package_versions_test() -> Nil {
  use #(packages, expected) <- list.each([
    #(hex_package("second", "1.0.0"), [#("low", low_vector)]),
    #(hex_package("first", "2.0.0"), [#("low", low_vector)]),
    #(hex_package("first", "1.0.0") <> "\n" <> hex_package("second", "1.0.0"), [
      #("critical", critical_vector),
      #("low", low_vector),
    ]),
  ])
  let root = prepare_project("sbom-severity", packages)
  let result =
    run(
      root,
      ["sbom", "--vulns"],
      licence_audit.Clients(
        ..clients(),
        osv_batch_fetcher: shared_batch,
        osv_detail_fetcher: package_severity_detail,
      ),
    )
  should.equal(result.exit_code, 0)
  let assert Ok([ratings]) =
    json.parse(
      result.output,
      decode.at(
        ["vulnerabilities"],
        decode.list(decode.field(
          "ratings",
          decode.list({
            use severity <- decode.field("severity", decode.string)
            use vector <- decode.field("vector", decode.string)
            decode.success(#(severity, vector))
          }),
          decode.success,
        )),
      ),
    )
  should.equal(ratings, expected)
}

pub fn invalid_licence_diagnostics_keep_field_and_exact_value_test() -> Nil {
  use field <- list.each(["allow", "deny"])
  let value = "  MIT/Apache-2.0  "
  let assert Error(failure) =
    config.parse(
      "[tools.licence_audit]\n" <> field <> " = [\"" <> value <> "\"]",
    )
  let failure = error.from_config_error(failure)
  should.equal(error.exit_code(failure), 2)
  assert string.contains(error.message(failure), field)
  assert string.contains(error.message(failure), value)
}

pub fn subdirectory_commit_queries_reach_every_vulnerability_consumer_test() -> Nil {
  let packages =
    ["first", "second"]
    |> list.map(fn(name) {
      "{ name = \""
      <> name
      <> "\", version = \"1.0.0\", source = \"git\", repo = \"https://github.com/example/mono\", commit = \""
      <> commit
      <> "\", path = \"packages/"
      <> name
      <> "\" },"
    })
    |> string.join("\n")
  let root = prepare_project("subpaths", packages)
  let selected_clients =
    licence_audit.Clients(
      ..clients(),
      osv_batch_fetcher: fn(purls) {
        should.equal(purls, [
          "pkg:github/example/mono@" <> commit <> "#packages/first",
          "pkg:github/example/mono@" <> commit <> "#packages/second",
        ])
        osv.query_batch(purls, fn(request) {
          let assert Ok(commits) =
            json.parse(
              request.body,
              decode.field(
                "queries",
                decode.list(decode.field(
                  "commit",
                  decode.string,
                  decode.success,
                )),
                decode.success,
              ),
            )
          should.equal(commits, [commit, commit])
          Ok(response.Response(
            status: 200,
            headers: [],
            body: "{\"results\":[{\"vulns\":[{\"id\":\"OSV-shared\"}]},{\"vulns\":[{\"id\":\"OSV-shared\"}]}]}",
          ))
        })
      },
      osv_detail_fetcher: fn(id) {
        osv.decode_vuln_body(
          "{\"database_specific\":{\"severity\":\"HIGH\"}}",
          id,
        )
      },
    )
  use #(command, exit_code) <- list.each([
    #(["vulns"], 0),
    #(["check", "--checks=vulns"], 1),
    #(["check", "--checks=all"], 1),
    #(["sbom", "--vulns"], 0),
  ])
  let result = run(root, command, selected_clients)
  should.equal(#(result.exit_code, result.output), #(exit_code, result.output))
  assert string.contains(result.output, "OSV-shared")
  case command {
    ["sbom", ..] -> {
      let assert Ok(refs) =
        json.parse(
          result.output,
          decode.at(
            ["vulnerabilities"],
            decode.list(decode.field(
              "affects",
              decode.list(decode.field("ref", decode.string, decode.success)),
              decode.success,
            )),
          ),
        )
      should.equal(refs, [
        [
          "pkg:github/example/mono@" <> commit <> "#packages/first",
          "pkg:github/example/mono@" <> commit <> "#packages/second",
        ],
      ])
    }
    _ -> Nil
  }
}
