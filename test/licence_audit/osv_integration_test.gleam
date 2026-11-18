import gleam/dynamic/decode
import gleam/http
import gleam/http/request
import gleam/http/response
import gleam/json
import gleam/list
import gleam/string
import gleeunit/should
import licence_audit
import licence_audit/config
import licence_audit/error
import licence_audit/hex
import licence_audit/httpc_adaptive
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
