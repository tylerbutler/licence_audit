import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleeunit/should
import licence_audit
import licence_audit/cli
import licence_audit/color
import licence_audit/error
import licence_audit/hex
import licence_audit/network
import licence_audit/notice
import licence_audit/osv
import licence_audit/progress
import licence_audit/sbom_command
import licence_audit/source_archive
import simplifile

fn no_network_clients() -> notice.Clients {
  notice.Clients(
    fetch_hex_tarball: fn(_, _) { panic as "Unexpected Hex archive request" },
    fetch_git_archive: fn(_, _) { panic as "Unexpected Git archive request" },
    resolve_commit: fn(_, _) { panic as "Unexpected repository request" },
    fetch_repo_archive: fn(_, _) { panic as "Unexpected repository archive" },
    fetch_spdx_index: fn(_) { panic as "Unexpected SPDX index request" },
    fetch_spdx: fn(_) { panic as "Unexpected SPDX request" },
  )
}

fn project(name: String, checksum: String) -> cli.SbomOptions {
  let root = "build/sbom-command-test/" <> name
  let assert Ok(_) = simplifile.create_directory_all(root)
  let assert Ok(_) =
    simplifile.write(
      "name = \"fixture\"\nversion = \"1.0.0\"\n[dependencies]\nhex_dep = \"1.0.0\"\n[dev-dependencies]\ndev_dep = \"1.0.0\"",
      to: root <> "/gleam.toml",
    )
  let assert Ok(_) = simplifile.write("packages = [
  { name = \"hex_dep\", version = \"1.0.0\", source = \"hex\", outer_checksum = \"" <> checksum <> "\" },
  { name = \"dev_dep\", version = \"1.0.0\", source = \"hex\", outer_checksum = \"" <> checksum <> "\" },
]
[requirements]
hex_dep = \"1.0.0\"
dev_dep = \"1.0.0\"
", to: root <> "/manifest.toml")
  cli.SbomOptions(
    manifest_path: Some(root),
    verbosity: progress.Verbose,
    color: color.Never,
    no_cache: True,
    cache_dir: None,
    output: None,
    offline: False,
    reproducible: True,
    with_vulns: False,
    format: cli.CyclonedxJson,
    license_text: False,
  )
}

pub fn reproducible_document_and_write_preserve_locked_metadata_and_scopes_test() -> Nil {
  let assert Ok(archive) =
    simplifile.read_bits("test/fixtures/sbom_metadata/hex.tar")
  let assert Ok(checksum) = source_archive.sha256_hex(archive)
  let options = project("document", checksum)
  let clients =
    notice.Clients(..no_network_clients(), fetch_hex_tarball: fn(_, version) {
      should.equal(version, "1.0.0")
      Ok(archive)
    })
  let metadata_fetcher = fn(_) { panic as "Must use locked metadata" }
  let publication_fetcher = fn(_, _) { panic as "No local publications" }
  let batch_fetcher = fn(_) { panic as "Vulnerabilities disabled" }
  let advisory_fetcher = fn(_, _) { panic as "Vulnerabilities disabled" }
  let reporter = progress.capturing(progress.Verbose, "sbom")
  let #(result, domain_reporter) =
    network.with_command(fn() {
      sbom_command.run(
        options,
        metadata_fetcher,
        publication_fetcher,
        batch_fetcher,
        advisory_fetcher,
        clients,
        reporter,
      )
    })
  let assert Ok(text) = result
  let specification = {
    use value <- decode.field("specVersion", decode.string)
    decode.success(value)
  }
  should.equal(json.parse(text, specification), Ok("1.6"))
  let component_scope = {
    use name <- decode.field("name", decode.string)
    use scope <- decode.field("scope", decode.string)
    decode.success(#(name, scope))
  }
  let components = {
    use value <- decode.field("components", decode.list(component_scope))
    decode.success(value)
  }
  should.equal(
    json.parse(text, components),
    Ok([#("dev_dep", "optional"), #("hex_dep", "required")]),
  )
  assert string.contains(text, "Metadata from the locked Hex archive")
  let #(root_result, root_events) =
    licence_audit.run_configured(
      ["sbom", "--reproducible", "--manifest=build/sbom-command-test/document"],
      licence_audit.Clients(
        ..licence_audit.default_clients(),
        fetcher: metadata_fetcher,
        publication_fetcher: publication_fetcher,
        osv_batch_fetcher: batch_fetcher,
        notice_clients: clients,
      ),
      reporter,
    )
  should.equal(root_result.exit_code, 0)
  should.equal(root_result.output, text)
  should.equal(root_events, progress.events(domain_reporter))
  let output = "build/sbom-command-test/document/sbom.json"
  let #(written, _) =
    network.with_command(fn() {
      sbom_command.run(
        cli.SbomOptions(..options, output: Some(output)),
        metadata_fetcher,
        publication_fetcher,
        batch_fetcher,
        advisory_fetcher,
        clients,
        reporter,
      )
    })
  should.equal(written, Ok(""))
  should.equal(simplifile.read(output), Ok(text))
}

pub fn spdx_reproducible_document_and_write_use_locked_metadata_test() -> Nil {
  let assert Ok(archive) =
    simplifile.read_bits("test/fixtures/sbom_metadata/hex.tar")
  let assert Ok(checksum) = source_archive.sha256_hex(archive)
  let options =
    cli.SbomOptions(..project("spdx-document", checksum), format: cli.SpdxJson)
  let clients =
    notice.Clients(..no_network_clients(), fetch_hex_tarball: fn(_, version) {
      should.equal(version, "1.0.0")
      Ok(archive)
    })
  let metadata_fetcher = fn(_) { panic as "Must use locked metadata" }
  let publication_fetcher = fn(_, _) { panic as "No local publications" }
  let batch_fetcher = fn(_) { panic as "SPDX does not fetch advisories" }
  let advisory_fetcher = fn(_, _) { panic as "SPDX does not fetch advisories" }
  let reporter = progress.capturing(progress.Verbose, "sbom")
  let #(result, domain_reporter) =
    network.with_command(fn() {
      sbom_command.run(
        options,
        metadata_fetcher,
        publication_fetcher,
        batch_fetcher,
        advisory_fetcher,
        clients,
        reporter,
      )
    })
  let assert Ok(text) = result
  let version = {
    use value <- decode.field("spdxVersion", decode.string)
    decode.success(value)
  }
  let names = {
    use value <- decode.field(
      "packages",
      decode.list({
        use name <- decode.field("name", decode.string)
        decode.success(name)
      }),
    )
    decode.success(value)
  }
  should.equal(json.parse(text, version), Ok("SPDX-2.3"))
  should.equal(json.parse(text, names), Ok(["fixture", "dev_dep", "hex_dep"]))
  let #(root_result, root_events) =
    licence_audit.run_configured(
      [
        "sbom",
        "--format=spdx-json",
        "--reproducible",
        "--manifest=build/sbom-command-test/spdx-document",
      ],
      licence_audit.Clients(
        ..licence_audit.default_clients(),
        fetcher: metadata_fetcher,
        publication_fetcher: publication_fetcher,
        osv_batch_fetcher: batch_fetcher,
        notice_clients: clients,
      ),
      reporter,
    )
  should.equal(root_result.exit_code, 0)
  should.equal(root_result.output, text)
  should.equal(root_events, progress.events(domain_reporter))
  let output = "build/sbom-command-test/spdx-document/sbom.json"
  let #(written, _) =
    network.with_command(fn() {
      sbom_command.run(
        cli.SbomOptions(..options, output: Some(output)),
        metadata_fetcher,
        publication_fetcher,
        batch_fetcher,
        advisory_fetcher,
        clients,
        reporter,
      )
    })
  should.equal(written, Ok(""))
  should.equal(simplifile.read(output), Ok(text))
}

pub fn unsupported_source_is_explicit_and_preserves_output_file_test() -> Nil {
  let options = project("unsupported", string.repeat("a", 64))
  let root = "build/sbom-command-test/unsupported"
  let assert Ok(_) =
    simplifile.write(
      "packages = [{ name = \"other\", version = \"1.0.0\", source = \"other\" }]",
      to: root <> "/manifest.toml",
    )
  let output = root <> "/sbom.json"
  let assert Ok(_) = simplifile.write("previous output", to: output)
  let #(result, _) =
    network.with_command(fn() {
      sbom_command.run(
        cli.SbomOptions(..options, output: Some(output)),
        fn(_) { panic as "Unsupported source has no Hex metadata" },
        fn(_, _) { panic as "Unsupported source has no local publication" },
        fn(_) { panic as "Vulnerabilities disabled" },
        fn(_, _) { panic as "Vulnerabilities disabled" },
        no_network_clients(),
        progress.disabled(),
      )
    })
  let assert Error(error.UnsupportedSourceForSbom(package, source, _)) = result
  should.equal(package, "other")
  should.equal(source, "other")
  should.equal(simplifile.read(output), Ok("previous output"))
}

pub fn empty_advisory_ids_do_not_fetch_details_test() -> Nil {
  let options = project("empty-advisories", string.repeat("a", 64))
  let #(result, _) =
    network.with_command(fn() {
      sbom_command.run(
        cli.SbomOptions(..options, reproducible: False, with_vulns: True),
        fn(_) { Ok(hex.licences_only(["MIT"])) },
        fn(_, _) { panic as "No local publications" },
        fn(purls) {
          should.equal(list.length(purls), 2)
          Ok(list.map(purls, fn(purl) { osv.BatchEntry(purl, []) }))
        },
        fn(_, _) { panic as "Empty advisory IDs must not fetch details" },
        no_network_clients(),
        progress.disabled(),
      )
    })
  let assert Ok(text) = result
  assert !string.contains(text, "\"vulnerabilities\"")
}

pub fn embedded_advisories_deduplicate_ids_and_preserve_component_references_test() -> Nil {
  let options = project("embedded", string.repeat("a", 64))
  let #(result, _) =
    network.with_command(fn() {
      sbom_command.run(
        cli.SbomOptions(..options, reproducible: False, with_vulns: True),
        fn(_) { Ok(hex.licences_only(["MIT"])) },
        fn(_, _) { panic as "No local publications" },
        fn(purls) {
          Ok(
            list.map(purls, fn(purl) {
              osv.BatchEntry(purl, ["CVE-2024-0001", "CVE-2024-0001"])
            }),
          )
        },
        fn(ids, reporter) {
          should.equal(ids, ["CVE-2024-0001"])
          #(
            Ok([
              osv.Vulnerability(
                id: "CVE-2024-0001",
                aliases: [],
                summary: "Example advisory",
                severity: osv.High,
                scores: [],
                affected: [],
              ),
            ]),
            reporter,
          )
        },
        no_network_clients(),
        progress.disabled(),
      )
    })
  let assert Ok(text) = result
  let reference = {
    use value <- decode.field("ref", decode.string)
    decode.success(value)
  }
  let references = {
    use value <- decode.field("affects", decode.list(reference))
    decode.success(value)
  }
  let vulnerabilities = {
    use value <- decode.field("vulnerabilities", decode.list(references))
    decode.success(value)
  }
  should.equal(
    json.parse(text, vulnerabilities),
    Ok([["pkg:hex/dev_dep@1.0.0", "pkg:hex/hex_dep@1.0.0"]]),
  )
}
