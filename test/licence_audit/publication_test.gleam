import gleam/dict
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import gleeunit/should
import licence_audit
import licence_audit/cache
import licence_audit/cache_dir
import licence_audit/error
import licence_audit/hex
import licence_audit/manifest
import licence_audit/notice
import licence_audit/osv
import licence_audit/progress
import licence_audit/publication
import licence_audit/sbom
import licence_audit/source_archive
import simplifile

fn fresh_root(name: String) -> String {
  let root = "build/tmp/publication-" <> name
  let _ = simplifile.delete(root)
  let assert Ok(_) = simplifile.create_directory_all(root)
  root
}

fn local(name: String, version: String) -> manifest.SbomEntry {
  manifest.SbomEntry(name, version, [], manifest.PathProvenance("local_dep"))
}

fn no_lookup(_: String, _: String) -> Result(hex.Publication, hex.Error) {
  panic as "usable cached evidence and offline runs must not query Hex"
}

pub fn positive_evidence_is_permanent_versioned_and_survives_negative_writes_test() {
  let root = fresh_root("positive")
  let entries = [local("local_dep", "1.0.0")]
  let mode = cache.Enabled(Some(root))
  should.equal(
    publication.resolve(entries, mode, False, 100, fn(name, version) {
      should.equal(#(name, version), #("local_dep", "1.0.0"))
      Ok(hex.Published)
    }).0,
    Ok(dict.from_list([#("local_dep", hex.Published)])),
  )
  let assert Ok(table) =
    cache_dir.open_table(Some(root), "publication-v1", "test")
  let assert Ok(_) =
    cache_dir.insert_at(
      table,
      "unpublished:local_dep@1.0.0",
      "unpublished",
      Some(1_000_000),
    )
  should.equal(
    publication.resolve(entries, mode, True, 1_000_000, no_lookup).0,
    Ok(dict.from_list([#("local_dep", hex.Published)])),
  )
  list.each([local("local_dep", "2.0.0"), local("other", "1.0.0")], fn(entry) {
    let assert Error(_) =
      publication.resolve([entry], mode, True, 1_000_000, no_lookup).0
  })
  let assert Ok(_) = simplifile.delete(root)
}

pub fn negative_evidence_expires_at_24_hours_without_stale_fallback_test() {
  let root = fresh_root("negative")
  let mode = cache.Enabled(Some(root))
  let entries = [local("local_dep", "1.0.0")]
  let assert Ok(_) =
    publication.resolve(entries, mode, False, 100, fn(_, _) {
      Ok(hex.Unpublished)
    }).0
  should.equal(
    publication.resolve(entries, mode, True, 86_499, no_lookup).0,
    Ok(dict.from_list([#("local_dep", hex.Unpublished)])),
  )
  let assert Error(_) =
    publication.resolve(entries, mode, True, 86_500, no_lookup).0
  let assert Error(_) =
    publication.resolve(entries, mode, False, 86_500, fn(_, _) {
      Error(hex.NetworkFailure("unavailable"))
    }).0
  let assert Error(_) =
    publication.resolve(entries, mode, True, 86_500, no_lookup).0
  should.equal(
    publication.resolve(entries, mode, False, 86_500, fn(_, _) {
      Ok(hex.Published)
    }).0,
    Ok(dict.from_list([#("local_dep", hex.Published)])),
  )
  let assert Ok(_) = simplifile.delete(root)
}

pub fn malformed_and_future_negative_evidence_are_misses_test() {
  let root = fresh_root("invalid")
  let mode = cache.Enabled(Some(root))
  let entries = [local("local_dep", "1.0.0")]
  let assert Ok(table) =
    cache_dir.open_table(Some(root), "publication-v1", "test")
  list.each(
    [
      #("unpublished", None),
      #("unpublished", Some(101)),
      #("invented", Some(100)),
    ],
    fn(example) {
      let assert Ok(_) =
        cache_dir.insert_at(
          table,
          "unpublished:local_dep@1.0.0",
          example.0,
          example.1,
        )
      let assert Error(_) =
        publication.resolve(entries, mode, True, 100, no_lookup).0
    },
  )
  let assert Ok(_) =
    cache_dir.insert(table, "published:local_dep@1.0.0", "unpublished")
  let assert Error(_) =
    publication.resolve(entries, mode, True, 100, no_lookup).0
  let assert Ok(_) = simplifile.delete(root)
}

pub fn lookup_errors_do_not_create_negative_evidence_test() {
  let root = fresh_root("errors")
  let entries = [local("local_dep", "1.0.0")]
  let mode = cache.Enabled(Some(root))
  list.each(
    [
      hex.NotFound,
      hex.RateLimited,
      hex.UnexpectedResponse(503),
      hex.InvalidJson("invalid"),
      hex.InvalidMetadata("wrong identity"),
      hex.NetworkFailure("TLS failed"),
    ],
    fn(reason) {
      let assert Error(failure) =
        publication.resolve(entries, mode, False, 100, fn(_, _) {
          Error(reason)
        }).0
      should.equal(error.exit_code(failure), 2)
      assert string.contains(error.message(failure), "local_dep@1.0.0")
      let assert Error(_) =
        publication.resolve(entries, mode, True, 100, no_lookup).0
    },
  )
  let assert Ok(_) = simplifile.delete(root)
}

pub fn no_cache_does_not_bypass_required_verification_or_delete_evidence_test() {
  let root = fresh_root("bypass")
  let entries = [local("local_dep", "1.0.0")]
  let mode = cache.Enabled(Some(root))
  let assert Ok(_) =
    publication.resolve(entries, mode, False, 100, fn(_, _) {
      Ok(hex.Published)
    }).0
  let assert Error(_) =
    publication.resolve(entries, cache.Disabled, True, 100, no_lookup).0
  let assert Error(_) =
    publication.resolve(entries, cache.Disabled, False, 100, fn(_, _) {
      Error(hex.NetworkFailure("offline"))
    }).0
  let assert Ok(_) = publication.resolve(entries, mode, True, 100, no_lookup).0
  let assert Ok(_) = simplifile.delete(root)
}

pub fn storage_failures_warn_but_live_verification_can_succeed_test() {
  let root = fresh_root("storage")
  let blocker = root <> "/file"
  let assert Ok(_) = simplifile.write(blocker, "not a directory")
  let entries = [local("local_dep", "1.0.0")]
  let mode = cache.Enabled(Some(blocker))
  let assert #(Ok(_), Some(_)) =
    publication.resolve(entries, mode, False, 100, fn(_, _) {
      Ok(hex.Published)
    })
  let assert #(Error(_), Some(_)) =
    publication.resolve(entries, mode, True, 100, no_lookup)
  let assert Ok(_) = simplifile.delete(root)
}

fn no_network_clients() -> licence_audit.Clients {
  licence_audit.Clients(
    fetcher: fn(_) { panic as "must not fetch mutable metadata" },
    publication_fetcher: no_lookup,
    osv_batch_fetcher: fn(_) { panic as "must not query OSV" },
    osv_detail_fetcher: fn(_) { panic as "must not fetch OSV details" },
    notice_clients: notice.Clients(
      fetch_hex_tarball: fn(_, _) { panic as "must not download Hex archives" },
      fetch_git_archive: fn(_, _) { panic as "must not download Git archives" },
      resolve_commit: fn(_, _) { panic as "must not resolve tags" },
      fetch_repo_archive: fn(_, _) {
        panic as "must not download repository archives"
      },
      fetch_spdx_index: fn(_) { panic as "must not fetch SPDX indexes" },
      fetch_spdx: fn(_) { panic as "must not fetch SPDX text" },
    ),
  )
}

fn online_clients(status: hex.Publication) -> licence_audit.Clients {
  let assert Ok(hex_archive) =
    simplifile.read_bits("test/fixtures/sbom_metadata/hex.tar")
  let assert Ok(git_archive) =
    simplifile.read_bits("test/fixtures/sbom_metadata/git.tar.gz")
  licence_audit.Clients(
    ..no_network_clients(),
    publication_fetcher: fn(name, version) {
      should.equal(#(name, version), #("local_dep", "1.0.0"))
      Ok(status)
    },
    notice_clients: notice.Clients(
      ..no_network_clients().notice_clients,
      fetch_hex_tarball: fn(_, _) { Ok(hex_archive) },
      fetch_git_archive: fn(_, _) { Ok(git_archive) },
      fetch_spdx: fn(_) { Ok(Some("pinned canonical licence text")) },
    ),
  )
}

fn project(name: String) -> String {
  let root = fresh_root(name)
  let assert Ok(_) = simplifile.create_directory_all(root <> "/local_dep")
  let assert Ok(_) =
    simplifile.write(
      root <> "/local_dep/gleam.toml",
      "name = \"local_dep\"\nversion = \"1.0.0\"\nlicences = [\"MIT\"]\ndescription = \"Current local metadata\"\n[dependencies]\nhex_dep = \"1.0.0\"\n",
    )
  let assert Ok(_) =
    simplifile.write(
      root <> "/gleam.toml",
      "name = \"app\"\nversion = \"1.0.0\"\n[dependencies]\nlocal_dep = { path = \"local_dep\" }\n",
    )
  let assert Ok(archive) =
    simplifile.read_bits("test/fixtures/sbom_metadata/hex.tar")
  let assert Ok(checksum) = source_archive.sha256_hex(archive)
  let assert Ok(_) =
    simplifile.write(
      root <> "/manifest.toml",
      "packages = [\n"
        <> "{ name = \"local_dep\", version = \"1.0.0\", source = \"local\", path = \"local_dep\", requirements = [\"hex_dep\"] },\n"
        <> "{ name = \"hex_dep\", version = \"1.0.0\", source = \"hex\", outer_checksum = \""
        <> checksum
        <> "\" },\n"
        <> "{ name = \"git_dep\", version = \"2.0.0\", source = \"git\", repo = \"https://github.com/example/git_dep\", commit = \"abcdef\" },\n"
        <> "]\n[requirements]\nlocal_dep = { path = \"local_dep\" }\ngit_dep = { git = \"https://github.com/example/git_dep\" }\n",
    )
  root
}

fn run(
  root: String,
  flags: List(String),
  clients: licence_audit.Clients,
) -> licence_audit.RunResult {
  let cache_flags = case list.contains(flags, "--no-cache") {
    True -> []
    False -> ["--cache-dir=" <> root <> "/cache"]
  }
  licence_audit.run_cli_configured(
    list.append(
      ["sbom", "--manifest=" <> root <> "/manifest.toml", ..flags],
      cache_flags,
    ),
    clients,
    progress.disabled(),
  ).0
}

type LocalComponent {
  LocalComponent(
    name: String,
    ref: String,
    purl: Option(String),
    properties: List(#(String, String)),
    description: String,
    hash_count: Int,
    supplier: Option(String),
    publisher: Option(String),
    urls: List(String),
  )
}

fn local_component(output: String) -> LocalComponent {
  let assert Ok(components) =
    json.parse(
      output,
      decode.at(
        ["components"],
        decode.list({
          use name <- decode.field("name", decode.string)
          use ref <- decode.field("bom-ref", decode.string)
          use purl <- decode.optional_field(
            "purl",
            None,
            decode.optional(decode.string),
          )
          use properties <- decode.optional_field(
            "properties",
            [],
            decode.list({
              use name <- decode.field("name", decode.string)
              use value <- decode.field("value", decode.string)
              decode.success(#(name, value))
            }),
          )
          use description <- decode.optional_field(
            "description",
            "",
            decode.string,
          )
          use hashes <- decode.optional_field(
            "hashes",
            [],
            decode.list(decode.dynamic),
          )
          use supplier <- decode.optional_field(
            "supplier",
            None,
            decode.optional(decode.at(["name"], decode.string)),
          )
          use publisher <- decode.optional_field(
            "publisher",
            None,
            decode.optional(decode.string),
          )
          use urls <- decode.optional_field(
            "externalReferences",
            [],
            decode.list(decode.at(["url"], decode.string)),
          )
          decode.success(LocalComponent(
            name,
            ref,
            purl,
            properties,
            description,
            list.length(hashes),
            supplier,
            publisher,
            urls,
          ))
        }),
      ),
    )
  let assert Ok(component) =
    list.find(components, fn(component) { component.name == "local_dep" })
  component
}

pub fn reproducible_online_and_offline_use_the_same_required_evidence_test() {
  let root = project("reproducible")
  let flags = ["--reproducible", "--license-text"]
  let online = run(root, flags, online_clients(hex.Published))
  should.equal(online.exit_code, 0)
  let offline = run(root, ["--offline", ..flags], no_network_clients())
  should.equal(offline, online)
  let component = local_component(online.output)
  should.equal(component.purl, Some("pkg:hex/local_dep@1.0.0"))
  assert list.contains(component.properties, #("licence_audit:source", "local"))
  should.equal(component.description, "Current local metadata")
  should.equal(component.hash_count, 0)
  should.equal(component.supplier, None)
  should.equal(component.publisher, None)
  assert !list.any(component.urls, fn(url) { string.contains(url, "tarballs") })
  let assert Ok(ref) = sbom.component_ref(local("local_dep", "1.0.0"))
  should.equal(component.ref, ref)
  let assert Ok(_) =
    simplifile.write(root <> "/local_dep/source.gleam", "// changed source\n")
  should.equal(run(root, ["--offline", ..flags], no_network_clients()), online)
  let assert Ok(_) = simplifile.delete(root)
}

pub fn expired_unpublished_evidence_can_add_a_purl_without_changing_local_identity_test() {
  let root = project("becomes-published")
  let flags = ["--reproducible"]
  let unpublished = run(root, flags, online_clients(hex.Unpublished))
  should.equal(unpublished.exit_code, 0)
  should.equal(local_component(unpublished.output).purl, None)
  should.equal(
    run(root, ["--offline", ..flags], no_network_clients()),
    unpublished,
  )
  let assert Ok(table) =
    cache_dir.open_table(Some(root <> "/cache"), "publication-v1", "test")
  let assert Ok(_) =
    cache_dir.insert_at(
      table,
      "unpublished:local_dep@1.0.0",
      "unpublished",
      Some(0),
    )
  let output = root <> "/previous.json"
  let assert Ok(_) = simplifile.write(output, "previous output")
  let expired =
    run(
      root,
      ["--offline", "--output=" <> output, ..flags],
      no_network_clients(),
    )
  should.equal(expired.exit_code, 2)
  assert string.contains(expired.output, "verification")
  should.equal(simplifile.read(output), Ok("previous output"))
  let published = run(root, flags, online_clients(hex.Published))
  should.equal(published.exit_code, 0)
  assert published.output != unpublished.output
  should.equal(
    local_component(published.output).purl,
    Some("pkg:hex/local_dep@1.0.0"),
  )
  let assert Ok(ref) = sbom.component_ref(local("local_dep", "1.0.0"))
  should.equal(local_component(unpublished.output).ref, ref)
  should.equal(local_component(published.output).ref, ref)
  let assert Ok(_) = simplifile.delete(root)
}

pub fn offline_missing_required_evidence_and_no_cache_fail_without_output_writes_test() {
  let root = project("offline-missing")
  let output = root <> "/previous.json"
  let assert Ok(_) = simplifile.write(output, "previous output")
  let flags = [
    "--offline",
    "--reproducible",
    "--license-text",
    "--output=" <> output,
  ]
  let missing_publication = run(root, flags, no_network_clients())
  should.equal(missing_publication.exit_code, 2)
  assert string.contains(missing_publication.output, "publication")
  let warm =
    run(
      root,
      ["--reproducible", "--license-text"],
      online_clients(hex.Published),
    )
  should.equal(warm.exit_code, 0)
  let bypassed = run(root, ["--no-cache", ..flags], no_network_clients())
  should.equal(bypassed.exit_code, 2)
  assert string.contains(bypassed.output, "Failed to verify Hex publication")
  assert string.contains(bypassed.output, "offline: usable cached verification")
  should.equal(simplifile.read(output), Ok("previous output"))
  let assert Ok(_) = simplifile.delete(root <> "/cache/spdx-v1")
  let missing_text = run(root, flags, no_network_clients())
  should.equal(missing_text.exit_code, 2)
  assert string.contains(
    missing_text.output,
    "offline: required pinned SPDX text",
  )
  let assert Ok(_) = simplifile.delete(root <> "/cache/hex-v2")
  let missing_metadata = run(root, flags, no_network_clients())
  should.equal(missing_metadata.exit_code, 2)
  assert string.contains(
    missing_metadata.output,
    "offline: required locked metadata",
  )
  should.equal(simplifile.read(output), Ok("previous output"))
  let assert Ok(_) = simplifile.delete(root)
}

pub fn default_offline_reads_optional_cached_metadata_without_requiring_it_test() {
  let root = project("optional")
  let online =
    run(
      root,
      [],
      licence_audit.Clients(..online_clients(hex.Published), fetcher: fn(_) {
        Ok(hex.PackageMetadata(
          licences: ["Apache-2.0"],
          description: Some("Cached optional Hex metadata"),
          links: [],
          publisher: None,
        ))
      }),
    )
  should.equal(online.exit_code, 0)
  let offline = run(root, ["--offline"], no_network_clients())
  should.equal(offline.exit_code, 0)
  assert string.contains(offline.output, "Cached optional Hex metadata")
  let assert Ok(_) = simplifile.delete(root <> "/cache/hex-v2")
  let without_optional = run(root, ["--offline"], no_network_clients())
  should.equal(without_optional.exit_code, 0)
  assert !string.contains(
    without_optional.output,
    "Cached optional Hex metadata",
  )
  should.equal(
    local_component(without_optional.output).purl,
    Some("pkg:hex/local_dep@1.0.0"),
  )
  let assert Ok(_) = simplifile.delete(root)
}

pub fn sbom_vulnerabilities_reference_the_local_component_not_its_published_purl_test() {
  let root = project("vuln-identity")
  let clients =
    licence_audit.Clients(
      ..online_clients(hex.Published),
      fetcher: fn(_) { Ok(hex.licences_only(["Apache-2.0"])) },
      osv_batch_fetcher: fn(purls) {
        should.equal(purls, [
          "pkg:hex/local_dep@1.0.0",
          "pkg:hex/hex_dep@1.0.0",
          "pkg:github/example/git_dep@abcdef",
        ])
        Ok(
          list.map(purls, fn(purl) {
            osv.BatchEntry(purl, case purl {
              "pkg:hex/local_dep@1.0.0" -> ["CVE-LOCAL"]
              _ -> []
            })
          }),
        )
      },
      osv_detail_fetcher: fn(_) {
        Ok(
          osv.Vulnerability(
            "CVE-LOCAL",
            [],
            "Published identity advisory",
            osv.High,
            [],
          ),
        )
      },
    )
  let result = run(root, ["--vulns"], clients)
  should.equal(result.exit_code, 0)
  let assert Ok(ref) = sbom.component_ref(local("local_dep", "1.0.0"))
  let assert Ok(affects) =
    json.parse(
      result.output,
      decode.at(
        ["vulnerabilities"],
        decode.list(decode.at(
          ["affects"],
          decode.list(decode.at(["ref"], decode.string)),
        )),
      ),
    )
  should.equal(affects, [[ref]])
  let assert Ok(_) = simplifile.delete(root)
}
