import gleam/dict
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleeunit/should
import licence_audit
import licence_audit/error
import licence_audit/hex
import licence_audit/manifest
import licence_audit/notice
import licence_audit/progress
import licence_audit/sbom
import licence_audit/sbom_spdx
import simplifile

fn fixture() -> sbom.SbomInput {
  sbom.SbomInput(
    manifest: manifest.SbomManifest(
      entries: [
        manifest.SbomEntry(
          name: "a_b",
          version: "1.0.0",
          requirements: ["a-b", "a-b"],
          provenance: manifest.HexProvenance(
            string.repeat("A", 64),
            Some(string.repeat("B", 64)),
          ),
        ),
        manifest.SbomEntry(
          name: "a-b",
          version: "",
          requirements: [],
          provenance: manifest.GitProvenance(
            "https://github.com/example/example.git",
            string.repeat("c", 40),
            None,
          ),
        ),
        manifest.SbomEntry(
          name: "unknown",
          version: "2.0.0",
          requirements: [],
          provenance: manifest.HexProvenance(string.repeat("d", 64), None),
        ),
      ],
      root_requirements: ["unknown", "a_b"],
    ),
    root: sbom.RootComponent(
      name: "example",
      version: "1.0.0",
      description: None,
      licences: ["LicenseRef-Private \"custom\""],
      repository: None,
    ),
    tool_version: "0.13.1",
    timestamp: "1970-01-01T00:00:00Z",
    serial_number: sbom.ContentDerivedSerial,
    package_metadata: dict.from_list([
      #(
        "a_b",
        hex.PackageMetadata(
          licences: ["mit"],
          description: None,
          links: [],
          publisher: None,
        ),
      ),
      #(
        "a-b",
        hex.PackageMetadata(
          licences: ["MIT", "Apache-2.0"],
          description: None,
          links: [],
          publisher: None,
        ),
      ),
    ]),
    publications: dict.new(),
    scopes: dict.new(),
    vulnerabilities: [],
    license_texts: dict.new(),
  )
}

fn package_decoder() -> decode.Decoder(#(String, String, String)) {
  use name <- decode.field("name", decode.string)
  use id <- decode.field("SPDXID", decode.string)
  use licence <- decode.field("licenseDeclared", decode.string)
  decode.success(#(name, id, licence))
}

fn relationship_decoder() -> decode.Decoder(#(String, String, String)) {
  use from <- decode.field("spdxElementId", decode.string)
  use kind <- decode.field("relationshipType", decode.string)
  use to <- decode.field("relatedSpdxElement", decode.string)
  decode.success(#(from, kind, to))
}

pub fn renders_resolved_graph_and_conservative_licences_test() {
  let assert Ok(document) = sbom_spdx.try_render(fixture())
  let assert Ok(packages) =
    json.parse(
      document,
      decode.at(["packages"], decode.list(package_decoder())),
    )
  packages
  |> should.equal([
    #("example", "SPDXRef-Root", "NOASSERTION"),
    #("a-b", "SPDXRef-Package-612D62", "NOASSERTION"),
    #("a_b", "SPDXRef-Package-615F62", "MIT"),
    #("unknown", "SPDXRef-Package-756E6B6E6F776E", "NOASSERTION"),
  ])
  let assert Ok(relationships) =
    json.parse(
      document,
      decode.at(["relationships"], decode.list(relationship_decoder())),
    )
  relationships
  |> should.equal([
    #("SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-Root"),
    #("SPDXRef-Root", "DEPENDS_ON", "SPDXRef-Package-615F62"),
    #("SPDXRef-Root", "DEPENDS_ON", "SPDXRef-Package-756E6B6E6F776E"),
    #("SPDXRef-Package-615F62", "DEPENDS_ON", "SPDXRef-Package-612D62"),
  ])
  // The external schema/semantic check consumes this mixed-source fixture.
  simplifile.write("build/spdx-test.json", document) |> should.be_ok
}

pub fn output_is_stable_under_manifest_and_requirement_reordering_test() {
  let input = fixture()
  let reordered =
    sbom.SbomInput(
      ..input,
      manifest: manifest.SbomManifest(
        entries: list.reverse(input.manifest.entries),
        root_requirements: list.reverse(input.manifest.root_requirements),
      ),
    )
  sbom_spdx.try_render(input) |> should.equal(sbom_spdx.try_render(reordered))
  let changed = sbom.SbomInput(..input, tool_version: "0.13.2")
  let namespace_decoder = decode.at(["documentNamespace"], decode.string)
  let assert Ok(first) = sbom_spdx.try_render(input)
  let assert Ok(second) = sbom_spdx.try_render(changed)
  json.parse(first, namespace_decoder)
  |> should.not_equal(json.parse(second, namespace_decoder))
}

pub fn checksums_use_only_outer_hash_and_lowercase_test() {
  let assert Ok(document) = sbom_spdx.try_render(fixture())
  let decoder = {
    use packages <- decode.field(
      "packages",
      decode.list({
        use name <- decode.field("name", decode.string)
        use checksums <- decode.optional_field(
          "checksums",
          [],
          decode.list(decode.at(["checksumValue"], decode.string)),
        )
        decode.success(#(name, checksums))
      }),
    )
    decode.success(packages)
  }
  let assert Ok(packages) = json.parse(document, decoder)
  packages
  |> should.equal([
    #("example", []),
    #("a-b", []),
    #("a_b", [string.repeat("a", 64)]),
    #("unknown", [string.repeat("d", 64)]),
  ])
}

pub fn rejects_invalid_checksum_and_unsupported_source_test() {
  let input = fixture()
  let assert [entry, ..] = input.manifest.entries
  list.each(["DEADBEEF", string.repeat("g", 64)], fn(checksum) {
    let invalid =
      manifest.SbomEntry(
        ..entry,
        requirements: [],
        provenance: manifest.HexProvenance(checksum, None),
      )
    let changed =
      sbom.SbomInput(
        ..input,
        manifest: manifest.SbomManifest(
          entries: [invalid],
          root_requirements: [],
        ),
      )
    sbom_spdx.try_render(changed)
    |> should.equal(
      Error(error.Input("Invalid locked SHA-256 checksum for a_b")),
    )
  })
  list.each(
    [
      manifest.UnknownProvenance("unsupported"),
      manifest.GitProvenance("https://gitlab.com/example/repo", "abcdef", None),
    ],
    fn(provenance) {
      let changed =
        sbom.SbomInput(
          ..input,
          manifest: manifest.SbomManifest(
            entries: [
              manifest.SbomEntry(
                ..entry,
                requirements: [],
                provenance: provenance,
              ),
            ],
            root_requirements: [],
          ),
        )
      let assert Error(error.UnsupportedSourceForSbom(..)) =
        sbom_spdx.try_render(changed)
    },
  )
}

pub fn rejects_duplicate_locked_names_test() {
  let input = fixture()
  let assert [entry, ..] = input.manifest.entries
  let changed =
    sbom.SbomInput(
      ..input,
      manifest: manifest.SbomManifest(
        entries: [
          manifest.SbomEntry(..entry, requirements: []),
          manifest.SbomEntry(..entry, requirements: [], version: "2.0.0"),
        ],
        root_requirements: [],
      ),
    )
  let assert Error(error.Input(_)) = sbom_spdx.try_render(changed)
}

pub fn git_package_subpaths_use_the_shared_purl_rules_test() {
  let input = fixture()
  let entry =
    manifest.SbomEntry(
      "nested",
      "1.0.0",
      [],
      manifest.GitProvenance(
        "https://github.com/Example/Repo.git",
        "abcdef",
        Some("packages/nested dir"),
      ),
    )
  let assert Ok(document) =
    sbom_spdx.try_render(
      sbom.SbomInput(
        ..input,
        manifest: manifest.SbomManifest([entry], ["nested"]),
      ),
    )
  let assert Ok([_, refs]) =
    json.parse(
      document,
      decode.at(
        ["packages"],
        decode.list({
          use refs <- decode.optional_field(
            "externalRefs",
            [],
            decode.list(decode.at(["referenceLocator"], decode.string)),
          )
          decode.success(refs)
        }),
      ),
    )
  should.equal(refs, ["pkg:github/example/repo@abcdef#packages/nested%20dir"])
}

pub fn rejects_missing_dependency_targets_test() {
  let input = fixture()
  let assert [entry, ..] = input.manifest.entries
  use requirements <- list.each([[], ["missing"]])
  let changed =
    sbom.SbomInput(
      ..input,
      manifest: manifest.SbomManifest(
        entries: [manifest.SbomEntry(..entry, requirements: requirements)],
        root_requirements: case requirements {
          [] -> ["missing"]
          _ -> []
        },
      ),
    )
  let assert Error(error.Input(_)) = sbom_spdx.try_render(changed)
}

pub fn local_publication_does_not_invent_source_evidence_test() {
  let input = fixture()
  let entry =
    manifest.SbomEntry(
      "local_dep",
      "1.0.0",
      [],
      manifest.PathProvenance("../dep"),
    )
  let input =
    sbom.SbomInput(
      ..input,
      manifest: manifest.SbomManifest([entry], ["local_dep"]),
    )
  let assert Error(error.SbomPublicationFailed(..)) =
    sbom_spdx.try_render(input)
  use publication <- list.each([hex.Published, hex.Unpublished])
  let assert Ok(document) =
    sbom_spdx.try_render(
      sbom.SbomInput(
        ..input,
        publications: dict.from_list([#("local_dep", publication)]),
      ),
    )
  let decoder =
    decode.at(
      ["packages"],
      decode.list({
        use name <- decode.field("name", decode.string)
        use location <- decode.field("downloadLocation", decode.string)
        use hashes <- decode.optional_field(
          "checksums",
          [],
          decode.list(decode.string),
        )
        use refs <- decode.optional_field(
          "externalRefs",
          [],
          decode.list(decode.at(["referenceLocator"], decode.string)),
        )
        use comment <- decode.optional_field("comment", "", decode.string)
        decode.success(#(name, location, hashes, refs, comment))
      }),
    )
  let assert Ok([_, local]) = json.parse(document, decoder)
  should.equal(local.1, "NOASSERTION")
  should.equal(local.2, [])
  should.equal(local.3, case publication {
    hex.Published -> ["pkg:hex/local_dep@1.0.0"]
    hex.Unpublished -> []
  })
  assert string.contains(local.4, "../dep")
  assert string.contains(local.4, "does not verify local source")
}

pub fn repeated_and_raw_declarations_remain_unresolved_test() {
  let input = fixture()
  use licences <- list.each([
    ["MIT", "mit"],
    ["MIT", "MIT"],
    [" MIT "],
    ["MIT OR Apache-2.0"],
    ["LicenseRef-Private"],
  ])
  let assert Ok(document) =
    sbom_spdx.try_render(
      sbom.SbomInput(
        ..input,
        root: sbom.RootComponent(..input.root, licences: licences),
      ),
    )
  let assert Ok([root, ..]) =
    json.parse(
      document,
      decode.at(
        ["packages"],
        decode.list({
          use declared <- decode.field("licenseDeclared", decode.string)
          use comment <- decode.optional_field(
            "licenseComments",
            "",
            decode.string,
          )
          decode.success(#(declared, comment))
        }),
      ),
    )
  should.equal(root.0, "NOASSERTION")
  assert string.contains(
    root.1,
    json.to_string(json.array(list.sort(licences, string.compare), json.string)),
  )
}

pub fn empty_manifest_is_a_valid_root_document_test() {
  let input =
    sbom.SbomInput(
      ..fixture(),
      manifest: manifest.SbomManifest(entries: [], root_requirements: []),
    )
  let assert Ok(document) = sbom_spdx.try_render(input)
  simplifile.write("build/spdx-empty-test.json", document) |> should.be_ok
}

pub fn spdx_licences_are_not_limited_to_the_cyclonedx_schema_test() {
  let input = fixture()
  let assert Ok(document) =
    sbom_spdx.try_render(
      sbom.SbomInput(
        ..input,
        root: sbom.RootComponent(..input.root, licences: ["mvt-1.1"]),
      ),
    )
  let assert Ok(packages) =
    json.parse(
      document,
      decode.at(["packages"], decode.list(package_decoder())),
    )
  let assert [#(_, _, licence), ..] = packages
  licence |> should.equal("MVT-1.1")
  sbom.license_entries(["mvt-1.1"])
  |> should.equal([sbom.LicenseName("mvt-1.1")])
}

fn forbid_network() -> a {
  panic as "Offline SBOM generation must not call a network client"
}

fn no_network_clients() -> licence_audit.Clients {
  licence_audit.Clients(
    fetcher: fn(_) { forbid_network() },
    publication_fetcher: fn(_, _) { forbid_network() },
    osv_batch_fetcher: fn(_) { forbid_network() },
    osv_detail_fetcher: fn(_) { forbid_network() },
    notice_clients: notice.Clients(
      fetch_hex_tarball: fn(_, _) { forbid_network() },
      fetch_git_archive: fn(_, _) { forbid_network() },
      resolve_commit: fn(_, _) { forbid_network() },
      fetch_repo_archive: fn(_, _) { forbid_network() },
      fetch_spdx_index: fn(_) { forbid_network() },
      fetch_spdx: fn(_) { forbid_network() },
    ),
  )
}

fn offline_git_result(reproducible: Bool) -> licence_audit.RunResult {
  let root = "build/spdx-offline-project"
  let local_git = root <> "/build/packages/git_dep"
  let assert Ok(Nil) = simplifile.create_directory_all(local_git)
  let assert Ok(Nil) =
    simplifile.write(
      root <> "/gleam.toml",
      "name = \"offline_fixture\"\nversion = \"1.0.0\"\nlicences = [\"Apache-2.0\"]\n",
    )
  let assert Ok(Nil) =
    simplifile.write(
      local_git <> "/gleam.toml",
      "name = \"git_dep\"\nlicences = [\"MIT\"]\n",
    )
  let manifest_path = root <> "/manifest.toml"
  let assert Ok(Nil) = simplifile.write(manifest_path, "packages = [
  { name = \"git_dep\", version = \"1.0.0\", source = \"git\", repo = \"https://github.com/example/git_dep\", commit = \"abcdef\" },
  { name = \"hex_dep\", version = \"1.0.0\", source = \"hex\", outer_checksum = \"" <> string.repeat(
      "a",
      64,
    ) <> "\" },
]
[requirements]
git_dep = { git = \"https://github.com/example/git_dep\" }
hex_dep = \"1.0.0\"
")
  let extra_args = case reproducible {
    True -> ["--reproducible"]
    False -> []
  }
  licence_audit.run_configured(
    [
      "sbom",
      "--format=spdx-json",
      "--manifest=" <> manifest_path,
      "--offline",
      ..extra_args
    ],
    no_network_clients(),
    progress.disabled(),
  ).0
}

pub fn offline_uses_local_git_licences_without_network_test() {
  let result = offline_git_result(False)
  result.exit_code |> should.equal(0)
  let assert Ok(packages) =
    json.parse(
      result.output,
      decode.at(["packages"], decode.list(package_decoder())),
    )
  list.map(packages, fn(package) { #(package.0, package.2) })
  |> should.equal([
    #("offline_fixture", "Apache-2.0"),
    #("git_dep", "MIT"),
    #("hex_dep", "NOASSERTION"),
  ])
}

pub fn offline_reproducible_requires_locked_metadata_without_network_test() {
  let result = offline_git_result(True)
  result.exit_code |> should.equal(2)
  assert string.contains(result.output, "required locked metadata")
}

pub fn local_offline_reproducible_reuses_publication_and_reads_current_metadata_test() {
  let root = "build/spdx-local-project"
  let assert Ok(_) = simplifile.create_directory_all(root <> "/local_dep")
  let assert Ok(_) =
    simplifile.write(
      root <> "/gleam.toml",
      "name = \"local_fixture\"\nversion = \"1.0.0\"\n[dependencies]\nlocal_dep = { path = \"local_dep\" }\n",
    )
  let assert Ok(_) =
    simplifile.write(
      root <> "/local_dep/gleam.toml",
      "name = \"local_dep\"\nversion = \"1.0.0\"\nlicences = [\"MIT\"]\n",
    )
  let assert Ok(_) =
    simplifile.write(
      root <> "/manifest.toml",
      "packages = [{ name = \"local_dep\", version = \"1.0.0\", source = \"local\", path = \"local_dep\", requirements = [] }]\n[requirements]\nlocal_dep = { path = \"local_dep\" }\n",
    )
  let args = [
    "sbom",
    "--format=spdx-json",
    "--manifest=" <> root <> "/manifest.toml",
    "--cache-dir=" <> root <> "/cache",
    "--reproducible",
  ]
  let clients = no_network_clients()
  let online =
    licence_audit.run_cli_configured(
      args,
      licence_audit.Clients(..clients, publication_fetcher: fn(name, version) {
        should.equal(#(name, version), #("local_dep", "1.0.0"))
        Ok(hex.Published)
      }),
      progress.disabled(),
    ).0
  should.equal(online.exit_code, 0)
  let offline =
    licence_audit.run_cli_configured(
      ["--offline", ..args],
      clients,
      progress.disabled(),
    ).0
  should.equal(offline, online)
  simplifile.write("build/spdx-local-test.json", offline.output) |> should.be_ok
  let assert Ok(_) =
    simplifile.write(
      root <> "/local_dep/gleam.toml",
      "name = \"local_dep\"\nversion = \"1.0.0\"\nlicences = [\"Apache-2.0\"]\n",
    )
  let changed =
    licence_audit.run_cli_configured(
      ["--offline", ..args],
      clients,
      progress.disabled(),
    ).0
  should.equal(changed.exit_code, 0)
  should.not_equal(changed.output, offline.output)
  let no_cache =
    licence_audit.run_configured(
      list.filter(["--offline", ..args], fn(arg) {
        !string.starts_with(arg, "--cache-dir=")
      }),
      clients,
      progress.disabled(),
    ).0
  should.equal(no_cache.exit_code, 2)
  assert string.contains(no_cache.output, "cached verification")
}

pub fn incompatible_spdx_flags_fail_before_clients_or_output_test() {
  let output = "build/spdx-usage-output.json"
  use flags <- list.each([
    ["--vulns"],
    ["--license-text"],
    ["--licence-text", "--offline"],
    ["--license-text", "--reproducible"],
  ])
  let assert Ok(_) = simplifile.write(output, "previous output")
  let result =
    licence_audit.run_configured(
      [
        "sbom",
        "--format=spdx-json",
        "--manifest=build/nonexistent-spdx-manifest.toml",
        "--output=" <> output,
        ..flags
      ],
      no_network_clients(),
      progress.disabled(),
    ).0
  should.equal(result.exit_code, 2)
  assert string.contains(result.output, "cyclonedx-json")
  should.equal(simplifile.read(output), Ok("previous output"))
}
