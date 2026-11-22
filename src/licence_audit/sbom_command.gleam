import gleam/bit_array
import gleam/bool
import gleam/dict
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/time/timestamp
import licence_audit/cache
import licence_audit/cache_dir
import licence_audit/cli
import licence_audit/error
import licence_audit/gleam_toml
import licence_audit/hex
import licence_audit/manifest
import licence_audit/network
import licence_audit/notice
import licence_audit/notice_cache
import licence_audit/notice_resolve
import licence_audit/osv
import licence_audit/path
import licence_audit/progress
import licence_audit/publication
import licence_audit/repository
import licence_audit/sbom
import licence_audit/sbom_json
import licence_audit/sbom_spdx
import licence_audit/sbom_uuid
import licence_audit/source_archive
import licence_audit/spdx
import licence_audit/toml
import licence_audit/version
import licence_audit/vulnerability_command
import simplifile

/// Return formatted SBOM text, or an empty string after writing the output.
/// The caller owns command scope, diagnostics, exit codes, and progress flush.
pub fn run(
  options: cli.SbomOptions,
  metadata_fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
  publication_fetcher: fn(String, String) -> Result(hex.Publication, hex.Error),
  batch_fetcher: fn(List(String)) -> Result(List(osv.BatchEntry), osv.Error),
  advisory_fetcher: fn(List(String), progress.Reporter) ->
    #(Result(List(osv.Vulnerability), error.Error), progress.Reporter),
  source_clients: notice.Clients,
  reporter: progress.Reporter,
) -> #(Result(String, error.Error), progress.Reporter) {
  let manifest_path =
    options.manifest_path
    |> option.unwrap("manifest.toml")
    |> manifest.resolve_path
  let project_root = path.dirname(manifest_path)
  let reporter = progress.phase(reporter, "Generating SBOM")
  let reporter = progress.detail(reporter, "Loading package manifest")
  let selection = {
    use sbom_manifest <- result.try(
      manifest.load_sbom(manifest_path)
      |> result.map_error(error.from_manifest_error),
    )
    use root <- result.try(read_root_component(project_root))
    use #(sbom_manifest, local_metadata) <- result.try(sbom.resolve_local(
      sbom_manifest,
      project_root,
    ))
    use prod_seed <- result.try(
      manifest.resolve_prod_seed(project_root, sbom_manifest.root_requirements)
      |> result.map_error(error.from_manifest_error),
    )
    Ok(#(
      sbom_manifest,
      root,
      manifest.sbom_scopes(sbom_manifest, prod_seed),
      local_metadata,
    ))
  }
  case selection {
    Error(reason) -> #(Error(reason), reporter)
    Ok(#(sbom_manifest, root, scopes, local_metadata)) ->
      run_for_manifest(
        options,
        sbom_manifest,
        root,
        scopes,
        project_root,
        local_metadata,
        metadata_fetcher,
        publication_fetcher,
        batch_fetcher,
        advisory_fetcher,
        source_clients,
        reporter,
      )
  }
}

fn run_for_manifest(
  options: cli.SbomOptions,
  sbom_manifest: manifest.SbomManifest,
  root: sbom.RootComponent,
  scopes: dict.Dict(String, manifest.Scope),
  project_root: String,
  local_metadata: dict.Dict(String, hex.PackageMetadata),
  metadata_fetcher: fn(String) -> Result(hex.PackageMetadata, hex.Error),
  publication_fetcher: fn(String, String) -> Result(hex.Publication, hex.Error),
  batch_fetcher: fn(List(String)) -> Result(List(osv.BatchEntry), osv.Error),
  advisory_fetcher: fn(List(String), progress.Reporter) ->
    #(Result(List(osv.Vulnerability), error.Error), progress.Reporter),
  source_clients: notice.Clients,
  reporter: progress.Reporter,
) -> #(Result(String, error.Error), progress.Reporter) {
  let cache_mode = cache.mode_for(options.no_cache, options.cache_dir)
  let #(now, _) =
    timestamp.system_time() |> timestamp.to_unix_seconds_and_nanoseconds
  let #(publications, warning) =
    publication.resolve(
      sbom_manifest.entries,
      cache_mode,
      options.offline,
      now,
      publication_fetcher,
    )
  let reporter = apply_cache_warning(reporter, warning)
  case publications {
    Error(reason) -> #(Error(reason), reporter)
    Ok(publications) -> {
      let cache_handle = cache.open(cache_mode)
      let cached_fetcher =
        cache.wrap(cache_handle, case options.offline {
          True -> fn(_) {
            Error(hex.NetworkFailure("offline: metadata is not cached"))
          }
          False -> metadata_fetcher
        })
      let #(metadata_result, cache_warning, reporter) = case
        options.reproducible
      {
        True ->
          fetch_reproducible_metadata(
            options,
            sbom_manifest,
            cache_handle,
            source_clients,
            reporter,
          )
        False -> {
          let #(metadata, reporter) =
            fetch_package_metadata(
              sbom_manifest,
              project_root,
              cached_fetcher,
              reporter,
            )
          #(metadata, None, reporter)
        }
      }
      let cache_warning = option.or(cache_warning, cache.close(cache_handle))
      case metadata_result {
        Error(reason) -> #(
          Error(reason),
          apply_cache_warning(reporter, cache_warning),
        )
        Ok(metadata) -> {
          let reporter = apply_cache_warning(reporter, cache_warning)
          let #(vulnerabilities, reporter) = case options.with_vulns {
            False -> #(Ok([]), reporter)
            True ->
              gather_embedded_vulnerabilities(
                sbom_manifest,
                publications,
                batch_fetcher,
                advisory_fetcher,
                reporter,
              )
          }
          case vulnerabilities {
            Error(reason) -> #(Error(reason), reporter)
            Ok(vulnerabilities) ->
              render(
                options,
                sbom_manifest,
                scopes,
                root,
                dict.merge(metadata, local_metadata),
                publications,
                vulnerabilities,
                source_clients,
                reporter,
              )
          }
        }
      }
    }
  }
}

fn apply_cache_warning(
  reporter: progress.Reporter,
  warning: Option(String),
) -> progress.Reporter {
  case warning {
    Some(message) -> progress.defer_warn(reporter, message)
    None -> reporter
  }
}

fn fetch_reproducible_metadata(
  options: cli.SbomOptions,
  manifest_value: manifest.SbomManifest,
  cache_handle: cache.Cache,
  clients: notice.Clients,
  reporter: progress.Reporter,
) -> #(
  Result(dict.Dict(String, hex.PackageMetadata), error.Error),
  Option(String),
  progress.Reporter,
) {
  let outcomes =
    network.fetch(
      manifest_value.entries,
      fn(entry) { entry.name <> "@" <> entry.version },
      fn(entry) {
        let captured = progress.fork(reporter)
        case manifest.immutable_metadata_key(entry) {
          Error(_) -> #(Ok(None), None, captured)
          Ok(key) -> {
            let captured =
              progress.detail(
                captured,
                "Reading reproducible metadata for "
                  <> entry.name
                  <> "@"
                  <> entry.version,
              )
            let #(metadata, warning) =
              cache.fetch_immutable(cache_handle, key, fn() {
                case options.offline {
                  True ->
                    Error(error.SbomMetadataFailed(
                      entry.name,
                      "offline: required locked metadata is not cached or caching is disabled",
                    ))
                  False -> metadata_from_locked_source(entry, clients)
                }
              })
            #(result.map(metadata, Some), warning, captured)
          }
        }
      },
    )
  list.fold(
    over: list.zip(manifest_value.entries, outcomes),
    from: #(Ok(dict.new()), None, reporter),
    with: fn(acc, pair) {
      let #(entry, outcome) = pair
      let #(metadata, warning, reporter) = acc
      case outcome {
        Error(reason) -> #(
          Error(error.RuntimeException(reason)),
          warning,
          reporter,
        )
        Ok(#(fetched, fetch_warning, captured)) -> {
          let reporter = progress.merge(reporter, captured)
          let metadata = {
            use metadata <- result.try(metadata)
            use package_metadata <- result.try(fetched)
            Ok(case package_metadata {
              None -> metadata
              Some(value) -> dict.insert(metadata, entry.name, value)
            })
          }
          #(metadata, option.or(warning, fetch_warning), reporter)
        }
      }
    },
  )
}

fn metadata_from_locked_source(
  entry: manifest.SbomEntry,
  clients: notice.Clients,
) -> Result(hex.PackageMetadata, error.Error) {
  case entry.provenance {
    manifest.HexProvenance(checksum, _) ->
      notice.hex_metadata_from_locked_source(
        entry.name,
        entry.version,
        checksum,
        clients.fetch_hex_tarball,
      )
      |> result.map_error(fn(source_error) {
        error.SbomMetadataFailed(
          entry.name,
          notice.describe_error(source_error),
        )
      })
    manifest.GitProvenance(repo, commit, path) ->
      git_metadata_from_locked_source(entry, repo, commit, path, clients)
    manifest.PathProvenance(_) | manifest.UnknownProvenance(_) ->
      Error(error.SbomMetadataFailed(entry.name, "unsupported package source"))
  }
}

fn git_metadata_from_locked_source(
  entry: manifest.SbomEntry,
  repo_url: String,
  commit: String,
  path: Option(String),
  clients: notice.Clients,
) -> Result(hex.PackageMetadata, error.Error) {
  use repo <- result.try(
    repository.parse_github_source(repo_url)
    |> result.replace_error(error.SbomMetadataFailed(
      entry.name,
      "unsupported Git repository URL",
    )),
  )
  use archive <- result.try(
    clients.fetch_git_archive(repo, commit)
    |> result.map_error(fn(fetch_error) {
      error.SbomMetadataFailed(
        entry.name,
        notice.describe_fetch_error(fetch_error),
      )
    }),
  )
  use contents <- result.try(
    {
      case path {
        None -> source_archive.extract_root_file_tar_gz(archive, "gleam.toml")
        Some(_) -> {
          use directory <- result.try(
            manifest.git_subdirectory(path)
            |> result.replace_error(source_archive.InvalidArchive),
          )
          source_archive.extract_package_file_tar_gz(
            archive,
            directory,
            "gleam.toml",
          )
        }
      }
    }
    |> result.map_error(fn(archive_error) {
      error.SbomMetadataFailed(
        entry.name,
        source_archive.describe_error(archive_error),
      )
    }),
  )
  use text <- result.try(
    bit_array.to_string(contents)
    |> result.replace_error(error.SbomMetadataFailed(
      entry.name,
      "locked Git archive gleam.toml is not valid UTF-8",
    )),
  )
  gleam_toml.package_metadata(text, gleam_toml.strip_git_suffix(repo_url))
  |> result.replace_error(error.SbomMetadataFailed(
    entry.name,
    "locked Git archive has an invalid gleam.toml",
  ))
}

fn render(
  options: cli.SbomOptions,
  sbom_manifest: manifest.SbomManifest,
  scopes: dict.Dict(String, manifest.Scope),
  root: sbom.RootComponent,
  package_metadata: dict.Dict(String, hex.PackageMetadata),
  publications: dict.Dict(String, hex.Publication),
  vulnerabilities: List(sbom.EmbeddedVulnerability),
  clients: notice.Clients,
  reporter: progress.Reporter,
) -> #(Result(String, error.Error), progress.Reporter) {
  let serial_and_timestamp = case options.reproducible {
    True -> Ok(#(sbom.ContentDerivedSerial, sbom_uuid.reproducible_timestamp()))
    False ->
      sbom_uuid.serial_number()
      |> result.map(fn(serial) {
        #(sbom.FixedSerial(serial), sbom_uuid.timestamp_now())
      })
      |> result.replace_error(error.SbomSerialNumberFailed)
  }
  case serial_and_timestamp {
    Error(reason) -> #(Error(reason), reporter)
    Ok(#(serial_number, timestamp)) -> {
      let #(texts, reporter) =
        gather_license_texts(options, root, package_metadata, clients, reporter)
      let rendered =
        texts
        |> result.map(fn(license_texts) {
          sbom.SbomInput(
            manifest: sbom_manifest,
            root: root,
            tool_version: tool_version(),
            serial_number: serial_number,
            timestamp: timestamp,
            package_metadata: package_metadata,
            publications: publications,
            scopes: scopes,
            vulnerabilities: vulnerabilities,
            license_texts: license_texts,
          )
        })
        |> result.try(fn(input) {
          case options.format {
            cli.CyclonedxJson -> sbom.try_render(input)
            cli.SpdxJson -> sbom_spdx.try_render(input)
          }
        })
      case rendered {
        Error(reason) -> #(Error(reason), reporter)
        Ok(json) -> write_output(options.output, json, reporter)
      }
    }
  }
}

fn gather_license_texts(
  options: cli.SbomOptions,
  root: sbom.RootComponent,
  metadata: dict.Dict(String, hex.PackageMetadata),
  clients: notice.Clients,
  reporter: progress.Reporter,
) -> #(Result(dict.Dict(String, String), error.Error), progress.Reporter) {
  use <- bool.guard(when: !options.license_text, return: #(
    Ok(dict.new()),
    reporter,
  ))
  let ids =
    metadata
    |> dict.values
    |> list.flat_map(fn(package) { package.licences })
    |> list.append(root.licences)
    |> sbom.license_entries
    |> list.filter_map(fn(entry) {
      case entry {
        sbom.LicenseId(id) -> Ok(id)
        sbom.LicenseName(_) | sbom.LicenseExpression(_) -> Error(Nil)
      }
    })
    |> list.sort(by: string.compare)
  let mode = case options.no_cache {
    True -> notice_cache.Disabled
    False -> notice_cache.Enabled(path: options.cache_dir)
  }
  let text_cache = notice_cache.open(mode)
  let #(texts, warning) =
    list.fold(ids, #(Ok(dict.new()), None), fn(acc, id) {
      use texts <- cache_dir.try_with_warning(acc)
      use resolved <- cache_dir.with_warning(case options.offline {
        True ->
          notice_resolve.resolve_cached_spdx(
            text_cache,
            "SBOM",
            spdx.LicenseRequirement(id),
          )
        False ->
          notice_resolve.resolve_spdx(
            text_cache,
            "SBOM",
            spdx.LicenseRequirement(id),
            clients,
          )
      })
      #(
        case resolved {
          Ok(Some(file)) -> Ok(dict.insert(texts, id, file.contents))
          Ok(None) ->
            Error(error.Notices(
              "Canonical SPDX licence text unavailable: " <> id,
            ))
          Error(fetch_error) ->
            Error(error.Notices(notice.describe_error(fetch_error)))
        },
        None,
      )
    })
  let warning = option.or(warning, notice_cache.close(text_cache))
  #(texts, apply_cache_warning(reporter, warning))
}

fn gather_embedded_vulnerabilities(
  sbom_manifest: manifest.SbomManifest,
  publications: dict.Dict(String, hex.Publication),
  batch_fetcher: fn(List(String)) -> Result(List(osv.BatchEntry), osv.Error),
  advisory_fetcher: fn(List(String), progress.Reporter) ->
    #(Result(List(osv.Vulnerability), error.Error), progress.Reporter),
  reporter: progress.Reporter,
) -> #(Result(List(sbom.EmbeddedVulnerability), error.Error), progress.Reporter) {
  let purl_pairs =
    list.try_fold(sbom_manifest.entries, [], fn(pairs, entry) {
      use purl <- result.try(sbom.verified_purl(entry, publications))
      use ref <- result.try(sbom.component_ref(entry))
      case purl {
        Some(purl) -> Ok(list.append(pairs, [#(purl, ref)]))
        None -> Ok(pairs)
      }
    })
  case purl_pairs {
    Error(reason) -> #(Error(reason), reporter)
    Ok(purl_pairs) -> {
      let purls = list.map(purl_pairs, fn(pair) { pair.0 })
      case purls {
        [] -> #(Ok([]), reporter)
        _ -> {
          let reporter =
            progress.detail(
              reporter,
              "Querying OSV.dev for "
                <> int.to_string(list.length(purls))
                <> " packages",
            )
          case batch_fetcher(purls) {
            Error(reason) -> #(Error(error.from_osv_error(reason)), reporter)
            Ok(entries) -> {
              let id_to_components = build_id_to_components(purl_pairs, entries)
              let #(vulnerabilities, reporter) = case vulnerability_command.unique_vuln_ids(entries) {
                [] -> #(Ok([]), reporter)
                ids -> advisory_fetcher(ids, reporter)
              }
              #(
                result.map(vulnerabilities, to_embedded_vulnerabilities(
                  _,
                  id_to_components,
                )),
                reporter,
              )
            }
          }
        }
      }
    }
  }
}

fn to_embedded_vulnerabilities(
  vulnerabilities: List(osv.Vulnerability),
  id_to_components: dict.Dict(String, List(#(String, String))),
) -> List(sbom.EmbeddedVulnerability) {
  list.map(vulnerabilities, fn(vulnerability) {
    let pairs = case dict.get(id_to_components, vulnerability.id) {
      Ok(refs) -> refs
      Error(_) -> []
    }
    sbom.EmbeddedVulnerability(
      vuln: vulnerability,
      affects: list.map(pairs, fn(pair) { pair.1 }),
      purls: list.map(pairs, fn(pair) { pair.0 }),
    )
  })
}

fn build_id_to_components(
  purl_pairs: List(#(String, String)),
  entries: List(osv.BatchEntry),
) -> dict.Dict(String, List(#(String, String))) {
  list.zip(purl_pairs, entries)
  |> list.fold(dict.new(), fn(acc, pair) {
    let #(identity, batch_entry) = pair
    list.fold(batch_entry.vuln_ids, acc, fn(inner, id) {
      let existing = case dict.get(inner, id) {
        Ok(refs) -> refs
        Error(_) -> []
      }
      case list.contains(existing, identity) {
        True -> inner
        False -> dict.insert(inner, id, list.append(existing, [identity]))
      }
    })
  })
}

fn fetch_package_metadata(
  manifest_value: manifest.SbomManifest,
  project_root: String,
  fetcher: fn(manifest.Package, progress.Reporter) ->
    #(Result(hex.PackageMetadata, hex.Error), progress.Reporter),
  reporter: progress.Reporter,
) -> #(
  Result(dict.Dict(String, hex.PackageMetadata), error.Error),
  progress.Reporter,
) {
  let outcomes =
    network.fetch(
      manifest_value.entries,
      fn(entry) { entry.name <> "@" <> entry.version },
      fn(entry) {
        let reporter = progress.fork(reporter)
        case entry.provenance {
          manifest.HexProvenance(_, _) ->
            fetch_hex_entry_metadata(entry, fetcher, dict.new(), reporter)
          manifest.GitProvenance(repo, _commit, _path) ->
            enrich_git_entry_metadata(
              entry,
              repo,
              project_root,
              dict.new(),
              reporter,
            )
          manifest.PathProvenance(_) | manifest.UnknownProvenance(_) -> #(
            dict.new(),
            reporter,
          )
        }
      },
    )
  list.fold(outcomes, #(Ok(dict.new()), reporter), fn(acc, outcome) {
    let #(metadata, reporter) = acc
    case outcome {
      Error(reason) -> #(Error(error.RuntimeException(reason)), reporter)
      Ok(#(fetched, captured)) -> #(
        result.map(metadata, dict.merge(_, fetched)),
        progress.merge(reporter, captured),
      )
    }
  })
}

fn fetch_hex_entry_metadata(
  entry: manifest.SbomEntry,
  fetcher: fn(manifest.Package, progress.Reporter) ->
    #(Result(hex.PackageMetadata, hex.Error), progress.Reporter),
  metadata_acc: dict.Dict(String, hex.PackageMetadata),
  reporter: progress.Reporter,
) -> #(dict.Dict(String, hex.PackageMetadata), progress.Reporter) {
  let package =
    manifest.Package(
      name: entry.name,
      version: entry.version,
      requirements: entry.requirements,
      outer_checksum: "",
    )
  let #(result, reporter) = fetcher(package, reporter)
  case result {
    Ok(metadata) -> #(dict.insert(metadata_acc, entry.name, metadata), reporter)
    Error(error) -> {
      let reporter =
        progress.defer_warn(
          reporter,
          "No Hex metadata for "
            <> entry.name
            <> "@"
            <> entry.version
            <> " ("
            <> hex.describe_error(error)
            <> "); SBOM component will omit licences, description, publisher, and links",
        )
      #(metadata_acc, reporter)
    }
  }
}

fn enrich_git_entry_metadata(
  entry: manifest.SbomEntry,
  repo: String,
  project_root: String,
  metadata_acc: dict.Dict(String, hex.PackageMetadata),
  reporter: progress.Reporter,
) -> #(dict.Dict(String, hex.PackageMetadata), progress.Reporter) {
  let repo_url = gleam_toml.strip_git_suffix(repo)
  let path = project_root <> "/build/packages/" <> entry.name <> "/gleam.toml"
  let metadata = {
    use contents <- result.try(
      simplifile.read(from: path) |> result.replace_error(Nil),
    )
    gleam_toml.package_metadata(contents, repo_url)
  }
  case metadata {
    Ok(metadata) -> #(dict.insert(metadata_acc, entry.name, metadata), reporter)
    Error(_) -> {
      let metadata =
        hex.PackageMetadata(
          licences: [],
          description: None,
          links: [#("Repository", repo_url)],
          publisher: None,
        )
      let reporter =
        progress.defer_warn(
          reporter,
          "No local metadata for "
            <> entry.name
            <> "@"
            <> entry.version
            <> " ("
            <> path
            <> " unreadable); SBOM component will omit description and licences",
        )
      #(dict.insert(metadata_acc, entry.name, metadata), reporter)
    }
  }
}

fn read_root_component(
  project_root: String,
) -> Result(sbom.RootComponent, error.Error) {
  let path = project_root <> "/gleam.toml"
  use contents <- result.try(case simplifile.read(from: path) {
    Error(reason) ->
      Error(error.Input(
        "Could not read SBOM root metadata from "
        <> path
        <> ": "
        <> simplifile.describe_error(reason),
      ))
    Ok(contents) -> Ok(contents)
  })
  use document <- result.try(case toml.parse(contents) {
    Error(_) ->
      Error(error.Input(
        "Could not parse SBOM root metadata from " <> path <> ": invalid TOML",
      ))
    Ok(document) -> Ok(document)
  })
  case
    toml.get_string(document, ["name"]),
    toml.get_string(document, ["version"])
  {
    Error(_), _ ->
      Error(error.Input(
        "Invalid SBOM root metadata in "
        <> path
        <> ": required `name` field is missing or not a string",
      ))
    _, Error(_) ->
      Error(error.Input(
        "Invalid SBOM root metadata in "
        <> path
        <> ": required `version` field is missing or not a string",
      ))
    Ok(name), Ok(version) -> {
      let description =
        option.from_result(toml.get_string(document, ["description"]))
      let licences = case toml.get_array(document, ["licences"]) {
        Ok(items) -> list.filter_map(items, toml.as_string)
        Error(_) -> []
      }
      let repository = case toml.get_table(document, ["repository"]) {
        Ok(entry) -> repository_url(entry)
        Error(_) -> None
      }
      Ok(sbom.RootComponent(
        name:,
        version:,
        description:,
        licences:,
        repository:,
      ))
    }
  }
}

fn repository_url(entry: toml.Entry) -> Option(String) {
  case
    repository_field(entry, "type"),
    repository_field(entry, "user"),
    repository_field(entry, "repo")
  {
    Some("github"), Some(user), Some(repo) ->
      Some("https://github.com/" <> user <> "/" <> repo)
    _, _, _ -> None
  }
}

fn repository_field(entry: toml.Entry, name: String) -> Option(String) {
  case toml.field(entry, name) {
    Ok(value) -> option.from_result(toml.as_string(value))
    Error(_) -> None
  }
}

fn tool_version() -> String {
  case version.build_version() {
    Ok(version) -> version
    Error(Nil) -> "unknown"
  }
}

fn write_output(
  output: Option(String),
  json: String,
  reporter: progress.Reporter,
) -> #(Result(String, error.Error), progress.Reporter) {
  case sbom_json.pretty_print(json) {
    Error(reason) -> #(
      Error(error.Decode(
        "failed to format SBOM JSON: " <> sbom_json.describe_error(reason),
      )),
      reporter,
    )
    Ok(pretty_json) ->
      case output {
        None -> #(Ok(pretty_json <> "\n"), reporter)
        Some(path) ->
          case simplifile.write(to: path, contents: pretty_json <> "\n") {
            Ok(_) -> #(Ok(""), reporter)
            Error(reason) -> #(
              Error(error.SbomWriteFailed(
                path: path,
                reason: simplifile.describe_error(reason),
              )),
              reporter,
            )
          }
      }
  }
}
