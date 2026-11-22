import gleam/dict
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import licence_audit/cache
import licence_audit/cache_dir
import licence_audit/cli
import licence_audit/config
import licence_audit/error
import licence_audit/gleam_toml
import licence_audit/hex
import licence_audit/manifest
import licence_audit/network
import licence_audit/notice
import licence_audit/notice_cache
import licence_audit/notice_resolve
import licence_audit/path
import licence_audit/progress
import licence_audit/repository
import licence_audit/toml
import simplifile

/// Return notice text, or an empty string after writing the requested file.
/// The caller owns diagnostics, exit codes, and deferred progress emission.
pub fn run(
  options: cli.NoticesOptions,
  clients: notice.Clients,
  reporter: progress.Reporter,
) -> #(Result(String, error.Error), progress.Reporter) {
  let manifest_path = option.unwrap(options.manifest_path, "manifest.toml")
  let project_root = path.dirname(manifest_path)
  let reporter = progress.phase(reporter, "Generating licence notices")
  let reporter = progress.detail(reporter, "Loading package manifest")

  let selection = {
    use configuration <- result.try(
      config.load_notices(
        project_root,
        options.config_path,
        options.ignore_config,
      )
      |> result.map_error(error.from_config_error),
    )
    use sbom_manifest <- result.try(
      manifest.load_sbom(manifest_path)
      |> result.map_error(error.from_manifest_error),
    )
    use prod_seed <- result.try(
      manifest.resolve_prod_seed(project_root, sbom_manifest.root_requirements)
      |> result.map_error(error.from_manifest_error),
    )
    let scopes = manifest.sbom_scopes(sbom_manifest, prod_seed)
    use selected <- result.try(
      notice.selected_entries(
        sbom_manifest,
        scopes,
        include_dev: options.scope == cli.All,
      )
      |> notice.filter_entries(sbom_manifest.entries, configuration)
      |> result.map_error(fn(notice_error) {
        error.Config(notice.describe_error(notice_error))
      }),
    )
    Ok(#(selected, scopes, list.length(sbom_manifest.entries)))
  }
  case selection {
    Error(selection_error) -> #(Error(selection_error), reporter)
    Ok(#(selected, scopes, count)) -> {
      let reporter =
        progress.detail(
          reporter,
          "Loaded manifest with " <> int.to_string(count) <> " total entries",
        )
      run_selected(
        options,
        selected,
        scopes,
        project_root,
        manifest_path,
        clients,
        reporter,
      )
    }
  }
}

fn run_selected(
  options: cli.NoticesOptions,
  selected: List(manifest.SbomEntry),
  scopes: dict.Dict(String, manifest.Scope),
  project_root: String,
  manifest_path: String,
  clients: notice.Clients,
  reporter: progress.Reporter,
) -> #(Result(String, error.Error), progress.Reporter) {
  let #(metadata_cache_mode, source_cache_mode) = case
    options.no_cache || selected == []
  {
    True -> #(cache.Disabled, notice_cache.Disabled)
    False -> #(
      cache.Enabled(path: options.cache_dir),
      notice_cache.Enabled(path: options.cache_dir),
    )
  }
  let metadata_cache = cache.open(metadata_cache_mode)
  let source_cache = notice_cache.open(source_cache_mode)

  let reporter =
    progress.detail(
      reporter,
      "Selected "
        <> int.to_string(list.length(selected))
        <> " package(s) for notices (scope="
        <> case options.scope {
        cli.Prod -> "prod"
        cli.All -> "all"
      }
        <> ")",
    )
  let reporter = progress.package_count(reporter, list.length(selected))

  let metadata_for = fn(entry: manifest.SbomEntry) {
    metadata_for_entry(entry, project_root, metadata_cache, clients)
  }
  let #(packages, metadata_warning) =
    notice.packages_from_entries(selected, scopes, metadata_for)
  let reporter =
    apply_cache_warning(
      reporter,
      option.or(metadata_warning, cache.close(metadata_cache)),
    )
  case packages {
    Error(notice_error) -> #(
      Error(error.Notices(notice.describe_error(notice_error))),
      apply_cache_warning(reporter, notice_cache.close(source_cache)),
    )
    Ok(packages) -> {
      let reporter =
        progress.detail(
          reporter,
          "Resolved metadata for "
            <> int.to_string(list.length(packages))
            <> " package(s)",
        )
      let #(result, reporter) =
        build_entries(
          packages,
          project_root,
          manifest_path,
          options.output,
          source_cache,
          clients,
          reporter,
        )
      let source_warning = notice_cache.close(source_cache)
      #(result, apply_cache_warning(reporter, source_warning))
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

fn build_entries(
  packages: List(notice.NoticePackage),
  project_root: String,
  manifest_path: String,
  output: Option(String),
  source_cache: notice_cache.Cache,
  clients: notice.Clients,
  reporter: progress.Reporter,
) -> #(Result(String, error.Error), progress.Reporter) {
  let reporter =
    list.fold(packages, reporter, fn(reporter, package) {
      progress.detail(
        reporter,
        "Fetching "
          <> package.name
          <> "@"
          <> package.version
          <> " from "
          <> describe_source(package.source),
      )
    })
  let #(result, warnings) =
    resolve_entries(packages, project_root, source_cache, clients)
  let reporter =
    list.fold(warnings, reporter, fn(reporter, warning) {
      progress.defer_warn(reporter, warning)
    })

  case result {
    Error(notice_error) -> #(
      Error(error.Notices(notice.describe_error(notice_error))),
      reporter,
    )
    Ok(entries) -> {
      let reporter =
        list.fold(entries, reporter, fn(reporter, entry) {
          progress.detail(
            reporter,
            "Found "
              <> int.to_string(list.length(entry.files))
              <> " licence file(s) for "
              <> entry.package.name,
          )
        })
      let reporter = progress.detail(reporter, "Rendering notices output")
      write_output(
        notice.render(entries, manifest_path: manifest_path),
        output,
        reporter,
      )
    }
  }
}

fn resolve_entries(
  packages: List(notice.NoticePackage),
  project_root: String,
  source_cache: notice_cache.Cache,
  clients: notice.Clients,
) -> #(Result(List(notice.NoticeEntry), notice.Error), List(String)) {
  let outcomes =
    network.fetch(
      packages,
      fn(package) { package.name <> "@" <> package.version },
      fn(package) {
        notice_resolve.resolve(
          source_cache,
          package_for_source_read(package, project_root),
          clients,
        )
      },
    )
  let #(entries, warnings) =
    list.fold(list.zip(packages, outcomes), #(Ok(#([], [])), []), fn(acc, pair) {
      let #(collected, warnings) = acc
      let #(package, outcome) = pair
      let #(resolved, cache_warning) = case outcome {
        Ok(resolved) -> resolved
        Error(reason) -> #(
          Error(notice.MetadataFailed(package.name, reason)),
          None,
        )
      }
      let warnings = case cache_warning {
        None -> warnings
        Some(message) -> list.append(warnings, [message])
      }
      let warnings = case resolved {
        Ok(resolution) -> list.append(warnings, resolution.warnings)
        Error(_) -> warnings
      }
      let collected = {
        use #(entries, missing) <- result.try(collected)
        use resolution <- result.try(resolved)
        Ok(accumulate_outcome(package, resolution.outcome, entries, missing))
      }
      #(collected, warnings)
    })
  case entries {
    Error(error) -> #(Error(error), warnings)
    Ok(#(entries, missing)) -> finalize_entries(entries, missing, warnings)
  }
}

fn finalize_entries(
  entries: List(notice.NoticeEntry),
  missing: List(String),
  warnings: List(String),
) -> #(Result(List(notice.NoticeEntry), notice.Error), List(String)) {
  case list.reverse(missing) {
    [] -> #(Ok(list.reverse(entries)), warnings)
    missing_packages -> #(
      Error(notice.MissingLicenceText(missing_packages)),
      warnings,
    )
  }
}

fn accumulate_outcome(
  package: notice.NoticePackage,
  outcome: notice_resolve.Outcome,
  entries: List(notice.NoticeEntry),
  missing: List(String),
) -> #(List(notice.NoticeEntry), List(String)) {
  case outcome {
    notice_resolve.Resolved(files) -> #(
      [notice.NoticeEntry(package: package, files: files), ..entries],
      missing,
    )
    notice_resolve.Missing -> #(entries, [package.name, ..missing])
  }
}

fn metadata_for_entry(
  entry: manifest.SbomEntry,
  project_root: String,
  metadata_cache: cache.Cache,
  clients: notice.Clients,
) -> #(Result(hex.PackageMetadata, notice.Error), Option(String)) {
  case entry.provenance {
    manifest.HexProvenance(checksum, _) -> {
      use key <- cache_dir.try_with_warning(#(
        manifest.immutable_metadata_key(entry)
          |> result.replace_error(notice.MetadataFailed(
            entry.name,
            "invalid Hex source",
          )),
        None,
      ))
      cache.fetch_immutable(metadata_cache, key, fn() {
        notice.hex_metadata_from_locked_source(
          entry.name,
          entry.version,
          checksum,
          clients.fetch_hex_tarball,
        )
      })
    }
    manifest.GitProvenance(_, _, _) -> {
      use key <- cache_dir.try_with_warning(#(
        manifest.immutable_metadata_key(entry)
          |> result.replace_error(notice.MetadataFailed(
            entry.name,
            "invalid Git source",
          )),
        None,
      ))
      // Missing Git declarations are allowed here, unlike reproducible SBOMs.
      cache.fetch_immutable(metadata_cache, "notices:" <> key, fn() {
        notice.git_metadata_from_locked_source(entry, clients)
      })
    }
    manifest.PathProvenance(dependency_path) -> #(
      case read_path_metadata(path.resolve(project_root, dependency_path)) {
        Ok(metadata) -> Ok(metadata)
        Error(_) -> Ok(hex.licences_only([]))
      },
      None,
    )
    manifest.UnknownProvenance(_) -> #(Ok(hex.licences_only([])), None)
  }
}

fn read_path_metadata(
  dependency_root: String,
) -> Result(hex.PackageMetadata, Nil) {
  use contents <- result.try(
    simplifile.read(from: dependency_root <> "/gleam.toml")
    |> result.replace_error(Nil),
  )
  use document <- result.try(toml.parse(contents))
  let description =
    option.from_result(toml.get_string(document, ["description"]))
  Ok(hex.PackageMetadata(
    licences: gleam_toml.declared_licences(document),
    description: description,
    links: gleam_toml.links(document),
    publisher: None,
  ))
}

fn describe_source(source: notice.PackageSource) -> String {
  case source {
    notice.HexPackage(_) -> "Hex"
    notice.GitPackage(repo, _url, _commit, _path) ->
      "git " <> repository.describe(repo)
    notice.PathPackage(path) -> "local path " <> path
  }
}

fn package_for_source_read(
  package: notice.NoticePackage,
  project_root: String,
) -> notice.NoticePackage {
  case package.source {
    notice.PathPackage(dependency_path) ->
      notice.NoticePackage(
        ..package,
        source: notice.PathPackage(path.resolve(project_root, dependency_path)),
      )
    notice.HexPackage(_) | notice.GitPackage(_, _, _, _) -> package
  }
}

fn write_output(
  text: String,
  output: Option(String),
  reporter: progress.Reporter,
) -> #(Result(String, error.Error), progress.Reporter) {
  case output {
    None -> #(Ok(text), reporter)
    Some(path) -> {
      let reporter = progress.detail(reporter, "Writing notices to " <> path)
      case simplifile.write(to: path, contents: text) {
        Ok(_) -> #(Ok(""), reporter)
        Error(reason) -> #(
          Error(
            error.Notices(
              notice.describe_error(notice.OutputWriteFailed(
                path,
                simplifile.describe_error(reason),
              )),
            ),
          ),
          reporter,
        )
      }
    }
  }
}
