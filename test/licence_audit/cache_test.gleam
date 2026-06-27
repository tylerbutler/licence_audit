import gleam/dynamic/decode
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleeunit/should
import licence_audit/cache
import licence_audit/hex
import licence_audit/manifest
import licence_audit/progress
import simplifile
import slate/set as dets_set

const tmp_dir = "build/tmp/cache_test"

fn fresh_path(name: String) -> String {
  let _ = simplifile.create_directory_all(tmp_dir)
  let path = tmp_dir <> "/" <> name <> ".dets"
  let _ = simplifile.delete(path)
  path
}

fn pkg(name: String, version: String) -> manifest.Package {
  manifest.Package(
    name: name,
    version: version,
    source: manifest.Hex,
    kind: manifest.Direct,
    requirements: [],
  )
}

fn reporter() -> progress.Reporter {
  progress.capturing(progress.Verbose, "report")
}

fn metadata_with_publisher(publisher: String) -> hex.PackageMetadata {
  hex.PackageMetadata(
    licences: ["MIT"],
    description: Some("Package metadata"),
    links: [#("HexDocs", "https://hexdocs.pm/example")],
    publisher: Some(publisher),
  )
}

fn write_legacy_cache_entry(
  path: String,
  key: String,
  metadata: hex.PackageMetadata,
) {
  let assert Ok(table) =
    dets_set.open(
      path,
      key_decoder: decode.string,
      value_decoder: decode.string,
    )
  let assert Ok(_) =
    dets_set.insert(
      into: table,
      key: key,
      value: hex.encode_cache_entry(metadata),
    )
  let assert Ok(_) = dets_set.close(table)
  Nil
}

fn detail_messages(rep: progress.Reporter) -> List(String) {
  progress.events(rep)
  |> list.filter_map(fn(event) {
    case event {
      progress.Event(progress.Detail, message) -> Ok(message)
      _ -> Error(Nil)
    }
  })
}

fn any_contains(values: List(String), needle: String) -> Bool {
  list.any(values, fn(value) { string.contains(value, needle) })
}

fn warning_messages(rep: progress.Reporter) -> List(String) {
  progress.events(rep)
  |> list.filter_map(fn(event) {
    case event {
      progress.Event(progress.Warning, message) -> Ok(message)
      _ -> Error(Nil)
    }
  })
}

pub fn disabled_cache_bypasses_storage_test() {
  let handle = cache.open(cache.Disabled)
  let warning = cache.close(handle)

  should.equal(warning, None)
}

pub fn disabled_cache_logs_passthrough_test() {
  let handle = cache.open(cache.Disabled)
  let fetcher = fn(_name) { Ok(hex.licences_only(["MIT"])) }
  let #(result, rep) =
    cache.wrap(handle, fetcher)(pkg("gleam_stdlib", "1.0.0"), reporter())
  let assert Ok(metadata) = result
  should.equal(metadata.licences, ["MIT"])
  let assert True = any_contains(detail_messages(rep), "Cache disabled")
  let assert None = cache.close(handle)
}

pub fn cache_round_trip_persists_metadata_test() {
  let path = fresh_path("round_trip")

  // First run: cache miss writes through to disk.
  let handle = cache.open(cache.Enabled(path: Some(path)))
  let fetcher = fn(_name) { Ok(hex.licences_only(["MIT"])) }
  let #(result, rep1) =
    cache.wrap(handle, fetcher)(pkg("gleam_stdlib", "1.0.0"), reporter())
  let assert Ok(metadata) = result
  should.equal(metadata.licences, ["MIT"])
  let messages = detail_messages(rep1)
  let assert True = any_contains(messages, "Cache miss")
  let assert True = any_contains(messages, "Cached licence metadata")
  let assert None = cache.close(handle)

  // Second run: hit — fetcher must not be called.
  let handle = cache.open(cache.Enabled(path: Some(path)))
  let exploding = fn(_name) {
    panic as "fetcher must not be called on cache hit"
  }
  let #(result, rep2) =
    cache.wrap(handle, exploding)(pkg("gleam_stdlib", "1.0.0"), reporter())
  let assert Ok(cached) = result
  should.equal(cached.licences, ["MIT"])
  let assert True = any_contains(detail_messages(rep2), "Cache hit")
  let assert None = cache.close(handle)
}

pub fn cache_key_includes_version_test() {
  let path = fresh_path("version_key")

  let handle = cache.open(cache.Enabled(path: Some(path)))
  let v1 = fn(_name) { Ok(hex.licences_only(["MIT"])) }
  let _ = cache.wrap(handle, v1)(pkg("foo", "1.0.0"), reporter())
  let assert None = cache.close(handle)

  // Different version → different key → fetcher must be re-invoked.
  let handle = cache.open(cache.Enabled(path: Some(path)))
  let v2 = fn(_name) { Ok(hex.licences_only(["Apache-2.0"])) }
  let #(result, _) = cache.wrap(handle, v2)(pkg("foo", "2.0.0"), reporter())
  let assert Ok(metadata) = result
  should.equal(metadata.licences, ["Apache-2.0"])
  let assert None = cache.close(handle)
}

pub fn cache_refetches_legacy_enriched_entry_instead_of_stale_publisher_test() {
  let path = fresh_path("legacy_enriched_refetch")
  write_legacy_cache_entry(
    path,
    "example@1.0.0",
    metadata_with_publisher("old-owner"),
  )

  let handle = cache.open(cache.Enabled(path: Some(path)))
  let fetcher = fn(_name) { Ok(metadata_with_publisher("new-owner")) }
  let #(result, rep) =
    cache.wrap(handle, fetcher)(pkg("example", "1.0.0"), reporter())

  let assert Ok(metadata) = result
  should.equal(metadata.publisher, Some("new-owner"))
  let assert True = any_contains(detail_messages(rep), "Cache miss")
  let assert None = cache.close(handle)
}

pub fn fetcher_errors_are_not_cached_test() {
  let path = fresh_path("errors_not_cached")

  let handle = cache.open(cache.Enabled(path: Some(path)))
  let failing = fn(_name) { Error(hex.NotFound) }
  let #(result, _) =
    cache.wrap(handle, failing)(pkg("missing", "1.0.0"), reporter())
  let assert Error(hex.NotFound) = result
  let assert None = cache.close(handle)

  let handle = cache.open(cache.Enabled(path: Some(path)))
  let succeeding = fn(_name) { Ok(hex.licences_only(["MIT"])) }
  let #(result, _) =
    cache.wrap(handle, succeeding)(pkg("missing", "1.0.0"), reporter())
  let assert Ok(metadata) = result
  should.equal(metadata.licences, ["MIT"])
  let assert None = cache.close(handle)
}

pub fn fetch_failure_falls_back_to_stale_entry_test() {
  let path = fresh_path("stale_fallback")
  // A legacy entry has no `cached_at` marker, so it is treated as expired
  // (a miss) and forces a refetch.
  write_legacy_cache_entry(
    path,
    "example@1.0.0",
    metadata_with_publisher("cached-owner"),
  )

  let handle = cache.open(cache.Enabled(path: Some(path)))
  let failing = fn(_name) { Error(hex.NetworkFailure("connection refused")) }
  let #(result, rep) =
    cache.wrap(handle, failing)(pkg("example", "1.0.0"), reporter())

  // The stale cached metadata is returned instead of dropping enrichment.
  let assert Ok(metadata) = result
  should.equal(metadata.publisher, Some("cached-owner"))
  let assert True = any_contains(warning_messages(rep), "stale cached metadata")
  let assert True = any_contains(warning_messages(rep), "connection refused")
  let assert None = cache.close(handle)
}

pub fn fetch_failure_without_cache_entry_propagates_error_test() {
  let path = fresh_path("no_stale_entry")

  let handle = cache.open(cache.Enabled(path: Some(path)))
  let failing = fn(_name) { Error(hex.NotFound) }
  let #(result, rep) =
    cache.wrap(handle, failing)(pkg("missing", "1.0.0"), reporter())

  // No stale entry exists, so the original error surfaces with no fallback
  // warning (the caller is responsible for warning about absent metadata).
  let assert Error(hex.NotFound) = result
  should.equal(warning_messages(rep), [])
  let assert None = cache.close(handle)
}

pub fn unwritable_path_returns_warning_test() {
  let _ = simplifile.create_directory_all(tmp_dir)
  let blocker = tmp_dir <> "/blocker.file"
  let _ = simplifile.write("data", to: blocker)
  let bad_path = blocker <> "/nested/hex.dets"

  let handle = cache.open(cache.Enabled(path: Some(bad_path)))
  let fetcher = fn(_name) { Ok(hex.licences_only(["MIT"])) }
  let #(result, _) =
    cache.wrap(handle, fetcher)(pkg("gleam_stdlib", "1.0.0"), reporter())
  let assert Ok(metadata) = result
  should.equal(metadata.licences, ["MIT"])

  let warning = cache.close(handle)
  let assert Some(_) = warning
}
