import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleeunit/should
import licence_audit/cache
import licence_audit/hex
import licence_audit/manifest
import licence_audit/progress
import simplifile

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

pub fn disabled_cache_bypasses_storage_test() {
  let handle = cache.open(cache.Disabled)
  let warning = cache.close(handle)

  should.equal(warning, None)
}

pub fn disabled_cache_logs_passthrough_test() {
  let handle = cache.open(cache.Disabled)
  let fetcher = fn(_name) { Ok(hex.PackageMetadata(licences: ["MIT"])) }
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
  let fetcher = fn(_name) { Ok(hex.PackageMetadata(licences: ["MIT"])) }
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
  let v1 = fn(_name) { Ok(hex.PackageMetadata(licences: ["MIT"])) }
  let _ = cache.wrap(handle, v1)(pkg("foo", "1.0.0"), reporter())
  let assert None = cache.close(handle)

  // Different version → different key → fetcher must be re-invoked.
  let handle = cache.open(cache.Enabled(path: Some(path)))
  let v2 = fn(_name) { Ok(hex.PackageMetadata(licences: ["Apache-2.0"])) }
  let #(result, _) = cache.wrap(handle, v2)(pkg("foo", "2.0.0"), reporter())
  let assert Ok(metadata) = result
  should.equal(metadata.licences, ["Apache-2.0"])
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
  let succeeding = fn(_name) { Ok(hex.PackageMetadata(licences: ["MIT"])) }
  let #(result, _) =
    cache.wrap(handle, succeeding)(pkg("missing", "1.0.0"), reporter())
  let assert Ok(metadata) = result
  should.equal(metadata.licences, ["MIT"])
  let assert None = cache.close(handle)
}

pub fn unwritable_path_returns_warning_test() {
  let _ = simplifile.create_directory_all(tmp_dir)
  let blocker = tmp_dir <> "/blocker.file"
  let _ = simplifile.write("data", to: blocker)
  let bad_path = blocker <> "/nested/hex.dets"

  let handle = cache.open(cache.Enabled(path: Some(bad_path)))
  let fetcher = fn(_name) { Ok(hex.PackageMetadata(licences: ["MIT"])) }
  let #(result, _) =
    cache.wrap(handle, fetcher)(pkg("gleam_stdlib", "1.0.0"), reporter())
  let assert Ok(metadata) = result
  should.equal(metadata.licences, ["MIT"])

  let warning = cache.close(handle)
  let assert Some(_) = warning
}
