import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleam/time/timestamp
import gleeunit/should
import licence_audit/cache
import licence_audit/cache_dir
import licence_audit/cache_support
import licence_audit/hex
import licence_audit/manifest
import licence_audit/progress
import simplifile

const tmp_dir = "build/tmp/cache_test"

type ConcurrentWriteError

@external(erlang, "cache_process_test_ffi", "monotonic_milliseconds")
fn monotonic_milliseconds() -> Int

@external(erlang, "cache_process_test_ffi", "concurrent_writes")
fn concurrent_writes(
  cache_path: String,
  first_key: String,
  first_value: String,
  second_key: String,
  second_value: String,
) -> Result(Nil, ConcurrentWriteError)

fn fresh_path(name: String) -> String {
  let _ = simplifile.create_directory_all(tmp_dir)
  let path = tmp_dir <> "/" <> name <> ".sqlite3"
  list.each(["", "-wal", "-shm"], fn(suffix) {
    let _ = simplifile.delete(path <> suffix)
  })
  path
}

fn pkg(name: String, version: String) -> manifest.Package {
  manifest.Package(name: name, version: version, requirements: [])
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

fn write_cache_entry_without_timestamp(
  path: String,
  key: String,
  metadata: hex.PackageMetadata,
) {
  let assert Ok(table) = cache_dir.open_table(Some(path), "unused", "test")
  let assert Ok(_) =
    cache_dir.insert(table, key, hex.encode_cache_entry(metadata))
  let assert None = cache_dir.close_table(table, "test", None)
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

pub fn immutable_cache_ignores_incomplete_legacy_metadata_test() {
  let path = fresh_path("immutable_legacy")
  let key = "example@1.0.0@hex:ABC"
  write_cache_entry_without_timestamp(
    path,
    "$immutable:" <> key,
    hex.licences_only([]),
  )
  let handle = cache.open(cache.Enabled(Some(path)))
  let metadata = hex.licences_only(["MIT"])
  let assert Ok(fetched) =
    cache.fetch_immutable(handle, key, fn() { Ok(metadata) })
  should.equal(fetched, metadata)
  let assert None = cache.close(handle)
}

pub fn disabled_cache_bypasses_storage_test() {
  let handle = cache.open(cache.Disabled)
  let warning = cache.close(handle)

  should.equal(warning, None)
}

pub fn open_failure_preserves_licence_warning_test() {
  let _ = simplifile.create_directory_all(tmp_dir)
  let blocker = tmp_dir <> "/open-blocker"
  let _ = simplifile.write("data", to: blocker)
  let path = blocker <> "/cache.sqlite3"
  let handle = cache.open(cache.Enabled(path: Some(path)))
  let assert Some(warning) = cache.close(handle)
  should.be_true(string.starts_with(
    warning,
    "Unable to open licence cache at " <> path <> ": ",
  ))
}

pub fn write_failure_preserves_licence_warning_test() {
  let path = fresh_path("write_failure")
  let handle = cache.open(cache.Enabled(path: Some(path)))
  let fetcher = fn(_name) { Ok(hex.licences_only(["MIT"])) }
  cache_support.with_writer(path, fn() {
    let #(result, _) =
      cache.wrap(handle, fetcher)(pkg("gleam_stdlib", "1.0.0"), reporter())
    let assert Ok(_) = result
    Nil
  })
  let assert Some(warning) = cache.close(handle)
  should.be_true(string.starts_with(warning, "Failed to access licence cache: "))
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

pub fn separate_vms_keep_distinct_successful_writes_test() {
  let path = fresh_path("separate_vms")
  let assert Ok(store) = cache_dir.open_table(Some(path), "unused", "test")
  let assert Ok(Nil) =
    concurrent_writes(
      path,
      "first-key",
      "first-value",
      "second-key",
      "second-value",
    )
  should.equal(cache_dir.lookup(store, "first-key"), Ok("first-value"))
  should.equal(cache_dir.lookup(store, "second-key"), Ok("second-value"))
  let assert None = cache_dir.close_table(store, "test", None)
}

pub fn held_lock_bounds_total_fetch_latency_test() {
  let path = fresh_path("held_lock")
  let handle = cache.open(cache.Enabled(path: Some(path)))
  let started = monotonic_milliseconds()
  cache_support.with_writer(path, fn() {
    list.each(["first", "second", "third"], fn(name) {
      should.equal(
        cache.fetch_cached_quiet(handle, name, "1.0.0", fn(_) {
          Ok(hex.licences_only(["MIT"]))
        }),
        Ok(hex.licences_only(["MIT"])),
      )
    })
    let assert Some(warning) = cache.close(handle)
    should.be_true(string.contains(warning, "SQLite error 5:"))
  })
  let elapsed = monotonic_milliseconds() - started
  should.be_true(elapsed < 1000)

  let assert Ok(store) = cache_dir.open_table(Some(path), "unused", "test")
  list.each(["first", "second", "third"], fn(name) {
    should.equal(cache_dir.lookup(store, name <> "@1.0.0"), Error(Nil))
  })
  should.equal(cache_dir.insert(store, "after-release", "safe"), Ok(Nil))
  should.equal(cache_dir.lookup(store, "after-release"), Ok("safe"))
  let assert None = cache_dir.close_table(store, "test", None)
}

pub fn immutable_cache_entries_do_not_expire_test() {
  let path = fresh_path("immutable")
  let key = "example@1.0.0@hex:ABC"

  let handle = cache.open(cache.Enabled(path: Some(path)))
  let assert Ok(metadata) =
    cache.fetch_immutable(handle, key, fn() {
      Ok(metadata_with_publisher("archived"))
    })
  should.equal(metadata.publisher, Some("archived"))
  let assert None = cache.close(handle)

  let handle = cache.open(cache.Enabled(path: Some(path)))
  let assert Ok(cached) =
    cache.fetch_immutable(handle, key, fn() {
      panic as "immutable fetcher must not run on a cache hit"
    })
  should.equal(cached.publisher, Some("archived"))
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

pub fn cache_reuses_metadata_for_seven_days_test() {
  list.each([172_800, 604_740, 604_860], fn(age_seconds) {
    let path = fresh_path("ttl_" <> int.to_string(age_seconds))
    let assert Ok(table) = cache_dir.open_table(Some(path), "unused", "test")
    let #(now, _) =
      timestamp.system_time()
      |> timestamp.to_unix_seconds_and_nanoseconds
    list.each(["reported", "quiet"], fn(name) {
      let key = name <> "@1.0.0"
      let assert Ok(_) =
        cache_dir.insert_at(
          table,
          key,
          hex.encode_cache_entry(metadata_with_publisher("cached")),
          Some(now - age_seconds),
        )
    })
    let assert None = cache_dir.close_table(table, "test", None)

    let handle = cache.open(cache.Enabled(path: Some(path)))
    let fetcher = fn(_name) {
      should.be_true(age_seconds > 604_800)
      Ok(metadata_with_publisher("fresh"))
    }
    let expected = case age_seconds > 604_800 {
      True -> Some("fresh")
      False -> Some("cached")
    }
    let #(result, _) =
      cache.wrap(handle, fetcher)(pkg("reported", "1.0.0"), reporter())
    let assert Ok(metadata) = result
    should.equal(metadata.publisher, expected)
    let assert Ok(quiet_metadata) =
      cache.fetch_cached_quiet(handle, "quiet", "1.0.0", fetcher)
    should.equal(quiet_metadata.publisher, expected)
    let assert None = cache.close(handle)
  })
}

pub fn cache_refetches_legacy_enriched_entry_instead_of_stale_publisher_test() {
  let path = fresh_path("legacy_enriched_refetch")
  write_cache_entry_without_timestamp(
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

pub fn corrupt_cache_entry_is_refetched_test() {
  let path = fresh_path("corrupt")
  let assert Ok(table) = cache_dir.open_table(Some(path), "unused", "test")
  let assert Ok(_) =
    cache_dir.insert_at(
      table,
      "example@1.0.0",
      "not valid json",
      Some(now_seconds()),
    )
  let assert None = cache_dir.close_table(table, "test", None)

  let handle = cache.open(cache.Enabled(path: Some(path)))
  let fetcher = fn(_name) { Ok(metadata_with_publisher("refetched")) }
  let #(result, rep) =
    cache.wrap(handle, fetcher)(pkg("example", "1.0.0"), reporter())
  let assert Ok(metadata) = result
  should.equal(metadata.publisher, Some("refetched"))
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

fn now_seconds() -> Int {
  let #(seconds, _) =
    timestamp.system_time()
    |> timestamp.to_unix_seconds_and_nanoseconds
  seconds
}

pub fn lookup_failure_keeps_other_successful_entries_test() {
  let path = fresh_path("partial_failure")
  let handle = cache.open(cache.Enabled(path: Some(path)))
  let fetcher = fn(name) {
    case name {
      "missing" -> Error(hex.NetworkFailure("connection refused"))
      _ -> Ok(hex.licences_only(["MIT"]))
    }
  }
  list.each(["before", "missing", "after"], fn(name) {
    let #(result, _) =
      cache.wrap(handle, fetcher)(pkg(name, "1.0.0"), reporter())
    should.equal(result, fetcher(name))
  })
  let assert None = cache.close(handle)

  let handle = cache.open(cache.Enabled(path: Some(path)))
  let retry = fn(name) {
    should.equal(name, "missing")
    Ok(hex.licences_only(["Apache-2.0"]))
  }
  list.each(["before", "missing", "after"], fn(name) {
    let #(result, _) = cache.wrap(handle, retry)(pkg(name, "1.0.0"), reporter())
    let expected = case name {
      "missing" -> ["Apache-2.0"]
      _ -> ["MIT"]
    }
    should.equal(result, Ok(hex.licences_only(expected)))
  })
  let assert None = cache.close(handle)
}

pub fn fetch_failure_falls_back_to_stale_entry_test() {
  let path = fresh_path("stale_fallback")
  // A legacy entry has no `cached_at` marker, so it is treated as expired
  // (a miss) and forces a refetch.
  write_cache_entry_without_timestamp(
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
  let bad_path = blocker <> "/nested/hex.sqlite3"

  let handle = cache.open(cache.Enabled(path: Some(bad_path)))
  let fetcher = fn(_name) { Ok(hex.licences_only(["MIT"])) }
  let #(result, _) =
    cache.wrap(handle, fetcher)(pkg("gleam_stdlib", "1.0.0"), reporter())
  let assert Ok(metadata) = result
  should.equal(metadata.licences, ["MIT"])

  let warning = cache.close(handle)
  let assert Some(_) = warning
}

pub fn busy_upsert_preserves_value_and_timestamp_test() {
  let path = fresh_path("atomic_timestamp")
  let assert Ok(store) = cache_dir.open_table(Some(path), "unused", "test")
  should.equal(cache_dir.insert_at(store, "key", "old", Some(10)), Ok(Nil))
  cache_support.with_writer(path, fn() {
    let assert Error(_) = cache_dir.insert_at(store, "key", "new", Some(20))
    should.equal(
      cache_dir.lookup_entry(store, "key"),
      Ok(cache_dir.Entry("old", Some(10))),
    )
  })
  should.equal(cache_dir.insert_at(store, "key", "new", Some(20)), Ok(Nil))
  should.equal(
    cache_dir.lookup_entry(store, "key"),
    Ok(cache_dir.Entry("new", Some(20))),
  )
  let assert Some(_) = cache_dir.close_table(store, "test", None)
}

pub fn legacy_dets_file_is_not_modified_test() {
  let path = fresh_path("legacy_dets")
  cache_support.create_legacy(path)
  let assert Ok(before) = simplifile.read_bits(path)
  let handle = cache.open(cache.Enabled(Some(path)))
  let assert Some(warning) = cache.close(handle)
  should.be_true(string.contains(warning, "SQLite error 26:"))
  should.equal(simplifile.read_bits(path), Ok(before))
}

pub fn corrupt_database_is_not_replaced_test() {
  let path = fresh_path("invalid_database")
  let assert Ok(_) = simplifile.write("not a database", to: path)
  let handle = cache.open(cache.Enabled(Some(path)))
  let assert Some(_) = cache.close(handle)
  should.equal(simplifile.read(path), Ok("not a database"))
}

pub fn nul_filename_returns_warning_test() {
  let handle = cache.open(cache.Enabled(Some(fresh_path("nul") <> "\u{0000}")))
  let assert Some(warning) = cache.close(handle)
  should.be_true(string.contains(warning, "NUL"))
}

pub fn cache_operations_release_all_connections_before_return_test() {
  let path = fresh_path("connection_lifetime")
  let assert Ok(store) = cache_dir.open_table(Some(path), "unused", "test")
  list.each(list.repeat("value", 25), fn(value) {
    should.equal(cache_dir.insert_at(store, "key", value, Some(1)), Ok(Nil))
    should.equal(
      cache_dir.lookup_entry(store, "key"),
      Ok(cache_dir.Entry(value, Some(1))),
    )
    let assert Error(_) = simplifile.read_bits(path <> "-wal")
    let assert Error(_) = simplifile.read_bits(path <> "-shm")
  })
  let assert None = cache_dir.close_table(store, "test", None)
}

pub fn concurrent_independent_caches_release_connections_test() {
  cache_support.assert_concurrent_cleanup(fresh_path("parallel_cleanup"))
}
