import gleam/dynamic/decode
import gleam/option.{None, Some}
import gleeunit/should
import licence_audit/manifest
import licence_audit/notice
import licence_audit/notice_cache
import simplifile
import slate/set as dets_set

const tmp_dir = "build/tmp/notices_cache_test"

fn fresh_path(name: String) -> String {
  let _ = simplifile.create_directory_all(tmp_dir)
  let path = tmp_dir <> "/" <> name <> ".dets"
  let _ = simplifile.delete(path)
  path
}

fn hex_package(name: String, checksum: String) -> notice.NoticePackage {
  notice.NoticePackage(
    name: name,
    version: "1.0.0",
    declared_licences: ["MIT"],
    repo_links: [],
    source: notice.HexPackage(outer_checksum: checksum),
    scope: manifest.Prod,
  )
}

fn notice(path: String, contents: String) -> notice.NoticeFile {
  notice.NoticeFile(path: path, contents: contents)
}

pub fn disabled_cache_bypasses_storage_test() {
  let handle = notice_cache.open(notice_cache.Disabled)
  let warning = notice_cache.close(handle)

  should.equal(warning, None)
}

pub fn disabled_cache_always_reads_live_test() {
  let handle = notice_cache.open(notice_cache.Disabled)
  let files = [notice("LICENSE", "MIT text")]
  let read = fn(_pkg) { Ok(files) }

  let result =
    notice_cache.read_cached(handle, hex_package("foo", "AAAA"), read)

  should.equal(result, Ok(files))
  let assert None = notice_cache.close(handle)
}

pub fn cache_round_trip_persists_notice_files_test() {
  let path = fresh_path("round_trip")
  let files = [notice("LICENSE", "MIT text"), notice("NOTICE", "Notice text")]

  // First run: miss writes through to disk.
  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  let read = fn(_pkg) { Ok(files) }
  let assert Ok(written) =
    notice_cache.read_cached(handle, hex_package("foo", "AAAA"), read)
  should.equal(written, files)
  let assert None = notice_cache.close(handle)

  // Second run: hit — the live read must not be called.
  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  let exploding = fn(_pkg) {
    panic as "live read must not be called on cache hit"
  }
  let assert Ok(cached) =
    notice_cache.read_cached(handle, hex_package("foo", "AAAA"), exploding)
  should.equal(cached, files)
  let assert None = notice_cache.close(handle)
}

pub fn cache_key_is_content_addressed_test() {
  let path = fresh_path("content_address")

  // Store under checksum AAAA.
  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  let original = [notice("LICENSE", "original")]
  let assert Ok(_) =
    notice_cache.read_cached(handle, hex_package("foo", "AAAA"), fn(_pkg) {
      Ok(original)
    })
  let assert None = notice_cache.close(handle)

  // Different checksum → different key → live read is invoked again.
  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  let updated = [notice("LICENSE", "updated")]
  let assert Ok(result) =
    notice_cache.read_cached(handle, hex_package("foo", "BBBB"), fn(_pkg) {
      Ok(updated)
    })
  should.equal(result, updated)
  let assert None = notice_cache.close(handle)
}

pub fn path_packages_are_not_cached_test() {
  let path = fresh_path("path_bypass")
  let package =
    notice.NoticePackage(
      name: "local",
      version: "0.1.0",
      declared_licences: [],
      repo_links: [],
      source: notice.PathPackage(path: "./local"),
      scope: manifest.Prod,
    )

  // First read returns one file but must not be cached.
  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  let assert Ok(_) =
    notice_cache.read_cached(handle, package, fn(_pkg) {
      Ok([notice("LICENSE", "first")])
    })
  let assert None = notice_cache.close(handle)

  // Second read must run live (no cached value), proving path deps bypass.
  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  let assert Ok(result) =
    notice_cache.read_cached(handle, package, fn(_pkg) {
      Ok([notice("LICENSE", "second")])
    })
  should.equal(result, [notice("LICENSE", "second")])
  let assert None = notice_cache.close(handle)
}

fn write_raw_entry(path: String, key: String, value: String) -> Nil {
  let assert Ok(table) =
    dets_set.open(
      path,
      key_decoder: decode.string,
      value_decoder: decode.string,
    )
  let assert Ok(_) = dets_set.insert(into: table, key: key, value: value)
  let assert Ok(_) = dets_set.close(table)
  Nil
}

pub fn corrupt_entry_is_treated_as_miss_test() {
  let path = fresh_path("corrupt")

  // Write an unparseable value under the content-addressed key.
  write_raw_entry(path, "foo@1.0.0@hex:AAAA", "not valid json")

  // read_cached must treat it as a miss and refetch live, then overwrite.
  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  let fresh = [notice("LICENSE", "refetched")]
  let assert Ok(result) =
    notice_cache.read_cached(handle, hex_package("foo", "AAAA"), fn(_pkg) {
      Ok(fresh)
    })
  should.equal(result, fresh)
  let assert None = notice_cache.close(handle)

  // The refetched value should now be cached and served on the next hit.
  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  let assert Ok(cached) =
    notice_cache.read_cached(handle, hex_package("foo", "AAAA"), fn(_pkg) {
      panic as "should hit cache after refetch"
    })
  should.equal(cached, fresh)
  let assert None = notice_cache.close(handle)
}

pub fn notice_files_codec_round_trips_test() {
  let files = [notice("LICENSE", "MIT text"), notice("NOTICE", "Notice text")]
  let assert Ok(decoded) =
    notice.decode_notice_files(notice.encode_notice_files(files))
  should.equal(decoded, files)
  should.equal(notice.decode_notice_files("not json"), Error(Nil))
}
