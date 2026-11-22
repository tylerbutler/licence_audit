import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import gleeunit/should
import licence_audit/cache_dir
import licence_audit/cache_support
import licence_audit/notice
import licence_audit/notice_cache
import simplifile

const tmp_dir = "build/tmp/notices_cache_test"

fn fresh_path(name: String) -> String {
  let _ = simplifile.create_directory_all(tmp_dir)
  let path = tmp_dir <> "/" <> name
  let _ = simplifile.delete(path)
  path
}

fn notice(path: String, contents: String) -> notice.NoticeFile {
  notice.NoticeFile(path: path, contents: contents)
}

pub fn disabled_cache_bypasses_storage_test() {
  let handle = notice_cache.open(notice_cache.Disabled)
  notice_cache.put_files(handle, "source:foo", [notice("LICENSE", "MIT text")])
  notice_cache.put_text(handle, "spdx:MIT", "MIT text")
  should.equal(notice_cache.get_files(handle, "source:foo"), #(Error(Nil), None))
  should.equal(notice_cache.get_text(handle, "spdx:MIT"), #(Error(Nil), None))
  let warning = notice_cache.close(handle)

  should.equal(warning, None)
}

pub fn open_failure_preserves_notices_warning_test() {
  let _ = simplifile.create_directory_all(tmp_dir)
  let blocker = tmp_dir <> "/open-blocker"
  let _ = simplifile.write("data", to: blocker)
  let path = blocker <> "/notices"
  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  let assert Some(warning) = notice_cache.close(handle)
  should.be_true(string.starts_with(
    warning,
    "Unable to open SPDX text cache at " <> path <> "/spdx-v1: ",
  ))
}

pub fn parent_directory_failure_preserves_warning_test() {
  let _ = simplifile.create_directory_all(tmp_dir)
  let blocker = tmp_dir <> "/blocker.file"
  let _ = simplifile.write("data", to: blocker)
  let dir = blocker <> "/nested"
  let handle =
    notice_cache.open(notice_cache.Enabled(path: Some(dir <> "/notices")))
  let assert Some(warning) = notice_cache.close(handle)
  should.be_true(string.contains(
    warning,
    "Unable to create licence cache directory",
  ))
}

pub fn write_failure_preserves_notices_warning_test() {
  let path = fresh_path("write_failure")
  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  cache_support.break_store(path <> "/spdx-v1")
  let assert Some(warning) =
    notice_cache.put_text(handle, "spdx:MIT", "MIT text")
  let assert None = notice_cache.close(handle)
  should.be_true(string.starts_with(warning, "Failed to access notices cache: "))
}

pub fn cache_round_trip_persists_notice_files_test() {
  let path = fresh_path("round_trip")
  let files = [notice("LICENSE", "MIT text"), notice("NOTICE", "Notice text")]

  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  should.equal(notice_cache.get_files(handle, "source:foo"), #(Error(Nil), None))
  notice_cache.put_files(handle, "source:foo", files)
  notice_cache.put_text(handle, "spdx:MIT", "Canonical MIT text")
  let assert None = notice_cache.close(handle)

  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  should.equal(notice_cache.get_files(handle, "source:foo"), #(Ok(files), None))
  should.equal(notice_cache.get_text(handle, "spdx:MIT"), #(
    Ok("Canonical MIT text"),
    None,
  ))
  let assert None = notice_cache.close(handle)
}

pub fn cache_namespaces_do_not_overlap_test() {
  let path = fresh_path("namespaces")
  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  let files = [notice("LICENSE", "source")]
  notice_cache.put_files(handle, "source:foo", files)
  notice_cache.put_text(handle, "spdx:foo", "canonical")
  should.equal(notice_cache.get_files(handle, "source:foo"), #(Ok(files), None))
  should.equal(notice_cache.get_text(handle, "spdx:foo"), #(
    Ok("canonical"),
    None,
  ))
  should.equal(notice_cache.get_files(handle, "pkg:foo"), #(Error(Nil), None))
  let assert None = notice_cache.close(handle)
}

fn write_raw_entry(path: String, key: String, value: String) -> Nil {
  let assert Ok(table) = cache_dir.open_table(Some(path), "notices-v3", "test")
  let assert Ok(_) = cache_dir.insert(table, key, value)
  Nil
}

pub fn corrupt_entry_is_treated_as_miss_test() {
  let path = fresh_path("corrupt")

  write_raw_entry(path, "source:foo", "not valid json")

  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  let fresh = [notice("LICENSE", "refetched")]
  should.equal(notice_cache.get_files(handle, "source:foo"), #(Error(Nil), None))
  notice_cache.put_files(handle, "source:foo", fresh)
  let assert None = notice_cache.close(handle)

  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  should.equal(notice_cache.get_files(handle, "source:foo"), #(Ok(fresh), None))
  let assert None = notice_cache.close(handle)
}

pub fn empty_text_is_treated_as_miss_test() {
  let handle =
    notice_cache.open(notice_cache.Enabled(path: Some(fresh_path("empty"))))
  notice_cache.put_text(handle, "spdx:MIT", "")
  should.equal(notice_cache.get_text(handle, "spdx:MIT"), #(Error(Nil), None))
  notice_cache.put_text(handle, "spdx:MIT", " \t\r\n")
  should.equal(notice_cache.get_text(handle, "spdx:MIT"), #(Error(Nil), None))
  let assert None = notice_cache.close(handle)
}

pub fn invalid_value_text_is_warned_miss_and_can_be_refetched_test() {
  let path = fresh_path("invalid_value")
  let key = "spdx:MIT"
  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  let assert Ok(Nil) = cache_support.corrupt_entry(path <> "/spdx-v1", key)

  let assert #(result, Some(warning)) = notice_cache.get_text(handle, key)
  should.equal(result, Error(Nil))
  should.equal(notice_cache.put_text(handle, key, "refetched MIT text"), None)
  should.equal(notice_cache.get_text(handle, key), #(
    Ok("refetched MIT text"),
    None,
  ))
  let assert None = notice_cache.close(handle)
  should.be_true(string.contains(warning, "read spdx:MIT"))

  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  should.equal(notice_cache.get_text(handle, key), #(
    Ok("refetched MIT text"),
    None,
  ))
  let assert None = notice_cache.close(handle)
}

pub fn notice_files_codec_round_trips_test() {
  let files = [notice("LICENSE", "MIT text"), notice("NOTICE", "Notice text")]
  let assert Ok(decoded) =
    notice.decode_notice_files(notice.encode_notice_files(files))
  should.equal(decoded, files)
  should.equal(notice.decode_notice_files("not json"), Error(Nil))
}

pub fn blank_cached_files_are_a_miss_even_with_other_usable_text_test() {
  list.each(["", " \t\r\n", "\u{00A0}\u{2003}"], fn(blank) {
    should.equal(
      notice.decode_notice_files(
        notice.encode_notice_files([
          notice("LICENSE", blank),
          notice("COPYING", "usable text"),
        ]),
      ),
      Error(Nil),
    )
  })
}

pub fn shared_root_separates_spdx_and_reuses_compatible_pinned_entries_test() {
  let root = fresh_path("shared_root-é中")
  let assert Ok(legacy) =
    cache_dir.open_table(Some(root), "notices-v3", "legacy")
  let key = "spdx:pinned-revision:license:MIT"
  should.equal(cache_dir.insert(legacy, key, "Pinned MIT text"), Ok(Nil))
  let cache = notice_cache.open(notice_cache.Enabled(Some(root)))
  should.equal(notice_cache.get_text(cache, key), #(Ok("Pinned MIT text"), None))
  let assert Ok(spdx_store) =
    cache_dir.open_table(Some(root), "spdx-v1", "SPDX text")
  should.equal(cache_dir.lookup(spdx_store, key), Ok("Pinned MIT text"))
  should.equal(cache_dir.lookup(legacy, key), Ok("Pinned MIT text"))
  notice_cache.put_files(cache, "source:immutable", [
    notice("LICENSE", "Source"),
  ])
  should.be_true(
    result.is_error(cache_dir.lookup(spdx_store, "source:immutable")),
  )
  should.be_true(result.is_ok(cache_dir.lookup(legacy, "source:immutable")))
  should.equal(notice_cache.close(cache), None)
}

pub fn unavailable_spdx_store_keeps_compatible_legacy_text_test() {
  let root = fresh_path("blocked_spdx")
  let assert Ok(legacy) =
    cache_dir.open_table(Some(root), "notices-v3", "legacy")
  let key = "spdx:pinned-revision:license:MIT"
  let assert Ok(Nil) = cache_dir.insert(legacy, key, "Legacy MIT text")
  let assert Ok(Nil) = simplifile.write("blocker", to: root <> "/spdx-v1")
  let cache = notice_cache.open(notice_cache.Enabled(Some(root)))
  should.equal(notice_cache.get_text(cache, key), #(Ok("Legacy MIT text"), None))
  let assert Some(warning) = notice_cache.close(cache)
  should.be_true(string.contains(warning, "Unable to open SPDX text cache"))
}

pub fn blank_spdx_entry_does_not_shadow_compatible_legacy_text_test() {
  let root = fresh_path("blank_spdx")
  let assert Ok(legacy) =
    cache_dir.open_table(Some(root), "notices-v3", "legacy")
  let key = "spdx:pinned-revision:license:MIT"
  let assert Ok(Nil) = cache_dir.insert(legacy, key, "Legacy MIT text")
  let cache = notice_cache.open(notice_cache.Enabled(Some(root)))
  should.equal(notice_cache.put_text(cache, key, " \t\n"), None)
  should.equal(notice_cache.get_text(cache, key), #(Ok("Legacy MIT text"), None))
  let assert Ok(spdx_store) =
    cache_dir.open_table(Some(root), "spdx-v1", "SPDX text")
  should.equal(cache_dir.lookup(spdx_store, key), Ok("Legacy MIT text"))
  should.equal(notice_cache.close(cache), None)
}

pub fn tag_expiry_is_exact_and_reads_do_not_extend_it_test() {
  let root = fresh_path("tag_expiry")
  let cache =
    notice_cache.open(notice_cache.Enabled(Some(root)))
    |> notice_cache.with_clock(fn() { 1000 })
  let key = "tag:v2:github:owner/repo@v1.0.0"
  should.equal(notice_cache.put_text(cache, key, "commit-a"), None)
  let assert Ok(table) = cache_dir.open_table(Some(root), "notices-v3", "test")
  should.equal(
    cache_dir.lookup_entry(table, key),
    Ok(cache_dir.Entry("commit-a", Some(1000))),
  )
  should.equal(
    notice_cache.get_text(notice_cache.with_clock(cache, fn() { 87_399 }), key),
    #(Ok("commit-a"), None),
  )
  list.each([999, 87_400, 87_401], fn(now) {
    should.equal(
      notice_cache.get_text(notice_cache.with_clock(cache, fn() { now }), key),
      #(Error(Nil), None),
    )
  })
  should.equal(
    cache_dir.lookup_entry(table, key),
    Ok(cache_dir.Entry("commit-a", Some(1000))),
  )
}

pub fn legacy_tag_without_timestamp_is_a_miss_test() {
  let root = fresh_path("legacy_tag")
  let key = "tag:v2:github:owner/repo@v1.0.0"
  write_raw_entry(root, key, "legacy-commit")
  let cache =
    notice_cache.open(notice_cache.Enabled(Some(root)))
    |> notice_cache.with_clock(fn() { 1000 })
  should.equal(notice_cache.get_text(cache, key), #(Error(Nil), None))
  should.equal(notice_cache.put_text(cache, key, "fresh-commit"), None)
  should.equal(notice_cache.get_text(cache, key), #(Ok("fresh-commit"), None))
}

pub fn tag_expiry_preserves_immutable_materials_and_disabled_mode_test() {
  let root = fresh_path("immutable_tag_neighbours")
  let cache =
    notice_cache.open(notice_cache.Enabled(Some(root)))
    |> notice_cache.with_clock(fn() { 0 })
  let files = [notice("LICENSE", "Immutable licence")]
  notice_cache.put_files(cache, "source:v2:locked-checksum", files)
  notice_cache.put_files(cache, "repo:v2:github:owner/repo@commit", files)
  notice_cache.put_text(cache, "spdx:pinned:license:MIT", "Pinned MIT text")
  let later = notice_cache.with_clock(cache, fn() { 864_000 })
  list.each(
    ["source:v2:locked-checksum", "repo:v2:github:owner/repo@commit"],
    fn(key) {
      should.equal(notice_cache.get_files(later, key), #(Ok(files), None))
    },
  )
  should.equal(notice_cache.get_text(later, "spdx:pinned:license:MIT"), #(
    Ok("Pinned MIT text"),
    None,
  ))
  let disabled =
    notice_cache.open(notice_cache.Disabled)
    |> notice_cache.with_clock(fn() { panic as "disabled cache used clock" })
  let key = "tag:v2:github:owner/repo@v1.0.0"
  should.equal(notice_cache.put_text(disabled, key, "commit"), None)
  should.equal(notice_cache.get_text(disabled, key), #(Error(Nil), None))
}
