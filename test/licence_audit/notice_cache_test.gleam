import gleam/list
import gleam/option.{None, Some}
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
  let path = tmp_dir <> "/" <> name <> ".sqlite3"
  list.each(["", "-wal", "-shm"], fn(suffix) {
    let _ = simplifile.delete(path <> suffix)
  })
  path
}

fn notice(path: String, contents: String) -> notice.NoticeFile {
  notice.NoticeFile(path: path, contents: contents)
}

pub fn disabled_cache_bypasses_storage_test() {
  let handle = notice_cache.open(notice_cache.Disabled)
  notice_cache.put_files(handle, "source:foo", [notice("LICENSE", "MIT text")])
  notice_cache.put_text(handle, "spdx:MIT", "MIT text")
  should.equal(notice_cache.get_files(handle, "source:foo"), Error(Nil))
  should.equal(notice_cache.get_text(handle, "spdx:MIT"), Error(Nil))
  let warning = notice_cache.close(handle)

  should.equal(warning, None)
}

pub fn open_failure_preserves_notices_warning_test() {
  let _ = simplifile.create_directory_all(tmp_dir)
  let blocker = tmp_dir <> "/open-blocker"
  let _ = simplifile.write("data", to: blocker)
  let path = blocker <> "/notices.sqlite3"
  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  let assert Some(warning) = notice_cache.close(handle)
  should.be_true(string.starts_with(
    warning,
    "Unable to open notices cache at " <> path <> ": ",
  ))
}

pub fn parent_directory_failure_preserves_warning_test() {
  let _ = simplifile.create_directory_all(tmp_dir)
  let blocker = tmp_dir <> "/blocker.file"
  let _ = simplifile.write("data", to: blocker)
  let dir = blocker <> "/nested"
  let handle =
    notice_cache.open(
      notice_cache.Enabled(path: Some(dir <> "/notices.sqlite3")),
    )
  let assert Some(warning) = notice_cache.close(handle)
  should.be_true(string.contains(
    warning,
    "Unable to create licence cache directory",
  ))
}

pub fn write_failure_preserves_notices_warning_test() {
  let path = fresh_path("write_failure")
  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  cache_support.with_writer(path, fn() {
    notice_cache.put_text(handle, "spdx:MIT", "MIT text")
  })
  let assert Some(warning) = notice_cache.close(handle)
  should.be_true(string.starts_with(warning, "Failed to access notices cache: "))
}

pub fn cache_round_trip_persists_notice_files_test() {
  let path = fresh_path("round_trip")
  let files = [notice("LICENSE", "MIT text"), notice("NOTICE", "Notice text")]

  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  should.equal(notice_cache.get_files(handle, "source:foo"), Error(Nil))
  notice_cache.put_files(handle, "source:foo", files)
  notice_cache.put_text(handle, "spdx:MIT", "Canonical MIT text")
  let assert None = notice_cache.close(handle)

  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  should.equal(notice_cache.get_files(handle, "source:foo"), Ok(files))
  should.equal(
    notice_cache.get_text(handle, "spdx:MIT"),
    Ok("Canonical MIT text"),
  )
  let assert None = notice_cache.close(handle)
}

pub fn cache_namespaces_do_not_overlap_test() {
  let path = fresh_path("namespaces")
  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  let files = [notice("LICENSE", "source")]
  notice_cache.put_files(handle, "source:foo", files)
  notice_cache.put_text(handle, "spdx:foo", "canonical")
  should.equal(notice_cache.get_files(handle, "source:foo"), Ok(files))
  should.equal(notice_cache.get_text(handle, "spdx:foo"), Ok("canonical"))
  should.equal(notice_cache.get_files(handle, "pkg:foo"), Error(Nil))
  let assert None = notice_cache.close(handle)
}

fn write_raw_entry(path: String, key: String, value: String) -> Nil {
  let assert Ok(table) = cache_dir.open_table(Some(path), "unused", "test")
  let assert Ok(_) = cache_dir.insert(table, key, value)
  let assert None = cache_dir.close_table(table, "test", None)
  Nil
}

pub fn corrupt_entry_is_treated_as_miss_test() {
  let path = fresh_path("corrupt")

  write_raw_entry(path, "source:foo", "not valid json")

  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  let fresh = [notice("LICENSE", "refetched")]
  should.equal(notice_cache.get_files(handle, "source:foo"), Error(Nil))
  notice_cache.put_files(handle, "source:foo", fresh)
  let assert None = notice_cache.close(handle)

  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  should.equal(notice_cache.get_files(handle, "source:foo"), Ok(fresh))
  let assert None = notice_cache.close(handle)
}

pub fn empty_text_is_treated_as_miss_test() {
  let handle =
    notice_cache.open(notice_cache.Enabled(path: Some(fresh_path("empty"))))
  notice_cache.put_text(handle, "spdx:MIT", "")
  should.equal(notice_cache.get_text(handle, "spdx:MIT"), Error(Nil))
  notice_cache.put_text(handle, "spdx:MIT", " \t\r\n")
  should.equal(notice_cache.get_text(handle, "spdx:MIT"), Error(Nil))
  let assert None = notice_cache.close(handle)
}

pub fn invalid_value_text_is_warned_miss_and_can_be_refetched_test() {
  let path = fresh_path("invalid_value")
  let key = "spdx:MIT"
  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  let assert Ok(Nil) = cache_support.corrupt_entry(path, key)

  should.equal(notice_cache.get_text(handle, key), Error(Nil))
  notice_cache.put_text(handle, key, "refetched MIT text")
  should.equal(notice_cache.get_text(handle, key), Ok("refetched MIT text"))
  let assert Some(warning) = notice_cache.close(handle)
  should.be_true(string.contains(warning, "read spdx:MIT"))

  let handle = notice_cache.open(notice_cache.Enabled(path: Some(path)))
  should.equal(notice_cache.get_text(handle, key), Ok("refetched MIT text"))
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
