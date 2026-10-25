import sqlight

pub fn drop_table(cache_path: String) -> Nil {
  let assert Ok(connection) = sqlight.open(cache_path)
  let assert Ok(Nil) = sqlight.exec("DROP TABLE cache_entries", on: connection)
  let assert Ok(Nil) = sqlight.close(connection)
  Nil
}

/// Store an invalid SQLite value so cache reads exercise their type checks.
@external(erlang, "cache_support_ffi", "corrupt_entry")
pub fn corrupt_entry(cache_path: String, key: String) -> Result(Nil, String)

/// Hold a separate writer while running a test callback.
@external(erlang, "cache_support_ffi", "with_writer")
pub fn with_writer(cache_path: String, action: fn() -> a) -> a

@external(erlang, "cache_support_ffi", "assert_busy")
pub fn assert_busy(action: fn() -> a) -> Nil

@external(erlang, "cache_support_ffi", "create_legacy")
pub fn create_legacy(cache_path: String) -> Nil

@external(erlang, "cache_support_ffi", "assert_concurrent_cleanup")
pub fn assert_concurrent_cleanup(path_prefix: String) -> Nil
