/// Store an invalid SQLite value so cache reads exercise their type checks.
@external(erlang, "cache_support_ffi", "corrupt_entry")
pub fn corrupt_entry(cache_path: String, key: String) -> Result(Nil, String)

/// Hold a separate writer while running a test callback.
@external(erlang, "cache_support_ffi", "with_writer")
pub fn with_writer(cache_path: String, action: fn() -> a) -> a

@external(erlang, "cache_support_ffi", "create_legacy")
pub fn create_legacy(cache_path: String) -> Nil

@external(erlang, "cache_support_ffi", "assert_concurrent_cleanup")
pub fn assert_concurrent_cleanup(path_prefix: String) -> Nil
