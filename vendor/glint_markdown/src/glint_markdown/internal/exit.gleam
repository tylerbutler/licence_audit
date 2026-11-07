//// Process-exit and stderr shims, isolated behind FFI so the rest of the
//// library stays pure Gleam.

@external(erlang, "glint_markdown_exit_ffi", "stderr")
@external(javascript, "./exit_ffi.mjs", "stderr")
pub fn stderr(message message: String) -> Nil

@external(erlang, "glint_markdown_exit_ffi", "exit_with")
@external(javascript, "./exit_ffi.mjs", "exit_with")
pub fn exit_with(code code: Int) -> Nil
