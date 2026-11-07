//// Process-exit and stderr shims, isolated behind FFI so the rest of the
//// library stays pure Gleam.

// Vendored from vendor/glint_markdown/src/glint_markdown/internal/exit.gleam at 9c66ec3a62e43c639b06c3dfa582f223fc2fef14.
// Modified for licence_audit vendoring. Run just vendor-sync to update.

import gleam/io

pub fn stderr(message message: String) -> Nil {
  io.print_error(message)
}

@external(erlang, "erlang", "halt")
@external(javascript, "node:process", "exit")
pub fn exit_with(code code: Int) -> Nil
