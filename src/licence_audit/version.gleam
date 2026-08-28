/// The licence_audit build version, embedded in the compiled OTP application
/// resource at build time (this project's own `gleam.toml`, not whatever
/// project is being audited). Used to populate CycloneDX `metadata.tools[]`
/// so the tool's own version can never leak from the current working
/// directory.
@external(erlang, "version_ffi", "build_version")
pub fn build_version() -> Result(String, Nil)
