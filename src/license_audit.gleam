import gleam/io

pub type RunResult {
  RunResult(exit_code: Int, output: String)
}

pub fn main(args: List(String)) -> Nil {
  let RunResult(exit_code, output) = run(args)
  io.print(output)
  halt(exit_code)
}

pub fn run(args: List(String)) -> RunResult {
  case args {
    ["--help"] | ["-h"] -> RunResult(0, help_text())
    _ -> RunResult(0, help_text())
  }
}

fn help_text() -> String {
  "Usage: license-audit [OPTIONS]\n"
}

@external(erlang, "erlang", "halt")
fn halt(code: Int) -> Nil
