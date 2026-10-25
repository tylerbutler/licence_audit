import filepath
import gleam/list
import gleam/string
import gleeunit/should
import licence_audit/path
import simplifile

fn is_windows() -> Bool {
  list.first(filepath.split("C:\\")) == Ok("c:/")
}

pub fn absolute_native_path(value: String) -> String {
  let assert Ok(cwd) = simplifile.current_directory()
  let absolute = path.resolve(cwd, value)
  case is_windows() {
    True -> string.replace(absolute, "/", "\\")
    False -> absolute
  }
}

pub fn relative_manifest_parent_test() {
  should.equal(path.dirname("manifest.toml"), ".")
  should.equal(path.dirname("project/manifest.toml"), "project")
  should.equal(path.resolve(".", "deps/local"), "deps/local")
  should.equal(path.resolve("project", "deps/local"), "project/deps/local")
}

pub fn absolute_paths_are_not_prefixed_test() {
  case is_windows() {
    False -> {
      should.equal(path.dirname("/manifest.toml"), "/")
      should.equal(path.resolve("project", "/deps/local"), "/deps/local")
    }
    True -> {
      should.equal(path.dirname("C:\\project\\manifest.toml"), "c:/project")
      should.equal(path.dirname("C:\\manifest.toml"), "c:/")
      should.equal(path.dirname("C:\\"), "c:/")
      should.equal(
        path.resolve("C:\\project", "D:\\deps\\local"),
        "d:/deps/local",
      )
      should.equal(
        path.dirname("\\\\server\\share\\manifest.toml"),
        "//server/share",
      )
      should.equal(
        path.resolve("C:\\project", "\\\\server\\share\\dep"),
        "//server/share/dep",
      )
    }
  }
}
