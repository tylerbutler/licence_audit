import gleam/dict
import gleeunit/should
import licence_audit/cache_dir

pub fn windows_native_cache_environment_test() {
  let environment =
    dict.from_list([
      #("LOCALAPPDATA", "C:/Users/é中/AppData/Local"),
      #("USERPROFILE", "C:/Users/é中"),
    ])
  cache_dir.default_directory(True, dict.get(environment, _))
  |> should.equal(Ok("C:/Users/é中/AppData/Local"))
}

pub fn windows_profile_fallback_test() {
  let environment =
    dict.from_list([
      #("LOCALAPPDATA", ""),
      #("USERPROFILE", "C:/Users/é中"),
    ])
  cache_dir.default_directory(True, dict.get(environment, _))
  |> should.equal(Ok("C:/Users/é中/AppData/Local"))
}

pub fn explicit_xdg_cache_takes_precedence_test() {
  let environment =
    dict.from_list([
      #("XDG_CACHE_HOME", "D:/cache"),
      #("LOCALAPPDATA", "C:/Users/test/AppData/Local"),
    ])
  cache_dir.default_directory(True, dict.get(environment, _))
  |> should.equal(Ok("D:/cache"))
}

pub fn unix_cache_does_not_use_windows_environment_test() {
  let environment =
    dict.from_list([
      #("HOME", "/home/test"),
      #("LOCALAPPDATA", "C:/Users/test/AppData/Local"),
    ])
  cache_dir.default_directory(False, dict.get(environment, _))
  |> should.equal(Ok("/home/test/.cache"))
  cache_dir.default_directory(False, fn(_) { Error(Nil) })
  |> should.equal(Error(Nil))
}
