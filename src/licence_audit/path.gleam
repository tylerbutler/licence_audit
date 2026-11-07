//// Local paths built with filepath's platform-aware splitting. Its directory
//// and join functions still require forward slashes and explicit drive handling.

import filepath
import gleam/list
import gleam/string

pub fn dirname(path: String) -> String {
  let normalized = normalize(path)
  let directory = filepath.directory_name(normalized)
  case normalized, filepath.split(normalized) {
    "/", _ -> "/"
    _, [drive, ..] ->
      case
        string.ends_with(drive, ":/")
        && { directory == "" || directory == string.drop_end(drive, 1) }
      {
        True -> drive
        False -> directory_or_current(directory)
      }
    _, [] -> "."
  }
}

pub fn join(parent: String, child: String) -> String {
  let child = normalize(child)
  case is_absolute(child) {
    True -> child
    False -> filepath.join(normalize(parent), child)
  }
}

pub fn resolve(root: String, path: String) -> String {
  case root {
    "." -> path
    _ -> join(root, path)
  }
}

fn normalize(path: String) -> String {
  case filepath.split(path) {
    [] -> ""
    ["/", "", ..parts] -> join_parts("//", parts)
    [first, ..parts] -> join_parts(first, parts)
  }
}

fn join_parts(root: String, parts: List(String)) -> String {
  parts
  |> list.filter(fn(part) { part != "" })
  |> list.fold(root, filepath.join)
}

fn is_absolute(path: String) -> Bool {
  filepath.is_absolute(path)
  || case filepath.split(path) {
    [drive, ..] -> string.ends_with(drive, ":/")
    [] -> False
  }
}

fn directory_or_current(directory: String) -> String {
  case directory {
    "" -> "."
    _ -> directory
  }
}
