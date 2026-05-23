import gleam/list
import gleam/string

const fallback = "❔"

const joiner = " "

pub fn for_licence(name: String) -> String {
  let lower = string.lowercase(string.trim(name))
  match(rules(), lower)
}

pub fn for_licences(licences: List(String)) -> String {
  case licences {
    [] -> fallback
    _ ->
      licences
      |> list.map(for_licence)
      |> string.join(joiner)
  }
}

fn rules() -> List(#(String, String)) {
  [
    #("agpl", "🌐"),
    #("lgpl", "📚"),
    #("gpl", "🐃"),
    #("mit", "🎓"),
    #("apache", "🪶"),
    #("0bsd", "🆓"),
    #("bsd-0", "🆓"),
    #("bsd", "🌲"),
    #("mpl", "🦎"),
    #("mozilla", "🦎"),
    #("isc", "🔑"),
    #("unlicense", "🆓"),
    #("cc0", "🆓"),
    #("public domain", "🆓"),
    #("wtfpl", "🤷"),
    #("zlib", "🗜️"),
    #("epl", "🌑"),
    #("eclipse", "🌑"),
    #("artistic", "🎨"),
    #("bsl", "💼"),
    #("business source", "💼"),
    #("boost", "🚀"),
    #("cddl", "☕"),
  ]
}

fn match(remaining: List(#(String, String)), lower: String) -> String {
  case remaining {
    [] -> fallback
    [#(prefix, emoji), ..rest] ->
      case string.starts_with(lower, prefix) {
        True -> emoji
        False -> match(rest, lower)
      }
  }
}
