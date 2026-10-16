import gleam/dynamic/decode
import gleam/result
import slate/set

/// Store a non-string value so cache reads see a corrupt entry.
pub fn corrupt_entry(cache_path: String, key: String) -> Result(Nil, Nil) {
  use table <- result.try(
    set.open(cache_path, key_decoder: decode.string, value_decoder: decode.int)
    |> result.replace_error(Nil),
  )
  use _ <- result.try(set.insert(table, key, 255) |> result.replace_error(Nil))
  set.close(table) |> result.replace_error(Nil)
}
