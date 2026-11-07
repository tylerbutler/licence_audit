import gleam/bit_array
import gleam/crypto
import gleam/result
import gleam/string
import simplifile

/// The entry file for `key`, computed independently of `cache_dir`.
pub fn entry_path(cache_path: String, key: String) -> String {
  let digest =
    crypto.hash(crypto.Sha256, bit_array.from_string(key))
    |> bit_array.base16_encode
    |> string.lowercase
  cache_path <> "/" <> digest <> ".json"
}

/// Replace the cache directory with a file, so later reads and writes fail.
pub fn break_store(cache_path: String) -> Nil {
  let assert Ok(Nil) = simplifile.delete(cache_path)
  let assert Ok(Nil) = simplifile.write("not a directory", to: cache_path)
  Nil
}

/// Store bytes that are not UTF-8, so cache reads exercise their checks.
pub fn corrupt_entry(cache_path: String, key: String) -> Result(Nil, String) {
  let assert Ok(Nil) = simplifile.create_directory_all(cache_path)
  simplifile.write_bits(<<0xFF>>, to: entry_path(cache_path, key))
  |> result.map_error(simplifile.describe_error)
}
