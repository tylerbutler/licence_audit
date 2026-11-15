//// Required Hex publication evidence for local SBOM components.
//// Positive records never expire. Negative records expire after 24 hours.
//// Separate keys prevent a concurrent negative write from erasing a positive.

import gleam/dict.{type Dict}
import gleam/list
import gleam/option.{type Option, None, Some}
import licence_audit/cache
import licence_audit/cache_dir
import licence_audit/error
import licence_audit/hex
import licence_audit/manifest

pub fn resolve(
  entries: List(manifest.SbomEntry),
  mode: cache.Mode,
  offline: Bool,
  now: Int,
  fetcher: fn(String, String) -> Result(hex.Publication, hex.Error),
) -> #(Result(Dict(String, hex.Publication), error.Error), Option(String)) {
  let locals =
    list.filter(entries, fn(entry) {
      case entry.provenance {
        manifest.PathProvenance(_) -> True
        manifest.HexProvenance(_, _)
        | manifest.GitProvenance(_, _, _)
        | manifest.UnknownProvenance(_) -> False
      }
    })
  case locals {
    [] -> #(Ok(dict.new()), None)
    [_, ..] -> {
      use table <- cache_dir.with_warning(open(mode))
      list.fold(locals, #(Ok(dict.new()), None), fn(acc, entry) {
        use publications <- cache_dir.try_with_warning(acc)
        use publication <- cache_dir.try_with_warning(verify(
          table,
          entry.name,
          entry.version,
          offline,
          now,
          fetcher,
        ))
        #(Ok(dict.insert(publications, entry.name, publication)), None)
      })
    }
  }
}

fn open(mode: cache.Mode) -> #(Option(cache_dir.Store), Option(String)) {
  case mode {
    cache.Disabled -> #(None, None)
    cache.Enabled(root) ->
      case cache_dir.open_table(root, "publication-v1", "publication") {
        Ok(table) -> #(Some(table), None)
        Error(reason) -> #(None, Some(cache_dir.describe_error(reason)))
      }
  }
}

fn verify(
  table: Option(cache_dir.Store),
  name: String,
  version: String,
  offline: Bool,
  now: Int,
  fetcher: fn(String, String) -> Result(hex.Publication, hex.Error),
) -> #(Result(hex.Publication, error.Error), Option(String)) {
  let key = name <> "@" <> version
  use cached <- cache_dir.with_warning(lookup(table, key, now))
  case cached {
    Ok(publication) -> #(Ok(publication), None)
    Error(Nil) ->
      case offline {
        True -> #(
          Error(error.SbomPublicationFailed(
            key,
            "offline: usable cached verification is required; it is missing, invalid, expired, or disabled by --no-cache",
          )),
          None,
        )
        False ->
          case fetcher(name, version) {
            Error(reason) -> #(
              Error(error.SbomPublicationFailed(key, hex.describe_error(reason))),
              None,
            )
            Ok(publication) -> #(
              Ok(publication),
              store(table, key, publication, now),
            )
          }
      }
  }
}

fn lookup(
  table: Option(cache_dir.Store),
  key: String,
  now: Int,
) -> #(Result(hex.Publication, Nil), Option(String)) {
  case table {
    None -> #(Error(Nil), None)
    Some(table) -> {
      use positive <- cache_dir.with_warning(read(table, "published:" <> key))
      case positive {
        Ok(cache_dir.Entry("published", _)) -> #(Ok(hex.Published), None)
        Ok(_) | Error(Nil) -> {
          use negative <- cache_dir.with_warning(read(
            table,
            "unpublished:" <> key,
          ))
          case negative {
            Ok(cache_dir.Entry("unpublished", Some(cached_at)))
              if cached_at <= now && now - cached_at < 86_400
            -> #(Ok(hex.Unpublished), None)
            Ok(_) | Error(Nil) -> #(Error(Nil), None)
          }
        }
      }
    }
  }
}

fn read(
  table: cache_dir.Store,
  key: String,
) -> #(Result(cache_dir.Entry, Nil), Option(String)) {
  case cache_dir.lookup_entry(table, key) {
    Ok(entry) -> #(Ok(entry), None)
    Error(reason) -> #(
      Error(Nil),
      cache_dir.access_warning(reason, "publication"),
    )
  }
}

fn store(
  table: Option(cache_dir.Store),
  key: String,
  publication: hex.Publication,
  now: Int,
) -> Option(String) {
  case table {
    None -> None
    Some(table) -> {
      let stored = case publication {
        hex.Published ->
          cache_dir.insert(table, "published:" <> key, "published")
        hex.Unpublished ->
          cache_dir.insert_at(
            table,
            "unpublished:" <> key,
            "unpublished",
            Some(now),
          )
      }
      case stored {
        Ok(Nil) -> None
        Error(reason) -> cache_dir.access_warning(reason, "publication")
      }
    }
  }
}
