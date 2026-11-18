//// Provider-agnostic parsing of source-repository URLs and construction of the
//// HTTP endpoints used to resolve a tag to an immutable commit SHA and to
//// download a repository archive at that commit.
////
//// Only normalized HTTPS URLs for a small allow-list of hosts are accepted
//// (`github.com`, `codeberg.org`, `gitlab.com`). Anything else — other hosts,
//// userinfo, ports, query strings, fragments, non-HTTPS schemes, or extra path
//// segments — is rejected. A trailing `.git` and/or `/` on the `owner/repo`
//// path is tolerated and normalized away. The `owner`/`repo` segments must be
//// literal, normalized names: percent escapes, backslashes, colons, control
//// characters, and the `.`/`..` dot segments are rejected, while ordinary
//// names containing dots, hyphens, and underscores are accepted.

import gleam/bool
import gleam/dynamic/decode
import gleam/http.{Get, Https}
import gleam/http/request.{type Request, Request}
import gleam/json
import gleam/list
import gleam/option.{None}
import gleam/result
import gleam/string
import gleam/uri

pub type Provider {
  GitHub
  GitLab
  Codeberg
}

pub type Repository {
  Repository(provider: Provider, owner: String, repo: String)
}

pub type TagTarget {
  Commit(sha: String)
  AnnotatedTag(sha: String)
}

/// Parse a normalized HTTPS repository URL for a supported host. Returns
/// `Error(Nil)` for any URL that is not exactly
/// `https://<host>/<owner>/<repo>` (with optional trailing `.git`/`/`) for one
/// of the allow-listed hosts.
pub fn parse(url: String) -> Result(Repository, Nil) {
  // Reject userinfo, query, fragment, and any whitespace outright.
  use <- bool.guard(
    when: contains_any(url, ["@", "?", "#", " ", "\t", "\n"]),
    return: Error(Nil),
  )
  use rest <- result.try(strip_prefix(url, "https://"))

  case string.split_once(rest, on: "/") {
    Error(_) -> Error(Nil)
    Ok(#(host, path)) -> {
      use provider <- result.try(provider_for_host(host))
      use #(owner, repo) <- result.try(owner_repo(path, provider))
      Ok(Repository(provider: provider, owner: owner, repo: repo))
    }
  }
}

/// Parse any GitHub source URL accepted by SBOM purl generation.
pub fn parse_github_source(url: String) -> Result(Repository, Nil) {
  case parse(url) {
    Ok(Repository(provider: GitHub, owner:, repo:)) ->
      Ok(Repository(provider: GitHub, owner: owner, repo: repo))
    Ok(_) -> Error(Nil)
    Error(_) -> {
      use path <- result.try(github_source_path(url))
      use <- bool.guard(
        when: contains_any(path, ["@", "?", "#", " ", "\t", "\n"]),
        return: Error(Nil),
      )
      use #(owner, repo) <- result.try(owner_repo(path, GitHub))
      Ok(Repository(provider: GitHub, owner: owner, repo: repo))
    }
  }
}

fn github_source_path(url: String) -> Result(String, Nil) {
  case strip_prefix(url, "http://github.com/") {
    Ok(path) -> Ok(path)
    Error(_) ->
      case strip_prefix(url, "git@github.com:") {
        Ok(path) -> Ok(path)
        Error(_) -> strip_prefix(url, "git@github.com/")
      }
  }
}

fn provider_for_host(host: String) -> Result(Provider, Nil) {
  case host {
    "github.com" -> Ok(GitHub)
    "gitlab.com" -> Ok(GitLab)
    "codeberg.org" -> Ok(Codeberg)
    _ -> Error(Nil)
  }
}

fn owner_repo(
  path: String,
  provider: Provider,
) -> Result(#(String, String), Nil) {
  let normalized =
    path
    |> drop_trailing_slash
    |> drop_suffix(".git")
    |> drop_trailing_slash
  let segments = string.split(normalized, on: "/")

  case provider, segments {
    GitLab, _ -> {
      use #(namespace, repo) <- result.try(split_last(segments))
      use <- bool.guard(
        when: !list.all([repo, ..namespace], valid_segment),
        return: Error(Nil),
      )
      Ok(#(string.join(namespace, "/"), repo))
    }
    _, [owner, repo] ->
      case valid_segment(owner) && valid_segment(repo) {
        True -> Ok(#(owner, repo))
        False -> Error(Nil)
      }
    _, _ -> Error(Nil)
  }
}

fn split_last(segments: List(String)) -> Result(#(List(String), String), Nil) {
  case segments {
    [] | [_] -> Error(Nil)
    [first, last] -> Ok(#([first], last))
    [first, ..rest] -> {
      use #(namespace, last) <- result.try(split_last(rest))
      Ok(#([first, ..namespace], last))
    }
  }
}

/// Whether an `owner`/`repo` path segment is a normalized, literal name. Rejects
/// empty segments, the `.`/`..` dot segments, percent escapes, backslashes,
/// colons, and control characters — all signs of an un-normalized or
/// path-traversing URL — while still accepting ordinary names that contain dots,
/// hyphens, and underscores (e.g. `socket.io`, `gleam_stdlib`).
fn valid_segment(segment: String) -> Bool {
  segment != ""
  && segment != "."
  && segment != ".."
  && !contains_any(segment, ["%", "\\", ":"])
  && !has_control_char(segment)
}

fn has_control_char(value: String) -> Bool {
  string.to_utf_codepoints(value)
  |> list.any(fn(codepoint) {
    let code = string.utf_codepoint_to_int(codepoint)
    code < 0x20 || code == 0x7f
  })
}

/// Human-readable `provider owner/repo` label for logs and cache keys.
pub fn describe(repo: Repository) -> String {
  provider_slug(repo.provider) <> ":" <> repo.owner <> "/" <> repo.repo
}

fn provider_slug(provider: Provider) -> String {
  case provider {
    GitHub -> "github"
    GitLab -> "gitlab"
    Codeberg -> "codeberg"
  }
}

/// Candidate tag names to try, in order, for a package version. Prefer the
/// conventional `v`-prefixed tag, then the bare version.
pub fn tag_candidates(version: String) -> List(String) {
  ["v" <> version, version]
}

/// Build the API request that resolves `tag` to a commit for `repo`.
pub fn commit_request(repo: Repository, tag: String) -> Request(String) {
  let tag = uri.percent_encode(tag)
  case repo.provider {
    GitHub ->
      api_request(
        "api.github.com",
        "/repos/" <> repo.owner <> "/" <> repo.repo <> "/git/ref/tags/" <> tag,
      )
    GitLab ->
      api_request(
        "gitlab.com",
        "/api/v4/projects/"
          <> string.replace(repo.owner, "/", "%2F")
          <> "%2F"
          <> repo.repo
          <> "/repository/tags/"
          <> tag,
      )
    Codeberg ->
      api_request(
        "codeberg.org",
        "/api/v1/repos/" <> repo.owner <> "/" <> repo.repo <> "/tags/" <> tag,
      )
  }
}

/// Read a GitHub annotated tag object, not a branch or an unqualified ref.
pub fn annotated_tag_request(repo: Repository, sha: String) -> Request(String) {
  api_request(
    "api.github.com",
    "/repos/"
      <> repo.owner
      <> "/"
      <> repo.repo
      <> "/git/tags/"
      <> uri.percent_encode(sha),
  )
}

pub fn decode_tag_target(body: String) -> Result(TagTarget, Nil) {
  let decoder = {
    use kind <- decode.field("type", decode.string)
    use sha <- decode.field("sha", decode.string)
    decode.success(#(kind, sha))
  }
  use #(kind, sha) <- result.try(
    json.parse(body, decode.field("object", decoder, decode.success))
    |> result.replace_error(Nil),
  )
  case kind, sha {
    _, "" -> Error(Nil)
    "commit", _ -> Ok(Commit(sha))
    "tag", _ -> Ok(AnnotatedTag(sha))
    _, _ -> Error(Nil)
  }
}

fn api_request(host: String, path: String) -> Request(String) {
  Request(
    method: Get,
    headers: [#("accept", "application/json")],
    body: "",
    scheme: Https,
    host: host,
    port: None,
    path: path,
    query: None,
  )
}

/// Decode a commit-resolution response body into a commit SHA. Returns
/// `Error(Nil)` when the body does not contain the provider's SHA field (e.g. a
/// 404 body or malformed JSON), which the caller treats as "tag not found".
pub fn decode_commit(repo: Repository, body: String) -> Result(String, Nil) {
  case repo.provider {
    GitHub ->
      case decode_tag_target(body) {
        Ok(Commit(sha)) -> Ok(sha)
        Ok(AnnotatedTag(_)) | Error(Nil) -> Error(Nil)
      }
    GitLab | Codeberg -> decode_provider_commit(repo.provider, body)
  }
}

fn decode_provider_commit(
  provider: Provider,
  body: String,
) -> Result(String, Nil) {
  json.parse(body, commit_decoder(provider))
  |> result.replace_error(Nil)
  |> result.try(fn(sha) {
    case sha {
      "" -> Error(Nil)
      _ -> Ok(sha)
    }
  })
}

fn commit_decoder(provider: Provider) -> decode.Decoder(String) {
  case provider {
    GitHub | Codeberg ->
      decode.field(
        "commit",
        decode.field("sha", decode.string, decode.success),
        decode.success,
      )
    GitLab ->
      decode.field(
        "commit",
        decode.field("id", decode.string, decode.success),
        decode.success,
      )
  }
}

/// Build the request that downloads the gzip-compressed tar archive of `repo`
/// at an immutable `commit`.
pub fn archive_request(repo: Repository, commit: String) -> Request(BitArray) {
  case repo.provider {
    GitHub ->
      archive_bits_request(
        "codeload.github.com",
        "/" <> repo.owner <> "/" <> repo.repo <> "/tar.gz/" <> commit,
      )
    GitLab ->
      archive_bits_request(
        "gitlab.com",
        "/"
          <> repo.owner
          <> "/"
          <> repo.repo
          <> "/-/archive/"
          <> commit
          <> "/"
          <> repo.repo
          <> "-"
          <> commit
          <> ".tar.gz",
      )
    Codeberg ->
      archive_bits_request(
        "codeberg.org",
        "/"
          <> repo.owner
          <> "/"
          <> repo.repo
          <> "/archive/"
          <> commit
          <> ".tar.gz",
      )
  }
}

fn archive_bits_request(host: String, path: String) -> Request(BitArray) {
  Request(
    method: Get,
    headers: [],
    body: <<>>,
    scheme: Https,
    host: host,
    port: None,
    path: path,
    query: None,
  )
}

fn contains_any(value: String, needles: List(String)) -> Bool {
  list.any(needles, fn(needle) { string.contains(value, needle) })
}

fn strip_prefix(value: String, prefix: String) -> Result(String, Nil) {
  use <- bool.guard(
    when: !string.starts_with(value, prefix),
    return: Error(Nil),
  )
  Ok(string.drop_start(value, string.length(prefix)))
}

fn drop_trailing_slash(value: String) -> String {
  use <- bool.guard(when: !string.ends_with(value, "/"), return: value)
  string.drop_end(value, 1)
}

fn drop_suffix(value: String, suffix: String) -> String {
  use <- bool.guard(when: !string.ends_with(value, suffix), return: value)
  string.drop_end(value, string.length(suffix))
}
