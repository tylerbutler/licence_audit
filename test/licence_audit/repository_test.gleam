import gleeunit/should
import licence_audit/repository

pub fn parses_github_url_test() {
  should.equal(
    repository.parse("https://github.com/owner/repo"),
    Ok(repository.Repository(repository.GitHub, "owner", "repo")),
  )
}

pub fn parses_gitlab_url_test() {
  should.equal(
    repository.parse("https://gitlab.com/owner/repo"),
    Ok(repository.Repository(repository.GitLab, "owner", "repo")),
  )
}

pub fn parses_gitlab_subgroup_url_test() {
  should.equal(
    repository.parse("https://gitlab.com/group/subgroup/repo"),
    Ok(repository.Repository(repository.GitLab, "group/subgroup", "repo")),
  )
}

pub fn parses_codeberg_url_test() {
  should.equal(
    repository.parse("https://codeberg.org/owner/repo"),
    Ok(repository.Repository(repository.Codeberg, "owner", "repo")),
  )
}

pub fn strips_trailing_git_and_slash_test() {
  should.equal(
    repository.parse("https://github.com/owner/repo.git"),
    Ok(repository.Repository(repository.GitHub, "owner", "repo")),
  )
  should.equal(
    repository.parse("https://github.com/owner/repo/"),
    Ok(repository.Repository(repository.GitHub, "owner", "repo")),
  )
  should.equal(
    repository.parse("https://github.com/owner/repo.git/"),
    Ok(repository.Repository(repository.GitHub, "owner", "repo")),
  )
}

pub fn rejects_non_https_scheme_test() {
  should.equal(repository.parse("http://github.com/owner/repo"), Error(Nil))
  should.equal(repository.parse("git@github.com:owner/repo.git"), Error(Nil))
}

pub fn rejects_unknown_host_test() {
  should.equal(repository.parse("https://example.com/owner/repo"), Error(Nil))
  should.equal(
    repository.parse("https://raw.githubusercontent.com/owner/repo"),
    Error(Nil),
  )
}

pub fn rejects_userinfo_port_query_fragment_test() {
  should.equal(
    repository.parse("https://user@github.com/owner/repo"),
    Error(Nil),
  )
  should.equal(
    repository.parse("https://github.com:443/owner/repo"),
    Error(Nil),
  )
  should.equal(
    repository.parse("https://github.com/owner/repo?ref=main"),
    Error(Nil),
  )
  should.equal(
    repository.parse("https://github.com/owner/repo#readme"),
    Error(Nil),
  )
}

pub fn rejects_extra_path_segments_test() {
  should.equal(
    repository.parse("https://github.com/owner/repo/tree/main"),
    Error(Nil),
  )
  should.equal(repository.parse("https://github.com/owner"), Error(Nil))
}

pub fn rejects_non_normalized_segments_test() {
  // Percent escapes, backslashes, colons, and control characters are rejected.
  should.equal(repository.parse("https://github.com/owner/re%2Fpo"), Error(Nil))
  should.equal(repository.parse("https://github.com/owner/re\\po"), Error(Nil))
  should.equal(repository.parse("https://github.com/owner/re:po"), Error(Nil))
  should.equal(repository.parse("https://github.com/ow\tner/repo"), Error(Nil))
  // Dot segments cannot appear as an owner or repo.
  should.equal(repository.parse("https://github.com/./repo"), Error(Nil))
  should.equal(repository.parse("https://github.com/owner/.."), Error(Nil))
}

pub fn accepts_dotted_hyphenated_names_test() {
  // Ordinary names with dots, hyphens, and underscores stay valid.
  should.equal(
    repository.parse("https://github.com/socketio/socket.io"),
    Ok(repository.Repository(repository.GitHub, "socketio", "socket.io")),
  )
  should.equal(
    repository.parse("https://github.com/my-org/my_repo.gleam"),
    Ok(repository.Repository(repository.GitHub, "my-org", "my_repo.gleam")),
  )
}

pub fn tag_candidates_prefers_v_prefix_test() {
  should.equal(repository.tag_candidates("1.2.3"), ["v1.2.3", "1.2.3"])
}

pub fn commit_request_targets_provider_api_test() {
  let github = repository.Repository(repository.GitHub, "o", "r")
  let request = repository.commit_request(github, "v1.0.0")
  should.equal(request.host, "api.github.com")
  should.equal(request.path, "/repos/o/r/commits/v1.0.0")

  let gitlab = repository.Repository(repository.GitLab, "o", "r")
  should.equal(
    repository.commit_request(gitlab, "v1.0.0").path,
    "/api/v4/projects/o%2Fr/repository/commits/v1.0.0",
  )

  let subgroup = repository.Repository(repository.GitLab, "o/sub", "r")
  should.equal(
    repository.commit_request(subgroup, "v1.0.0").path,
    "/api/v4/projects/o%2Fsub%2Fr/repository/commits/v1.0.0",
  )

  let codeberg = repository.Repository(repository.Codeberg, "o", "r")
  should.equal(
    repository.commit_request(codeberg, "v1.0.0").path,
    "/api/v1/repos/o/r/tags/v1.0.0",
  )
}

pub fn decode_commit_reads_provider_shape_test() {
  let github = repository.Repository(repository.GitHub, "o", "r")
  should.equal(
    repository.decode_commit(github, "{\"sha\":\"abc123\"}"),
    Ok("abc123"),
  )

  let gitlab = repository.Repository(repository.GitLab, "o", "r")
  should.equal(
    repository.decode_commit(gitlab, "{\"id\":\"def456\"}"),
    Ok("def456"),
  )

  let codeberg = repository.Repository(repository.Codeberg, "o", "r")
  should.equal(
    repository.decode_commit(codeberg, "{\"commit\":{\"sha\":\"ghi789\"}}"),
    Ok("ghi789"),
  )
}

pub fn decode_commit_missing_field_is_error_test() {
  let github = repository.Repository(repository.GitHub, "o", "r")
  should.equal(
    repository.decode_commit(github, "{\"message\":\"Not Found\"}"),
    Error(Nil),
  )
}

pub fn archive_request_targets_provider_download_test() {
  let github = repository.Repository(repository.GitHub, "o", "r")
  let request = repository.archive_request(github, "sha")
  should.equal(request.host, "codeload.github.com")
  should.equal(request.path, "/o/r/tar.gz/sha")

  let gitlab = repository.Repository(repository.GitLab, "o", "r")
  should.equal(
    repository.archive_request(gitlab, "sha").path,
    "/o/r/-/archive/sha/r-sha.tar.gz",
  )

  let subgroup = repository.Repository(repository.GitLab, "o/sub", "r")
  should.equal(
    repository.archive_request(subgroup, "sha").path,
    "/o/sub/r/-/archive/sha/r-sha.tar.gz",
  )

  let codeberg = repository.Repository(repository.Codeberg, "o", "r")
  should.equal(
    repository.archive_request(codeberg, "sha").path,
    "/o/r/archive/sha.tar.gz",
  )
}
