import gleam/list
import licence_audit/semver

pub fn valid_semver_test() {
  [
    "0.0.0",
    "1.2.3",
    "1.2.3-alpha",
    "1.2.3-alpha.1",
    "1.2.3-0.3.7",
    "1.2.3-x.7.z.92",
    "1.2.3+build.4",
    "1.2.3-alpha+build.4",
    "999999999999999999999999999999.2.3",
  ]
  |> list.each(fn(version) {
    assert semver.is_valid(version)
  })
}

pub fn invalid_semver_test() {
  [
    "",
    "1",
    "1.2",
    "1.2.3.4",
    "01.2.3",
    "1.02.3",
    "1.2.03",
    "1.2.3-",
    "1.2.3-01",
    "1.2.3-alpha..1",
    "1.2.3+",
    "1.2.3+build..1",
    "1.2.x",
    ">=1.2.3",
    "v1.2.3",
    "1.2.3?qualifier=value",
    "1.2.3#subpath",
  ]
  |> list.each(fn(version) {
    assert !semver.is_valid(version)
  })
}
