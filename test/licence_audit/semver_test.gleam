import gleam/list
import gleam/order
import gleeunit/should
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

pub fn precedence_handles_prereleases_builds_and_large_numbers_test() -> Nil {
  use #(left, right, expected) <- list.each([
    #("1.2.0", "1.10.0", order.Lt),
    #("1.0.0-alpha.2", "1.0.0-alpha.10", order.Lt),
    #("1.0.0-alpha.10", "1.0.0-alpha.beta", order.Lt),
    #("1.0.0-alpha", "1.0.0-alpha.1", order.Lt),
    #("1.0.0-rc.1", "1.0.0", order.Lt),
    #("1.0.0+first", "1.0.0+second", order.Eq),
    #(
      "999999999999999999999999999999.0.0",
      "99999999999999999999999999999.0.0",
      order.Gt,
    ),
  ])
  should.equal(semver.compare(left, right), Ok(expected))
  should.equal(semver.compare(right, left), Ok(order.negate(expected)))
  should.equal(semver.compare(left, "not-a-version"), Error(Nil))
}
