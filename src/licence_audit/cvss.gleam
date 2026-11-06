import gleam/dynamic.{type Dynamic}

pub type Rating {
  None
  Low
  Medium
  High
  Critical
}

type Cvss

pub fn rating(vector: String) -> Result(Rating, Nil) {
  case parse(vector) {
    Ok(parsed) -> Ok(parsed_rating(parsed))
    Error(_) -> Error(Nil)
  }
}

// The cvss dependency is Erlang-only. Keep scoring in that parser rather than
// reimplementing CVSS rules or treating a vector string as a severity label.
@external(erlang, "cvss", "parse")
fn parse(vector: String) -> Result(Cvss, Dynamic)

// Read the parsed vector's rating from the same dependency and scoring rules.
@external(erlang, "cvss", "rating")
fn parsed_rating(cvss: Cvss) -> Rating
