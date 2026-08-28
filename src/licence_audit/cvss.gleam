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

@external(erlang, "cvss", "parse")
fn parse(vector: String) -> Result(Cvss, Dynamic)

@external(erlang, "cvss", "rating")
fn parsed_rating(cvss: Cvss) -> Rating
