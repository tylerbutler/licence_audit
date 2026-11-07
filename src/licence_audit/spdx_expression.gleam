//// SPDX expression syntax, independent of licence policy and text retrieval.
//// Identifiers are checked for syntax, not membership in the SPDX licence list.

import gleam/bool
import gleam/list
import gleam/result
import gleam/string

pub type Expression {
  Licence(id: String)
  With(licence: String, exception: String)
  And(left: Expression, right: Expression)
  Or(left: Expression, right: Expression)
}

pub type ParseError {
  InvalidExpression
  ExpressionTooLarge
  NestingTooDeep
}

/// Parse SPDX operators in precedence order: WITH, AND, OR.
/// Limit untrusted input to 64 KiB, 1024 tokens, and 64 nested parentheses.
pub fn parse(input: String) -> Result(Expression, ParseError) {
  use <- bool.guard(
    when: string.byte_size(input) > 65_536,
    return: Error(ExpressionTooLarge),
  )
  let tokens = tokenize(input)
  use <- bool.guard(
    when: list.length(tokens) > 1024,
    return: Error(ExpressionTooLarge),
  )
  use #(expression, remaining) <- result.try(parse_or(tokens, 0))
  case remaining {
    [] -> Ok(expression)
    _ -> Error(InvalidExpression)
  }
}

/// Split syntax tokens without validating the expression or its identifiers.
pub fn tokenize(input: String) -> List(String) {
  input
  |> string.replace("(", " ( ")
  |> string.replace(")", " ) ")
  |> string.replace("\t", " ")
  |> string.replace("\r", " ")
  |> string.replace("\n", " ")
  |> string.split(" ")
  |> list.filter(fn(token) { token != "" })
}

fn parse_or(
  tokens: List(String),
  depth: Int,
) -> Result(#(Expression, List(String)), ParseError) {
  use #(left, rest) <- result.try(parse_and(tokens, depth))
  parse_or_rest(left, rest, depth)
}

fn parse_or_rest(
  left: Expression,
  tokens: List(String),
  depth: Int,
) -> Result(#(Expression, List(String)), ParseError) {
  case tokens {
    ["OR", ..rest] -> {
      use #(right, rest) <- result.try(parse_and(rest, depth))
      parse_or_rest(Or(left, right), rest, depth)
    }
    _ -> Ok(#(left, tokens))
  }
}

fn parse_and(
  tokens: List(String),
  depth: Int,
) -> Result(#(Expression, List(String)), ParseError) {
  use #(left, rest) <- result.try(parse_primary(tokens, depth))
  parse_and_rest(left, rest, depth)
}

fn parse_and_rest(
  left: Expression,
  tokens: List(String),
  depth: Int,
) -> Result(#(Expression, List(String)), ParseError) {
  case tokens {
    ["AND", ..rest] -> {
      use #(right, rest) <- result.try(parse_primary(rest, depth))
      parse_and_rest(And(left, right), rest, depth)
    }
    _ -> Ok(#(left, tokens))
  }
}

fn parse_primary(
  tokens: List(String),
  depth: Int,
) -> Result(#(Expression, List(String)), ParseError) {
  case tokens {
    ["(", ..rest] -> {
      use <- bool.guard(when: depth >= 64, return: Error(NestingTooDeep))
      use #(expression, rest) <- result.try(parse_or(rest, depth + 1))
      case rest {
        [")", ..rest] -> Ok(#(expression, rest))
        _ -> Error(InvalidExpression)
      }
    }
    [licence, "WITH", exception, ..rest] ->
      case valid_licence(licence) && valid_identifier(exception) {
        True -> Ok(#(With(licence, exception), rest))
        False -> Error(InvalidExpression)
      }
    [licence, ..rest] ->
      case valid_licence(licence) {
        True -> Ok(#(Licence(licence), rest))
        False -> Error(InvalidExpression)
      }
    [] -> Error(InvalidExpression)
  }
}

fn valid_licence(id: String) -> Bool {
  case id {
    "LicenseRef-" <> reference -> identifier_characters(reference)
    "DocumentRef-" <> reference ->
      case string.split(reference, ":LicenseRef-") {
        [document, licence] ->
          identifier_characters(document) && identifier_characters(licence)
        _ -> False
      }
    _ -> {
      let id = case string.ends_with(id, "+") {
        True -> string.drop_end(id, 1)
        False -> id
      }
      valid_identifier(id)
    }
  }
}

fn valid_identifier(id: String) -> Bool {
  !list.contains(["AND", "OR", "WITH"], id) && identifier_characters(id)
}

fn identifier_characters(id: String) -> Bool {
  id != ""
  && list.all(string.to_graphemes(id), fn(character) {
    string.contains(
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-",
      character,
    )
  })
}
