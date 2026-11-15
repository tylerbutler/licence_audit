//// Parse Hex's data-only Erlang term subset without interning atoms or
//// evaluating binary expressions. Keep byte strings distinct from /utf8 strings.

import gleam/bit_array
import gleam/bool
import gleam/dict.{type Dict}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string

type Value {
  Text(String)
  Sequence(List(Value))
  Tuple(List(Value))
  Ignored
}

pub fn decode(
  input: BitArray,
) -> Result(#(List(String), Option(String), List(#(String, String))), Nil) {
  use <- bool.guard(
    when: bit_array.byte_size(input) > 1_048_576
      || bit_array.bit_size(input) % 8 != 0,
    return: Error(Nil),
  )
  use fields <- result.try(fields(space(input), dict.new()))
  use licences <- result.try(case dict.get(fields, "licenses") {
    Ok(Sequence(values)) -> list.try_map(values, text)
    _ -> Error(Nil)
  })
  use description <- result.try(case dict.get(fields, "description") {
    Ok(Text(value)) -> Ok(Some(value))
    Error(Nil) -> Ok(None)
    _ -> Error(Nil)
  })
  use links <- result.try(case dict.get(fields, "links") {
    Ok(Sequence(values)) ->
      list.try_map(values, fn(value) {
        case value {
          Tuple([Text(label), Text(url)]) -> Ok(#(label, url))
          _ -> Error(Nil)
        }
      })
    Error(Nil) -> Ok([])
    _ -> Error(Nil)
  })
  Ok(#(licences, description, links))
}

fn text(value: Value) -> Result(String, Nil) {
  case value {
    Text(value) -> Ok(value)
    Sequence(_) | Tuple(_) | Ignored -> Error(Nil)
  }
}

fn fields(
  input: BitArray,
  entries: Dict(String, Value),
) -> Result(Dict(String, Value), Nil) {
  case input {
    <<>> -> Ok(entries)
    _ -> {
      use #(field, remaining) <- result.try(value(input, 0))
      case field, space(remaining) {
        Tuple([Text(key), entry]), <<".":utf8, rest:bytes>> -> {
          use <- bool.guard(
            when: dict.has_key(entries, key),
            return: Error(Nil),
          )
          fields(space(rest), dict.insert(entries, key, entry))
        }
        _, _ -> Error(Nil)
      }
    }
  }
}

fn value(input: BitArray, depth: Int) -> Result(#(Value, BitArray), Nil) {
  use <- bool.guard(when: depth > 64, return: Error(Nil))
  case input {
    <<"<<":utf8, rest:bytes>> -> binary_segments(space(rest), [])
    <<"[":utf8, rest:bytes>> -> {
      use #(values, rest) <- result.try(
        sequence(space(rest), 93, depth + 1, []),
      )
      Ok(#(Sequence(values), rest))
    }
    <<"{":utf8, rest:bytes>> -> {
      use #(values, rest) <- result.try(
        sequence(space(rest), 125, depth + 1, []),
      )
      Ok(#(Tuple(values), rest))
    }
    <<"\"":utf8, rest:bytes>> -> {
      use #(source, rest) <- result.try(quoted_source(rest))
      use _ <- result.try(quoted_characters(source, False, []))
      Ok(#(Ignored, rest))
    }
    <<first, rest:bytes>> if first >= 97 && first <= 122 ->
      Ok(#(Ignored, literal_tail(rest, False)))
    <<first, rest:bytes>> if first >= 48 && first <= 57 ->
      Ok(#(Ignored, literal_tail(rest, True)))
    _ -> Error(Nil)
  }
}

fn literal_tail(input: BitArray, number: Bool) -> BitArray {
  case input {
    <<character, rest:bytes>>
      if character >= 48
      && character <= 57
      || !number
      && {
        character >= 97
        && character <= 122
        || character >= 65
        && character <= 90
        || character == 95
        || character == 64
      }
    -> literal_tail(rest, number)
    _ -> input
  }
}

fn sequence(
  input: BitArray,
  end: Int,
  depth: Int,
  values: List(Value),
) -> Result(#(List(Value), BitArray), Nil) {
  case input {
    <<character, rest:bytes>> if character == end ->
      Ok(#(list.reverse(values), rest))
    _ -> {
      use #(entry, remaining) <- result.try(value(input, depth))
      sequence_after(space(remaining), end, depth, [entry, ..values])
    }
  }
}

fn sequence_after(
  input: BitArray,
  end: Int,
  depth: Int,
  values: List(Value),
) -> Result(#(List(Value), BitArray), Nil) {
  case input {
    <<character, rest:bytes>> if character == end ->
      Ok(#(list.reverse(values), rest))
    <<",":utf8, rest:bytes>> -> {
      use #(entry, remaining) <- result.try(value(space(rest), depth))
      sequence_after(space(remaining), end, depth, [entry, ..values])
    }
    _ -> Error(Nil)
  }
}

fn binary_segments(
  input: BitArray,
  segments: List(BitArray),
) -> Result(#(Value, BitArray), Nil) {
  case input, segments {
    <<">>":utf8, rest:bytes>>, [] -> Ok(#(Text(""), rest))
    <<">>":utf8, _:bytes>>, _ -> Error(Nil)
    _, _ -> {
      use #(segment, remaining) <- result.try(segment(input))
      case space(remaining) {
        <<">>":utf8, rest:bytes>> -> {
          use text <- result.try(
            [segment, ..segments]
            |> list.reverse
            |> bit_array.concat
            |> binary_text,
          )
          Ok(#(Text(text), rest))
        }
        <<",":utf8, rest:bytes>> ->
          binary_segments(space(rest), [segment, ..segments])
        _ -> Error(Nil)
      }
    }
  }
}

fn segment(input: BitArray) -> Result(#(BitArray, BitArray), Nil) {
  case input {
    <<"\"":utf8, rest:bytes>> -> {
      use #(source, remaining) <- result.try(quoted_source(rest))
      let #(unicode, rest) = case space(remaining) {
        <<"/utf8":utf8, rest:bytes>> -> #(True, rest)
        rest -> #(False, rest)
      }
      use characters <- result.try(quoted_characters(source, unicode, []))
      use encoded <- result.try(
        list.try_map(characters, encode_character(_, unicode)),
      )
      Ok(#(bit_array.concat(encoded), rest))
    }
    <<first, _:bytes>> if first >= 48 && first <= 57 -> {
      let #(byte, rest) = digits(input, 10, 3, 0)
      case byte <= 255 {
        True -> Ok(#(<<byte>>, rest))
        False -> Error(Nil)
      }
    }
    _ -> Error(Nil)
  }
}

fn encode_character(character: Int, unicode: Bool) -> Result(BitArray, Nil) {
  case unicode {
    True -> {
      use point <- result.try(string.utf_codepoint(character))
      Ok(<<point:utf8_codepoint>>)
    }
    False if character <= 255 -> Ok(<<character>>)
    False -> Error(Nil)
  }
}

fn quoted_source(input: BitArray) -> Result(#(BitArray, BitArray), Nil) {
  use rest <- result.try(after_quote(input))
  let length = bit_array.byte_size(input) - bit_array.byte_size(rest) - 1
  use source <- result.try(bit_array.slice(input, 0, length))
  Ok(#(source, rest))
}

fn after_quote(input: BitArray) -> Result(BitArray, Nil) {
  case input {
    <<"\"":utf8, rest:bytes>> -> Ok(rest)
    <<"\\":utf8, _, rest:bytes>> -> after_quote(rest)
    <<_, rest:bytes>> -> after_quote(rest)
    _ -> Error(Nil)
  }
}

fn quoted_characters(
  input: BitArray,
  unicode: Bool,
  characters: List(Int),
) -> Result(List(Int), Nil) {
  case input {
    <<>> -> Ok(list.reverse(characters))
    _ -> {
      use #(character, rest) <- result.try(case input {
        <<"\\":utf8, rest:bytes>> -> escape(rest, unicode)
        _ -> character(input, unicode)
      })
      // Erlang string literals exclude these two otherwise valid codepoints.
      use <- bool.guard(
        when: character == 0xFFFE || character == 0xFFFF,
        return: Error(Nil),
      )
      use _ <- result.try(string.utf_codepoint(character))
      quoted_characters(rest, unicode, [character, ..characters])
    }
  }
}

fn character(input: BitArray, unicode: Bool) -> Result(#(Int, BitArray), Nil) {
  case unicode, input {
    True, <<point:utf8_codepoint, rest:bytes>> ->
      Ok(#(string.utf_codepoint_to_int(point), rest))
    False, <<byte, rest:bytes>> -> Ok(#(byte, rest))
    _, _ -> Error(Nil)
  }
}

fn escape(input: BitArray, unicode: Bool) -> Result(#(Int, BitArray), Nil) {
  case input {
    <<"x{":utf8, rest:bytes>> -> hex_escape(rest, 0, False)
    <<"x":utf8, first, second, rest:bytes>> -> {
      use first <- result.try(digit(first, 16))
      use second <- result.try(digit(second, 16))
      Ok(#(first * 16 + second, rest))
    }
    <<"x":utf8, _:bytes>> -> Error(Nil)
    <<"^?":utf8, rest:bytes>> -> Ok(#(127, rest))
    <<"^":utf8, character, rest:bytes>>
      if character >= 64
      && character <= 95
      || character >= 97
      && character <= 122
    -> {
      Ok(#(character % 32, rest))
    }
    <<"^":utf8, _:bytes>> -> Error(Nil)
    <<first, _:bytes>> if first >= 48 && first <= 55 ->
      Ok(digits(input, 8, 3, 0))
    <<first, rest:bytes>> -> {
      let escaped = case first {
        98 -> 8
        100 -> 127
        101 -> 27
        102 -> 12
        110 -> 10
        114 -> 13
        115 -> 32
        116 -> 9
        118 -> 11
        _ -> first
      }
      case first < 128 || !unicode {
        True -> Ok(#(escaped, rest))
        False -> character(input, unicode)
      }
    }
    _ -> Error(Nil)
  }
}

fn hex_escape(
  input: BitArray,
  value: Int,
  has_digit: Bool,
) -> Result(#(Int, BitArray), Nil) {
  case input {
    <<"}":utf8, rest:bytes>> if has_digit -> Ok(#(value, rest))
    <<first, rest:bytes>> -> {
      use digit <- result.try(digit(first, 16))
      let value = value * 16 + digit
      use <- bool.guard(when: value > 0x10FFFF, return: Error(Nil))
      hex_escape(rest, value, True)
    }
    _ -> Error(Nil)
  }
}

fn digits(
  input: BitArray,
  base: Int,
  remaining: Int,
  value: Int,
) -> #(Int, BitArray) {
  case input, remaining {
    <<first, rest:bytes>>, remaining if remaining > 0 ->
      case digit(first, base) {
        Ok(digit) -> digits(rest, base, remaining - 1, value * base + digit)
        Error(Nil) -> #(value, input)
      }
    _, _ -> #(value, input)
  }
}

fn digit(character: Int, base: Int) -> Result(Int, Nil) {
  let value = case character {
    character if character >= 48 && character <= 57 -> character - 48
    character if character >= 65 && character <= 70 -> character - 65 + 10
    character if character >= 97 && character <= 102 -> character - 97 + 10
    _ -> base
  }
  case value < base {
    True -> Ok(value)
    False -> Error(Nil)
  }
}

fn binary_text(input: BitArray) -> Result(String, Nil) {
  case bit_array.to_string(input) {
    Ok(text) -> Ok(text)
    Error(Nil) -> latin1(input, [])
  }
}

fn latin1(input: BitArray, parts: List(BitArray)) -> Result(String, Nil) {
  case input {
    <<byte, rest:bytes>> -> {
      use point <- result.try(string.utf_codepoint(byte))
      latin1(rest, [<<point:utf8_codepoint>>, ..parts])
    }
    _ -> parts |> list.reverse |> bit_array.concat |> bit_array.to_string
  }
}

fn space(input: BitArray) -> BitArray {
  case input {
    <<character, rest:bytes>>
      if character == 32 || character == 9 || character == 10 || character == 13
    -> space(rest)
    <<"%":utf8, rest:bytes>> -> space(after_comment(rest))
    _ -> input
  }
}

fn after_comment(input: BitArray) -> BitArray {
  case input {
    <<"\n":utf8, rest:bytes>> -> rest
    <<_, rest:bytes>> -> after_comment(rest)
    _ -> input
  }
}
