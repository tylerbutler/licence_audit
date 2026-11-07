import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string
import gleeunit/should
import glint
import glint/constraint
import snag

fn optional_app(flag: glint.Flag(a)) -> glint.Glint(snag.Result(Option(a))) {
  glint.new()
  |> glint.add(at: [], do: {
    use value <- glint.optional_flag(flag)
    use _, _, flags <- glint.command()
    value(flags)
  })
}

fn assert_optional_value(
  flag: glint.Flag(a),
  args: List(String),
  expected: Option(a),
) -> Nil {
  optional_app(flag)
  |> glint.execute(args)
  |> should.equal(Ok(glint.Out(Ok(expected))))
}

pub fn omitted_optional_flags_return_none_for_every_type_test() -> Nil {
  assert_optional_value(glint.string_flag("value"), [], None)
  assert_optional_value(glint.int_flag("value"), [], None)
  assert_optional_value(glint.float_flag("value"), [], None)
  assert_optional_value(glint.bool_flag("value"), [], None)
  assert_optional_value(glint.strings_flag("value"), [], None)
  assert_optional_value(glint.ints_flag("value"), [], None)
  assert_optional_value(glint.floats_flag("value"), [], None)
}

pub fn supplied_optional_flags_return_some_for_every_type_test() -> Nil {
  assert_optional_value(
    glint.string_flag("value"),
    ["--value=file.txt"],
    Some("file.txt"),
  )
  assert_optional_value(glint.int_flag("value"), ["--value=0"], Some(0))
  assert_optional_value(glint.float_flag("value"), ["--value=2.5"], Some(2.5))
  assert_optional_value(
    glint.bool_flag("value"),
    ["--value=false"],
    Some(False),
  )
  assert_optional_value(
    glint.strings_flag("value"),
    ["--value=a,b"],
    Some(["a", "b"]),
  )
  assert_optional_value(glint.ints_flag("value"), ["--value=1,2"], Some([1, 2]))
  assert_optional_value(
    glint.floats_flag("value"),
    ["--value=1.0,2.5"],
    Some([1.0, 2.5]),
  )
}

pub fn explicit_empty_optional_string_is_not_absent_test() -> Nil {
  assert_optional_value(glint.string_flag("value"), ["--value="], Some(""))
}

pub fn optional_string_preserves_equals_in_value_test() -> Nil {
  assert_optional_value(
    glint.string_flag("value"),
    ["--value=a=b"],
    Some("a=b"),
  )
}

pub fn optional_flags_preserve_defaults_test() -> Nil {
  assert_optional_value(
    glint.string_flag("value") |> glint.flag_default("fallback"),
    [],
    Some("fallback"),
  )
  assert_optional_value(
    glint.bool_flag("value") |> glint.flag_default(False),
    [],
    Some(False),
  )
  assert_optional_value(
    glint.strings_flag("value") |> glint.flag_default([]),
    [],
    Some([]),
  )
  assert_optional_value(
    glint.string_flag("value") |> glint.flag_default("fallback"),
    ["--value=provided"],
    Some("provided"),
  )
}

pub fn optional_bool_preserves_toggle_behavior_test() -> Nil {
  assert_optional_value(glint.bool_flag("value"), ["--value"], Some(True))
  assert_optional_value(
    glint.bool_flag("value") |> glint.flag_default(True),
    ["--value"],
    Some(False),
  )
}

pub fn supplied_optional_flag_without_value_is_an_error_test() -> Nil {
  let assert Error(message) =
    optional_app(glint.string_flag("value"))
    |> glint.execute(["--value"])

  string.contains(message, "has no assigned value")
  |> should.be_true()
}

pub fn optional_flags_reject_invalid_input_before_running_test() -> Nil {
  let command = {
    use _value <- glint.optional_flag(glint.int_flag("value"))
    use _, _, _ <- glint.command()
    panic as "invalid input must not run the command"
  }

  glint.new()
  |> glint.add(at: [], do: command)
  |> glint.execute(["--value=invalid"])
  |> should.be_error()

  optional_app(glint.bool_flag("value"))
  |> glint.execute(["--value=invalid"])
  |> should.be_error()

  optional_app(glint.float_flag("value"))
  |> glint.execute(["--value=invalid"])
  |> should.be_error()

  optional_app(glint.ints_flag("value"))
  |> glint.execute(["--value=1,invalid"])
  |> should.be_error()

  optional_app(glint.floats_flag("value"))
  |> glint.execute(["--value=1.0,invalid"])
  |> should.be_error()

  Nil
}

pub fn optional_flag_constraints_apply_only_to_supplied_values_test() -> Nil {
  let flag =
    glint.string_flag("severity")
    |> glint.flag_constraint(constraint.one_of(["low", "high"]))

  assert_optional_value(flag, [], None)
  assert_optional_value(flag, ["--severity=high"], Some("high"))

  let assert Error(message) =
    optional_app(flag) |> glint.execute(["--severity="])
  string.contains(message, "must be one of")
  |> should.be_true()

  optional_app(flag)
  |> glint.execute(["--severity=invalid"])
  |> should.be_error()

  Nil
}

pub fn optional_group_flags_are_inherited_test() -> Nil {
  let flag = glint.string_flag("output")
  let app =
    glint.new()
    |> glint.group_flag(at: [], of: flag)
    |> glint.add(at: ["export"], do: {
      use _, _, flags <- glint.command()
      glint.get_optional_flag(flags, flag)
    })

  app
  |> glint.execute(["export"])
  |> should.equal(Ok(glint.Out(Ok(None))))

  app
  |> glint.execute(["export", "--output=file.txt"])
  |> should.equal(Ok(glint.Out(Ok(Some("file.txt")))))

  app
  |> glint.group_flag(at: [], of: glint.flag_default(flag, "fallback.txt"))
  |> glint.execute(["export"])
  |> should.equal(Ok(glint.Out(Ok(Some("fallback.txt")))))
}

pub fn optional_local_flag_overrides_group_default_test() -> Nil {
  let app =
    glint.new()
    |> glint.group_flag(
      at: [],
      of: glint.string_flag("output") |> glint.flag_default("group.txt"),
    )
    |> glint.add(at: [], do: {
      use output <- glint.optional_flag(glint.string_flag("output"))
      use _, _, flags <- glint.command()
      output(flags)
    })

  app
  |> glint.execute([])
  |> should.equal(Ok(glint.Out(Ok(None))))
}

pub fn optional_group_getter_preserves_errors_test() -> Nil {
  let string_flag = glint.string_flag("value")
  let command = {
    use _, _, flags <- glint.command()
    glint.get_optional_flag(flags, string_flag)
  }

  let assert Ok(glint.Out(Error(missing))) =
    glint.new()
    |> glint.add(at: [], do: command)
    |> glint.execute([])

  string.contains(snag.pretty_print(missing), "flag provided but not defined")
  |> should.be_true()

  [glint.int_flag("value"), glint.int_flag("value") |> glint.flag_default(1)]
  |> list.each(fn(flag) {
    let assert Ok(glint.Out(Error(wrong_type))) =
      glint.new()
      |> glint.group_flag(at: [], of: flag)
      |> glint.add(at: [], do: command)
      |> glint.execute([])

    string.contains(
      snag.pretty_print(wrong_type),
      "cannot access flag as string",
    )
    |> should.be_true()
  })
}

fn assert_required_flag_still_errors(flag: glint.Flag(a)) -> Nil {
  let assert Ok(glint.Out(Error(error))) =
    glint.new()
    |> glint.add(at: [], do: {
      use value <- glint.flag(flag)
      use _, _, flags <- glint.command()
      value(flags)
    })
    |> glint.execute([])

  let message = snag.pretty_print(error)
  string.contains(message, "no value provided")
  |> should.be_true()
  string.contains(message, "failed to retrieve value for flag 'value'")
  |> should.be_true()
}

pub fn existing_getters_still_error_when_omitted_for_every_type_test() -> Nil {
  assert_required_flag_still_errors(glint.string_flag("value"))
  assert_required_flag_still_errors(glint.int_flag("value"))
  assert_required_flag_still_errors(glint.float_flag("value"))
  assert_required_flag_still_errors(glint.bool_flag("value"))
  assert_required_flag_still_errors(glint.strings_flag("value"))
  assert_required_flag_still_errors(glint.ints_flag("value"))
  assert_required_flag_still_errors(glint.floats_flag("value"))
}
