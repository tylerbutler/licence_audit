import gleam/option.{type Option, None, Some}
import gleam/string
import gleeunit/should
import licence_audit/internal/vendor/glint
import snag

fn assert_optional_and_required_getters(flag: glint.Flag(a)) -> Nil {
  glint.new()
  |> glint.add(at: [], do: {
    use value <- glint.optional_flag(flag)
    use _, _, flags <- glint.command()
    value(flags)
  })
  |> glint.execute([])
  |> should.equal(Ok(glint.Out(Ok(None))))

  let assert Ok(glint.Out(Error(error))) =
    glint.new()
    |> glint.add(at: [], do: {
      use value <- glint.flag(flag)
      use _, _, flags <- glint.command()
      value(flags)
    })
    |> glint.execute([])

  snag.pretty_print(error)
  |> string.contains("no value provided")
  |> should.be_true()
}

pub fn optional_getters_preserve_absence_for_every_type_test() -> Nil {
  assert_optional_and_required_getters(glint.string_flag("value"))
  assert_optional_and_required_getters(glint.int_flag("value"))
  assert_optional_and_required_getters(glint.float_flag("value"))
  assert_optional_and_required_getters(glint.bool_flag("value"))
  assert_optional_and_required_getters(glint.strings_flag("value"))
  assert_optional_and_required_getters(glint.ints_flag("value"))
  assert_optional_and_required_getters(glint.floats_flag("value"))
}

fn optional_group_app(
  flag: glint.Flag(String),
) -> glint.Glint(snag.Result(Option(String))) {
  glint.new()
  |> glint.group_flag(at: [], of: flag)
  |> glint.add(at: ["export"], do: {
    use _, _, flags <- glint.command()
    glint.get_optional_flag(flags, flag)
  })
}

pub fn optional_group_getters_preserve_defaults_and_values_test() -> Nil {
  let flag = glint.string_flag("output")

  optional_group_app(flag)
  |> glint.execute(["export"])
  |> should.equal(Ok(glint.Out(Ok(None))))

  optional_group_app(glint.flag_default(flag, "fallback.txt"))
  |> glint.execute(["export"])
  |> should.equal(Ok(glint.Out(Ok(Some("fallback.txt")))))

  optional_group_app(flag)
  |> glint.execute(["export", "--output="])
  |> should.equal(Ok(glint.Out(Ok(Some("")))))
}

pub fn detailed_execution_preserves_input_and_command_context_test() {
  let app =
    glint.new()
    |> glint.add(at: ["group", "run"], do: {
      use <- glint.unnamed_args(glint.EqArgs(0))
      use _ <- glint.optional_flag(glint.int_flag("count"))
      use _, _, _ <- glint.command()
      Nil
    })
  let assert Error(unknown) =
    glint.execute_detailed(app, ["group", "run", "--unknown=literal"])
  should.equal(unknown.command_path, ["group", "run"])
  should.equal(unknown.cause, glint.UnknownFlag("unknown", "--unknown=literal"))
  let assert Error(missing) =
    glint.execute_detailed(app, ["group", "run", "--count"])
  should.equal(missing.cause, glint.MissingFlagValue("count", "--count"))
  let assert Error(invalid) =
    glint.execute_detailed(app, ["group", "run", "--count=--help"])
  should.equal(
    invalid.cause,
    glint.InvalidFlagValue("count", "--help", "--count=--help"),
  )
  let assert Error(extra) =
    glint.execute_detailed(app, ["group", "run", "extra", "--help"])
  should.equal(extra.command_path, ["group", "run"])
  should.equal(
    extra.cause,
    glint.InvalidArgumentCount(glint.EqArgs(0), ["extra"]),
  )
  let assert Ok(glint.Help(_)) =
    glint.execute(app, ["group", "run", "extra", "--help"])
  let assert Ok(glint.Help(_)) =
    glint.execute_detailed(app, ["group", "run", "--unknown", "--help"])
  let assert Error(legacy) = glint.execute(app, ["group", "run", "--count"])
  assert string.contains(legacy, "has no assigned value")
  assert string.contains(legacy, "USAGE:")
}

pub fn detailed_execution_retains_custom_constraint_and_runner_results_test() {
  let app =
    glint.new()
    |> glint.add(at: [], do: {
      use _ <- glint.optional_flag(
        glint.string_flag("value")
        |> glint.flag_constraint(fn(_) {
          snag.error("custom constraint failure")
        }),
      )
      use _, _, _ <- glint.command()
      Error("runner failure")
    })
  let assert Error(error) = glint.execute_detailed(app, ["--value=raw"])
  should.equal(
    error.cause,
    glint.InvalidFlagValue("value", "raw", "--value=raw"),
  )
  assert string.contains(
    snag.pretty_print(error.diagnostic),
    "custom constraint failure",
  )
  should.equal(
    glint.execute_detailed(app, []),
    Ok(glint.Out(Error("runner failure"))),
  )
}
