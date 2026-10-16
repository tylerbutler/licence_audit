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

pub fn backported_getters_preserve_absence_for_every_type_test() -> Nil {
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

pub fn backported_group_getters_preserve_defaults_and_values_test() -> Nil {
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
