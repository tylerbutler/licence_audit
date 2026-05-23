import envoy
import gleam/string
import gleeunit/should
import licence_audit/color

pub fn for_enabled_true_enables_palette_test() {
  should.equal(color.for_enabled(True), color.Palette(enabled: True))
}

pub fn for_enabled_false_disables_palette_test() {
  should.equal(color.for_enabled(False), color.Palette(enabled: False))
}

pub fn mode_from_string_parses_known_values_test() {
  should.equal(color.mode_from_string("auto"), Ok(color.Auto))
  should.equal(color.mode_from_string("always"), Ok(color.Always))
  should.equal(color.mode_from_string("never"), Ok(color.Never))
  should.equal(color.mode_from_string("ALWAYS"), Ok(color.Always))
}

pub fn mode_from_string_rejects_invalid_test() {
  let assert Error(message) = color.mode_from_string("rainbow")
  assert string.contains(message, "rainbow")
}

pub fn resolve_always_is_enabled_test() {
  should.equal(color.resolve(color.Always), color.Palette(enabled: True))
}

pub fn resolve_never_is_disabled_test() {
  should.equal(color.resolve(color.Never), color.Palette(enabled: False))
}

pub fn resolve_auto_disabled_when_no_color_set_test() {
  let prior = envoy.get("NO_COLOR")
  envoy.set("NO_COLOR", "1")

  let palette = color.resolve(color.Auto)
  restore_no_color(prior)

  should.equal(palette, color.Palette(enabled: False))
}

pub fn resolve_auto_enabled_when_no_color_unset_test() {
  let prior = envoy.get("NO_COLOR")
  envoy.unset("NO_COLOR")

  let palette = color.resolve(color.Auto)
  restore_no_color(prior)

  should.equal(palette, color.Palette(enabled: True))
}

pub fn resolve_auto_enabled_when_no_color_empty_test() {
  let prior = envoy.get("NO_COLOR")
  envoy.set("NO_COLOR", "")

  let palette = color.resolve(color.Auto)
  restore_no_color(prior)

  should.equal(palette, color.Palette(enabled: True))
}

pub fn enabled_palette_wraps_text_with_ansi_test() {
  let palette = color.for_enabled(True)

  assert color.green(palette, "ok") != "ok"
  assert color.red(palette, "no") != "no"
  assert color.yellow(palette, "?") != "?"
}

pub fn disabled_palette_passes_through_test() {
  let palette = color.for_enabled(False)

  should.equal(color.green(palette, "ok"), "ok")
  should.equal(color.red(palette, "no"), "no")
  should.equal(color.yellow(palette, "?"), "?")
}

fn restore_no_color(prior: Result(String, Nil)) -> Nil {
  case prior {
    Ok(value) -> envoy.set("NO_COLOR", value)
    Error(_) -> envoy.unset("NO_COLOR")
  }
}
