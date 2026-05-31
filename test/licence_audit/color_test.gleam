import gleam/string
import gleeunit/should
import licence_audit/color
import tty

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
  assert string.contains(color.mode_error_message(message), "rainbow")
}

pub fn resolve_always_is_enabled_test() {
  should.equal(color.resolve(color.Always), color.Palette(enabled: True))
}

pub fn resolve_never_is_disabled_test() {
  should.equal(color.resolve(color.Never), color.Palette(enabled: False))
}

pub fn resolve_with_color_level_auto_uses_tty_color_detection_test() {
  should.equal(
    color.resolve_with_color_level(color.Auto, tty.NoColor),
    color.Palette(enabled: False),
  )
  should.equal(
    color.resolve_with_color_level(color.Auto, tty.Basic),
    color.Palette(enabled: True),
  )
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
