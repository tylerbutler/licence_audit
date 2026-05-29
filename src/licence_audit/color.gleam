import gleam/bool
import gleam/string
import gleam_community/ansi
import tty

pub type Mode {
  Auto
  Always
  Never
}

pub type Palette {
  Palette(enabled: Bool)
}

pub fn for_enabled(enabled: Bool) -> Palette {
  Palette(enabled: enabled)
}

pub fn resolve(mode: Mode) -> Palette {
  case mode {
    Always -> Palette(enabled: True)
    Never -> Palette(enabled: False)
    Auto -> resolve_with_color_level(Auto, tty.detect_color_level(tty.Stdout))
  }
}

pub fn resolve_with_color_level(mode: Mode, level: tty.ColorLevel) -> Palette {
  case mode {
    Always -> Palette(enabled: True)
    Never -> Palette(enabled: False)
    Auto -> Palette(enabled: level != tty.NoColor)
  }
}

pub type ColorModeError {
  InvalidColorValue(String)
}

pub fn mode_from_string(value: String) -> Result(Mode, ColorModeError) {
  case string.lowercase(value) {
    "auto" -> Ok(Auto)
    "always" -> Ok(Always)
    "never" -> Ok(Never)
    other -> Error(InvalidColorValue(other))
  }
}

/// Human-readable description of an invalid `--color` value.
pub fn mode_error_message(error: ColorModeError) -> String {
  let InvalidColorValue(value) = error
  "invalid --color value: " <> value
}

pub fn green(palette: Palette, text: String) -> String {
  use <- bool.guard(when: !palette.enabled, return: text)
  ansi.green(text)
}

pub fn red(palette: Palette, text: String) -> String {
  use <- bool.guard(when: !palette.enabled, return: text)
  ansi.red(text)
}

pub fn yellow(palette: Palette, text: String) -> String {
  use <- bool.guard(when: !palette.enabled, return: text)
  ansi.yellow(text)
}

pub type SeverityLabel {
  CriticalSeverity
  HighSeverity
  MediumSeverity
  LowSeverity
  UnknownSeverityLabel
}

/// Render a fixed-width, color-coded severity tag suitable for the vulns
/// report. Width is constant (10 chars) regardless of color so columns
/// align with or without ANSI codes.
pub fn severity(palette: Palette, label: SeverityLabel) -> String {
  let text = case label {
    CriticalSeverity -> "[CRITICAL]"
    HighSeverity -> "[HIGH    ]"
    MediumSeverity -> "[MEDIUM  ]"
    LowSeverity -> "[LOW     ]"
    UnknownSeverityLabel -> "[UNKNOWN ]"
  }
  case palette.enabled {
    False -> text
    True ->
      case label {
        CriticalSeverity -> ansi.red(text)
        HighSeverity -> ansi.red(text)
        MediumSeverity -> ansi.yellow(text)
        LowSeverity -> ansi.yellow(text)
        UnknownSeverityLabel -> text
      }
  }
}
