import gleam/string
import spruce
import spruce/style
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

fn paint(enabled: Bool, color: style.Color, text: String) -> String {
  let sp = case enabled {
    True -> spruce.with_color_level(tty.Basic)
    False -> spruce.no_color()
  }
  style.render(sp, style.fg(style.new(), color), text)
}

pub fn green(palette: Palette, text: String) -> String {
  paint(palette.enabled, style.Green, text)
}

pub fn red(palette: Palette, text: String) -> String {
  paint(palette.enabled, style.Red, text)
}

pub fn yellow(palette: Palette, text: String) -> String {
  paint(palette.enabled, style.Yellow, text)
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
  case label {
    UnknownSeverityLabel -> text
    CriticalSeverity | HighSeverity -> paint(palette.enabled, style.Red, text)
    MediumSeverity | LowSeverity -> paint(palette.enabled, style.Yellow, text)
  }
}
