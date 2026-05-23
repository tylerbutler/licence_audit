import envoy
import gleam/string
import gleam_community/ansi

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
    Auto -> Palette(enabled: !no_color_set())
  }
}

pub fn mode_from_string(value: String) -> Result(Mode, String) {
  case string.lowercase(value) {
    "auto" -> Ok(Auto)
    "always" -> Ok(Always)
    "never" -> Ok(Never)
    other -> Error("invalid --color value: " <> other)
  }
}

pub fn green(palette: Palette, text: String) -> String {
  case palette.enabled {
    True -> ansi.green(text)
    False -> text
  }
}

pub fn red(palette: Palette, text: String) -> String {
  case palette.enabled {
    True -> ansi.red(text)
    False -> text
  }
}

pub fn yellow(palette: Palette, text: String) -> String {
  case palette.enabled {
    True -> ansi.yellow(text)
    False -> text
  }
}

fn no_color_set() -> Bool {
  case envoy.get("NO_COLOR") {
    Ok(value) -> value != ""
    Error(_) -> False
  }
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
