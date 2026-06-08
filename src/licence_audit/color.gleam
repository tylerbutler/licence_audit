import gleam/string
import spruce
import spruce/box
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

/// Build the shared spruce rendering context for a palette. Color escapes are
/// emitted at the `Basic` level when the palette is enabled, and suppressed
/// entirely otherwise, so plain-text output stays byte-identical.
fn spruce_context(palette: Palette) -> spruce.Spruce {
  case palette.enabled {
    True -> spruce.with_color_level(tty.Basic)
    False -> spruce.no_color()
  }
}

fn fg(palette: Palette, color: style.Color, text: String) -> String {
  let sp = spruce_context(palette)
  style.render(sp, style.fg(style.new(), color), text)
}

pub fn green(palette: Palette, text: String) -> String {
  fg(palette, style.Green, text)
}

pub fn red(palette: Palette, text: String) -> String {
  fg(palette, style.Red, text)
}

pub fn yellow(palette: Palette, text: String) -> String {
  fg(palette, style.Yellow, text)
}

/// Render `text` in bold when color is enabled; plain text otherwise.
pub fn bold(palette: Palette, text: String) -> String {
  let sp = spruce_context(palette)
  style.render(sp, style.bold(style.new()), text)
}

/// Render `text` in bold and underlined when color is enabled; plain text otherwise.
pub fn bold_underline(palette: Palette, text: String) -> String {
  let sp = spruce_context(palette)
  let text_style =
    style.new()
    |> style.bold
    |> style.underline
  style.render(sp, text_style, text)
}

/// Render `text` dimmed when color is enabled; plain text otherwise.
pub fn dim(palette: Palette, text: String) -> String {
  let sp = spruce_context(palette)
  style.render(sp, style.dim(style.new()), text)
}

pub type DependencySection {
  ProductionDependencies
  DevelopmentDependencies
}

/// Render a dependency section title with scope-aware emphasis.
pub fn dependency_section_title(
  palette: Palette,
  section: DependencySection,
) -> String {
  let #(title, tint) = case section {
    ProductionDependencies -> #("PRODUCTION DEPENDENCIES", style.Green)
    DevelopmentDependencies -> #("DEVELOPMENT DEPENDENCIES", style.Cyan)
  }
  let sp = spruce_context(palette)
  let title_style =
    style.new()
    |> style.fg(tint)
    |> style.bold
    |> style.underline
  style.render(sp, title_style, title)
}

/// Frame `content` in a rounded box with a `title` in the top border. The box
/// borders are drawn (uncolored) even when the palette is disabled, so callers
/// get a consistent layout regardless of color support.
pub fn boxed(palette: Palette, title: String, content: String) -> String {
  let sp = spruce_context(palette)
  let options =
    box.options(title: title, color: style.Cyan)
    |> box.border(box.Rounded)
    |> box.padding(0, 1, 0, 1)
  box.render(sp, content, options)
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
    CriticalSeverity | HighSeverity -> fg(palette, style.Red, text)
    MediumSeverity | LowSeverity -> fg(palette, style.Yellow, text)
  }
}
