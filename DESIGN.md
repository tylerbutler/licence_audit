---
name: licence_audit
description: The Gleam-native supply-chain auditor — licences, SBOM, and vulns in one small CLI.
colors:
  # Brand — warm pink (the Gleam nod, deepened for contrast)
  pink: "oklch(0.66 0.19 352)"
  pink-hover: "oklch(0.60 0.205 352)"
  pink-link: "oklch(0.52 0.205 353)"
  pink-soft: "oklch(0.94 0.045 350)"
  pink-softer: "oklch(0.975 0.02 350)"
  pink-bright: "oklch(0.82 0.13 350)"
  # Ground — calm true off-white (not warm cream)
  bg: "oklch(0.985 0.004 340)"
  bg-sunken: "oklch(0.966 0.007 340)"
  surface: "oklch(1 0 0)"
  border: "oklch(0.905 0.008 340)"
  border-strong: "oklch(0.83 0.012 340)"
  # Ink — near-black with a whisper of plum
  ink: "oklch(0.25 0.02 335)"
  ink-2: "oklch(0.40 0.018 335)"
  ink-muted: "oklch(0.505 0.016 335)"
  # Semantic status roles on light surfaces (echo the CLI glyphs)
  pass-ink: "oklch(0.50 0.13 155)"
  deny-ink: "oklch(0.515 0.21 25)"
  muted-ink: "oklch(0.52 0.015 320)"
  pass-soft: "oklch(0.94 0.05 155)"
  deny-soft: "oklch(0.945 0.05 25)"
  # Terminal — the one dark surface
  term-bg: "oklch(0.215 0.022 320)"
  term-bar: "oklch(0.275 0.022 320)"
  term-border: "oklch(0.33 0.02 320)"
  term-fg: "oklch(0.925 0.008 320)"
  term-dim: "oklch(0.68 0.012 320)"
  term-pass: "oklch(0.82 0.16 150)"
  term-deny: "oklch(0.72 0.19 22)"
  term-muted: "oklch(0.66 0.012 320)"
typography:
  display:
    fontFamily: "Fraunces Variable, Georgia, serif"
    fontSize: "clamp(2.5rem, 1.55rem + 4.4vw, 4.5rem)"
    fontWeight: 700
    lineHeight: 1.08
    letterSpacing: "-0.01em"
  headline:
    fontFamily: "Fraunces Variable, Georgia, serif"
    fontSize: "clamp(1.6rem, 1.34rem + 1.25vw, 2.25rem)"
    fontWeight: 700
    lineHeight: 1.08
    letterSpacing: "-0.01em"
  title:
    fontFamily: "Fraunces Variable, Georgia, serif"
    fontSize: "clamp(1.25rem, 1.14rem + 0.5vw, 1.5rem)"
    fontWeight: 700
    lineHeight: 1.25
    letterSpacing: "normal"
  body:
    fontFamily: "Hanken Grotesk Variable, system-ui, sans-serif"
    fontSize: "1.0625rem"
    fontWeight: 400
    lineHeight: 1.62
    letterSpacing: "normal"
  label:
    fontFamily: "Hanken Grotesk Variable, system-ui, sans-serif"
    fontSize: "0.8125rem"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "0.09em"
  mono:
    fontFamily: "JetBrains Mono Variable, ui-monospace, monospace"
    fontSize: "0.9rem"
    fontWeight: 400
    lineHeight: 1.75
    letterSpacing: "normal"
rounded:
  sm: "6px"
  md: "10px"
  lg: "16px"
  xl: "22px"
  full: "999px"
spacing:
  "2": "0.5rem"
  "3": "0.75rem"
  "4": "1rem"
  "5": "1.5rem"
  "6": "2rem"
  "7": "3rem"
  "8": "4rem"
  "9": "6rem"
components:
  button-primary:
    backgroundColor: "{colors.pink}"
    textColor: "oklch(0.2 0.02 335)"
    rounded: "{rounded.full}"
    padding: "0.85rem 1.5rem"
  button-primary-hover:
    backgroundColor: "{colors.pink-hover}"
    textColor: "oklch(0.2 0.02 335)"
    rounded: "{rounded.full}"
    padding: "0.85rem 1.5rem"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.full}"
    padding: "0.85rem 1.5rem"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.ink-2}"
    rounded: "{rounded.full}"
    padding: "0.85rem 1.5rem"
  badge:
    backgroundColor: "{colors.pink-soft}"
    textColor: "{colors.pink-link}"
    rounded: "{rounded.full}"
    padding: "0.35rem 0.75rem"
  nav-link-active:
    backgroundColor: "{colors.pink-soft}"
    textColor: "{colors.pink-link}"
    rounded: "{rounded.sm}"
    padding: "0.4rem 0.7rem"
  terminal:
    backgroundColor: "{colors.term-bg}"
    textColor: "{colors.term-fg}"
    rounded: "{rounded.lg}"
    typography: "{typography.mono}"
---

# Design System: licence_audit

## 1. Overview

**Creative North Star: "The Honest Terminal"**

licence_audit tells you the truth about your dependencies, warmly — and the
website is that same terminal rendered as a page. The system runs on a calm,
readable off-white ground with a single dark terminal as its hero object, a warm
pink that nods to Gleam without impersonating it, and a status palette lifted
straight from the CLI's own report glyphs. Every colour means what it means in
the tool: green is `✓ allowed`, red is `✗ denied`, grey is `· skipped` / `?
unknown`. The design demonstrates the product instead of describing it.

The voice is playful and approachable but never sloppy. Confidence comes from
being clear and correct — real command output above the fold, predictable
spacing, high-contrast type — not from gravitas or decoration. It borrows the
warm CLI-brand personality of Charm and the crisp, code-forward directness of
Bun and Biome.

This system explicitly rejects the generic SaaS landing page (gradient hero,
three identical feature cards, a big-number stat band, purple-blue gradients)
and the corporate enterprise-security look (navy-and-gold compliance theatre,
stock photos of locks and shields, fear-based selling).

**Key Characteristics:**
- Warm pink (`oklch(0.66 0.19 352)`) as a deliberate Gleam nod, used as accent — never drenching.
- A semantic status palette (pass green / deny red / muted grey) drawn from the CLI's glyphs.
- Real terminal output as the hero, not abstract feature copy.
- One dark terminal surface on an otherwise flat, off-white page.
- Playful, approachable display type over an exacting, high-contrast reading experience.

## 2. Colors

A **full palette**: a warm pink brand voice, a small set of semantic status
roles that echo the CLI, and a calm off-white ground — plus one self-contained
dark terminal palette. All values are OKLCH; hues stay in the plum/pink band
(320–353) so neutrals and brand cohere.

### Primary
- **Warm Pink** (`oklch(0.66 0.19 352)`): the brand voice and the Gleam nod. Primary-button fields (with dark ink text), the logo mark, key accents, the hero glow.
- **Pink Link** (`oklch(0.52 0.205 353)`): the darker pink for link text and active nav on light surfaces — the AA-safe reading variant of the brand hue.
- **Pink Soft / Softer** (`oklch(0.94 0.045 350)` / `oklch(0.975 0.02 350)`): washes behind badges, active nav pills, inline `code`, and callouts.
- **Pink Bright** (`oklch(0.82 0.13 350)`): the pink used *on* the dark terminal — the prompt `$` and the typing caret.

### Secondary — Status roles (the tool's own vocabulary)
- **Pass Green** (`oklch(0.50 0.13 155)` light · `oklch(0.82 0.16 150)` terminal): the `✓ allowed` state and any passing affordance.
- **Deny Red** (`oklch(0.515 0.21 25)` light · `oklch(0.72 0.19 22)` terminal): the `✗ denied` state and violation affordances.

### Tertiary
- **Muted Grey** (`oklch(0.52 0.015 320)` light · `oklch(0.66 0.012 320)` terminal): the `· skipped` and `? unknown` states, plus secondary metadata.

### Neutral
- **Off-White Background** (`oklch(0.985 0.004 340)`): the calm page ground — a true off-white with a whisper of the brand hue, deliberately not a warm cream.
- **Sunken** (`oklch(0.966 0.007 340)`): recessed sections (workflow band, footer) and mobile nav pills.
- **Surface** (`oklch(1 0 0)`): lifted cards and the secondary button field.
- **Ink / Ink-2 / Ink-muted** (`oklch(0.25 0.02 335)` / `0.40` / `0.505`): headings & body / strong secondary / muted — the muted end still clears 4.5:1 on the background.
- **Border / Border-strong** (`oklch(0.905 0.008 340)` / `0.83`): hairlines and stronger dividers.

### Terminal palette
- **Terminal BG / Bar / Border** (`oklch(0.215 0.022 320)` / `0.275` / `0.33`): the dark surface, its title bar, and its edges — a deep plum-near-black, the brand hue carried into the dark.
- **Terminal FG / Dim** (`oklch(0.925 0.008 320)` / `0.68`): main output text and tree lines / comments.

### Named Rules
**The Report-Truth Rule.** The status colours mean exactly what they mean in the
CLI. Never use deny-red decoratively or pass-green for a non-passing thing; the
palette is documentation, so keep it honest.

**The Pink-Nod Rule.** Pink signals kinship with Gleam, never identity theft. It
carries accents, one CTA field, and the mark — never a drenched surface.

**The One-Terminal Rule.** There is exactly one family of dark surface: the
terminal (hero, Expressive Code blocks). Everything else is flat and light.

## 3. Typography

**Display Font:** Fraunces Variable (with `Georgia`/serif fallback), optical sizing on
**Body Font:** Hanken Grotesk Variable (with `system-ui` fallback)
**Mono Font:** JetBrains Mono Variable (with `ui-monospace` fallback)

**Character:** A soft, characterful display serif (Fraunces — with its `opsz`,
`SOFT`, and `WONK` axes) carries the brand voice and headings; a clean, neutral
humanist sans (Hanken) does the reading work — a deliberate expressive-serif /
neutral-sans contrast that reads crafted and honest, not generic-SaaS. Monospace
appears only where output, commands, and code are literal — it is honest here,
never costume.

### Hierarchy
- **Display** (Fraunces 700, `clamp(2.5rem, 1.55rem + 4.4vw, 4.5rem)`, lh 1.08, ls −0.01em, optical sizing auto): the hero headline; one per page.
- **Headline** (Fraunces 700, `clamp(1.6rem, … , 2.25rem)`, ls −0.01em): section headings (`h2`).
- **Title** (Fraunces 700, `clamp(1.25rem, … , 1.5rem)`, lh 1.25, ls normal): sub-section and step headings (`h3`).
- **Body** (Hanken 400, `1.0625rem`/17px, lh 1.62): prose, capped at 65–75ch (`.docs__main` 48rem, section text 42–46ch).
- **Label** (Hanken 700, `0.8125rem`, ls 0.09em, uppercase): footer and docs nav group headers only.
- **Mono / Data** (JetBrains 400, `0.9rem`, lh 1.75): terminal output, commands, code, package names. Tabular-nums on version columns.

### Named Rules
**The Mono-Is-Real Rule.** Monospace is reserved for things that are literally
code or terminal output. If it's brand copy, it's the sans. Mono as decoration
is prohibited.

**The Two-Voice Rule.** Fraunces speaks (display, personality); Hanken reads
(body, UI). They never swap roles.

## 4. Elevation

Flat by default. Depth comes from tonal layering — the off-white ground versus
slightly sunken sections and hairline borders — not from shadows. Two shadows
exist, and both are purposeful: a soft `--shadow-card` under lifted buttons and
static code frames, and a larger warm-tinted `--shadow-term` that lifts the hero
terminal off the page as the signature object. There is no ambient drop-shadow
vocabulary beyond these.

### Shadow Vocabulary
- **shadow-card** (`0 1px 2px …/0.05, 0 6px 18px -12px …/0.14`): quiet lift on secondary buttons, the GitHub nav pill, and Expressive Code frames.
- **shadow-term** (`0 2px 6px …, 0 34px 64px -26px oklch(0.55 0.16 350 / 0.42), …`): the hero terminal only — a warm pink-tinted glow, the one dramatic lift.
- **shadow-pop** (`0 12px 32px -10px …/0.22`): reserved for future overlays/popovers.

### Named Rules
**The Flat-By-Default Rule.** Surfaces are flat at rest. The hero terminal is the
single sanctioned exception; depth elsewhere is tone and spacing, not shadow.

## 5. Components

### Buttons (`Button.astro`)
- **Shape:** fully rounded (`--r-full`, 999px pill).
- **Primary:** pink field (`{colors.pink}`) with **dark ink** text (`oklch(0.2 0.02 335)`) — Gleam-flavoured and high-legibility (5.3:1). Padding `0.62rem 1.1rem` (md) / `0.85rem 1.5rem` (lg).
- **Hover / Focus:** background → `pink-hover`, `translateY(-2px)`, deepened pink glow; reduced-motion drops the translate. Focus-visible → 2.5px `pink-link` outline, 2px offset.
- **Secondary:** `surface` field, `ink` text, `border-strong` hairline, `shadow-card`; hover borders pink.
- **Ghost:** text-only, `ink-2` → `pink-link` on hover.

### Badge / kicker
- Pill (`--r-full`) with a `pink-soft` wash, `pink-link` text, and a leading icon. On the "what it checks" section the kicker recolours per status (pass-ink / pink-link / deny-ink) and uses the mono font.

### Navigation (`Nav.astro`)
- Sticky, `z-sticky`, translucent `bg` with a functional `backdrop-filter` blur and a bottom hairline (not decorative glass).
- Links are `ink-2` → `ink`; the active docs link is `pink-link`. The GitHub action is a bordered `surface` pill that lifts on hover.
- Mobile (≤34rem): the "Install" link and GitHub label collapse to the icon.

### Terminal (`Terminal.astro` / `HeroTerminal.astro`)
- The signature component. Window chrome: a title bar with three dots (the first is `pink`, the rest muted) + a mono title; a horizontally-scrollable body.
- Corner `--r-lg` (16px), `term-border` edge, `shadow-term` when `lift`.
- The hero variant streams a real mixed `check` report in line by line (command typed first, output after), driven by status colours. **Motion is an enhancement over a fully-visible default** — an inline guard adds the arming class only when motion is welcome, with a 6s failsafe; reduced-motion and no-JS render the full report statically.

### Code blocks (Expressive Code)
- All non-hero code renders through Expressive Code, themed to the terminal: `term-bg` background, `term-border` edges, `--r-lg`, JetBrains Mono, a `pink` active-tab indicator, and a copy button. Shell langs get a terminal frame; files (`toml`/`json`/`yaml`) get a titled editor frame.

### Docs sidebar (`DocsLayout.astro`)
- Sticky left rail on desktop; a horizontally-scrollable pill row on mobile (≤52rem). Group headers use the uppercase **Label** role. Active item is a `pink-soft` pill with `pink-link` text — no side-stripe.

### Prose
- Body `ink-2`; strong `ink`; list markers `pink-link`; inline `code` in a `pink-softer` chip with a hairline. Blockquotes are `pink-softer` callouts with a pink-tinted border (full border, not a stripe). Tables use a sunken header row and hairline rows; flag tables are kept to two columns so they never overflow.

## 6. Do's and Don'ts

### Do:
- **Do** put real audit output on the page — the actual `✓ ✗ ? ·` glyphs, tree indentation, and status colours — as the hero. Show, don't tell.
- **Do** keep status colours semantically honest: green = allowed, red = denied, grey = skipped/unknown, matching the CLI exactly.
- **Do** reserve monospace for literal terminal output, commands, and code.
- **Do** lead with the install command and the GitHub CTA (primary = view / star on GitHub).
- **Do** hold body text to 65–75ch and verify every text colour clears WCAG AA (ink 15.4:1, muted 5.7:1, pink-link 5.9:1, pass 5.3:1, deny 6.0:1).
- **Do** keep motion to one signature hero moment plus quiet, responsive feedback; ship an already-visible default and give every animation a reduced-motion path.
- **Do** add `min-width: 0` to any grid item holding a code block so it scrolls internally instead of blowing out the track.

### Don't:
- **Don't** build a generic SaaS landing page: no gradient hero, no three identical feature cards, no big-number stat band, no purple-blue gradients.
- **Don't** reach for the corporate enterprise-security look: no navy-and-gold compliance theatre, no stock photos of locks or shields, no fear-based selling.
- **Don't** let pink drench the surface or impersonate Gleam's identity — it's an accent and a nod.
- **Don't** use a warm-tinted cream/sand background; the ground is a calm, true off-white (`oklch(0.985 0.004 340)`).
- **Don't** use monospace as shorthand for "technical." If it isn't real code or output, it's the sans.
- **Don't** use `border-left`/`border-right` > 1px as a coloured accent stripe; use a `pink-soft` fill, a full border, or a leading glyph.
- **Don't** gate content visibility on a class-triggered reveal; the report must render even when the animation never fires.
