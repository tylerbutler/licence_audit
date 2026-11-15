import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Resvg } from "@resvg/resvg-js";
import { create } from "fontkit";

function font(family) {
  return create(readFileSync(fileURLToPath(import.meta.resolve(
    `@fontsource-variable/${family}/files/${family}-latin-wght-normal.woff2`,
  ))));
}

export function renderOpenGraphImage() {
  const display = font("fraunces");
  const sans = font("hanken-grotesk");
  const mono = font("jetbrains-mono");

  // Outline the bundled WOFF2 fonts so rendering never uses host fonts.
  function text(value, face, size, x, y, color, maxWidth) {
    const run = face.layout(value);
    const scale = size / face.unitsPerEm;
    assert.ok(run.advanceWidth * scale <= maxWidth, `Text overflows: ${value}`);
    let cursor = 0;
    const paths = run.glyphs.map((glyph, index) => {
      assert.notEqual(glyph.id, 0, `Missing glyph in: ${value}`);
      const position = run.positions[index];
      const path = `<path d="${glyph.path.toSVG()}" transform="translate(${cursor + position.xOffset} ${position.yOffset})"/>`;
      cursor += position.xAdvance;
      return path;
    });
    return `<g fill="${color}" transform="translate(${x} ${y}) scale(${scale} ${-scale})">${paths.join("")}</g>`;
  }

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
    <rect width="1200" height="630" fill="#fbf9fb"/>
    <rect width="1200" height="8" fill="#df609d"/>
    <rect x="64" y="58" width="44" height="44" rx="13" fill="#df609d"/>
    <path d="M76 80 L83 87 L97 71" fill="none" stroke="#fff" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>
    ${text("licence_audit", display, 34, 124, 92, "#281e27", 450)}
    ${text("GLEAM SUPPLY-CHAIN AUDITING", sans, 18, 66, 166, "#993365", 540)}
    ${text("Check your Gleam", display, 56, 64, 252, "#281e27", 580)}
    ${text("dependencies.", display, 64, 64, 326, "#993365", 580)}
    ${text("Licence policy. CycloneDX SBOMs.", sans, 27, 66, 396, "#51434e", 570)}
    ${text("Known vulnerabilities. One CLI.", sans, 27, 66, 436, "#51434e", 570)}

    <rect x="676" y="190" width="460" height="290" rx="16" fill="#1e1720"/>
    <path d="M692 190 H1120 Q1136 190 1136 206 V232 H676 V206 Q676 190 692 190" fill="#302832"/>
    <circle cx="698" cy="211" r="5" fill="#e77d7d"/>
    <circle cx="716" cy="211" r="5" fill="#e4c378"/>
    <circle cx="734" cy="211" r="5" fill="#80c59b"/>
    ${text("licence_audit", mono, 14, 826, 216, "#b0a5b0", 280)}
    ${text("$ licence_audit check", mono, 21, 702, 279, "#f0a5ce", 408)}
    ${text("Package          Licence", mono, 17, 702, 326, "#b0a5b0", 408)}
    ${text("gleam_stdlib     Apache-2.0", mono, 17, 702, 362, "#ede7ed", 408)}
    ${text("gleam_json       Apache-2.0", mono, 17, 702, 394, "#ede7ed", 408)}
    <path d="M703 437 L708 442 L717 430" fill="none" stroke="#85d99c" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
    ${text("All dependencies allowed", mono, 17, 730, 443, "#85d99c", 380)}

    <path d="M64 526 H1136" stroke="#e5dfe5"/>
    ${text("licence-audit.tylerbutler.com", sans, 21, 66, 571, "#51434e", 700)}
    ${text("LOCAL + CI", mono, 17, 1030, 571, "#993365", 106)}
  </svg>`;

  return new Resvg(svg, { font: { loadSystemFonts: false } }).render().asPng();
}

if (import.meta.main) {
  const output = new URL("../public/og.png", import.meta.url);
  writeFileSync(output, renderOpenGraphImage());
  console.log(`Generated ${fileURLToPath(output)} (1200 x 630)`);
}
