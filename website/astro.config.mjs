// @ts-check
import { defineConfig } from "astro/config";
import expressiveCode from "astro-expressive-code";

// https://astro.build/config
export default defineConfig({
  site: "https://licence-audit.tylerbutler.com",
  devToolbar: { enabled: false },
  integrations: [
    expressiveCode({
      // One dark theme so every code block reads as a terminal — cohesive
      // with the hero (DESIGN.md: "The Honest Terminal").
      themes: ["github-dark"],
      useDarkModeMediaQuery: false,
      defaultProps: {
        showLineNumbers: false,
        wrap: false,
      },
      styleOverrides: {
        borderRadius: "12px",
        borderColor: "var(--term-border)",
        codeBackground: "var(--term-bg)",
        codeFontFamily: '"JetBrains Mono Variable", ui-monospace, monospace',
        codeFontSize: "0.86rem",
        codeLineHeight: "1.7",
        codePaddingBlock: "1rem",
        codePaddingInline: "1.15rem",
        uiFontFamily: '"Hanken Grotesk Variable", system-ui, sans-serif',
        scrollbarThumbColor: "color-mix(in oklch, var(--term-fg) 22%, transparent)",
        scrollbarThumbHoverColor: "color-mix(in oklch, var(--term-fg) 40%, transparent)",
        frames: {
          frameBoxShadowCssValue: "var(--shadow-card)",
          editorBackground: "var(--term-bg)",
          editorActiveTabBackground: "var(--term-bar)",
          editorActiveTabIndicatorTopColor: "var(--pink)",
          editorActiveTabIndicatorBottomColor: "transparent",
          editorTabBarBackground: "var(--term-bar)",
          editorTabBarBorderBottomColor: "var(--term-border)",
          editorActiveTabForeground: "var(--term-fg)",
          editorInactiveTabForeground: "var(--term-dim)",
          terminalBackground: "var(--term-bg)",
          terminalTitlebarBackground: "var(--term-bar)",
          terminalTitlebarBorderBottomColor: "var(--term-border)",
          terminalTitlebarForeground: "var(--term-dim)",
          terminalTitlebarDotsForeground:
            "color-mix(in oklch, var(--term-fg) 24%, transparent)",
          inlineButtonBackground: "var(--term-fg)",
          inlineButtonForeground: "var(--term-bg)",
          inlineButtonBorder: "transparent",
          tooltipSuccessBackground: "var(--pass-ink)",
        },
      },
    }),
  ],
});
