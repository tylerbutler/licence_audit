# Product

## Register

brand

## Platform

web

## Users
Gleam developers who use Hex dependencies and need to keep their supply chain
honest: the right licences, a valid SBOM, no known vulnerabilities. They reach
the site from Hex, GitHub, the Gleam Discord, or a "how do I check licences in
Gleam?" search. They are comfortable in a terminal and skeptical of marketing;
they want to know what the tool does and how to run it in about ten seconds. The
secondary reader is the CI/DevOps engineer wiring a licence or vuln gate into a
pipeline, but the page speaks to the individual developer first.

## Product Purpose
licence_audit is one small CLI that audits the licences, generates a CycloneDX
SBOM, and checks for known vulnerabilities across a Gleam project's locked Hex
dependencies. The website exists to make that legible fast — to turn a visitor
who's never heard of it into someone who trusts it enough to run it and star the
repo. Success is a developer landing, understanding the inspect → policy →
enforce workflow, and leaving for GitHub with intent to try it.

## Positioning
The Gleam-native supply-chain auditor: licence policy, CycloneDX SBOM, and OSV
vulnerability checks for your locked Hex dependencies, in one dependency-free
binary. Not a dashboard, not a service — a fast CLI you can wire into CI and
forget.

## Conversion & proof
- Primary CTA: **View / star on GitHub**. Secondary fallback: the copy-paste
  install command (release archive or `mise`), for a visitor ready to try it
  before clicking through.
- The line a visitor remembers after 10 seconds: *"Audit your Gleam
  dependencies' licences, SBOM, and vulns — one small CLI."*
- Belief ladder: (1) this solves a real problem I have (licence/SBOM/vuln
  compliance for Hex deps); (2) it's genuinely Gleam-native, not a bolted-on
  wrapper; (3) it's precise and trustworthy enough to gate CI on; (4) it's easy
  to install and run right now.
- Proof on hand: shipped releases through v0.7.0, CycloneDX schema validation
  against the official schema, OSV.dev vulnerability integration, and a GitHub
  Actions setup path. No testimonials, logos, or named users yet — proof is the
  track record and the correctness discipline, not social proof.

## Brand Personality
Playful and approachable, but never sloppy. Warm, a little witty, human about a
dry subject — licences and SBOMs made light without being made trivial. At home
in the Gleam ecosystem: a familial nod to the signature pink and Lucy-era
warmth, while keeping its own distinct identity as a serious auditing tool.
Confidence comes from being clear and correct, not from enterprise gravitas.

## Anti-references
Not a generic SaaS landing page — no gradient hero, no three identical feature
cards, no big-number stat band, no purple-blue gradients. And not corporate
enterprise-security — no navy-and-gold compliance theatre, no stock photos of
locks and shields, no fear-based selling.

## Design Principles
Practice what you preach — a tool about rigor should itself feel precise and
correct; playful, never careless. Show, don't tell — lead with real terminal
output (the report table, the ✓/✗/?/· glyphs, the tree) instead of describing
features in the abstract. Approachable rigor — make a dry compliance topic feel
light and human without undercutting trust. Developer-honest — plain speech, no
FUD, install command up front, respect the reader's time. At home in Gleam —
familial warmth and a nod to the ecosystem, without becoming a pink clone.

## Accessibility & Inclusion
Target WCAG 2.1 AA: AA contrast on all text, full keyboard navigation, semantic
HTML, and a proper `prefers-reduced-motion` alternative for every animation.
