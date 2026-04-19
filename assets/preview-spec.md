# Preview Spec

- Dimensions: `1600x900`
- Format: static terminal-style PNG
- Background: page `#0b1020`, terminal panel `#111827`, header bar `#0f172a`
- Border: `1px` stroke `#1f2937`
- Padding: `48px` outer, `40px` inner terminal padding
- Corner radius: `24px`
- Font treatment: monospace only, semibold command line, regular body text
- Command shown: `little-canary serve --help`
- Exact output shown: the contents of `assets/preview-source.txt`
- Semantic coloring:
  - prompt line `#60a5fa`
  - neutral body `#e5e7eb`
  - warning flags or option names `#fbbf24`
  - failing or blocking signals `#f87171`
  - passing indicators `#34d399`
- Do not use mock UI, gradients, stock art, or synthetic output
- Future Hermes OSS repos should reuse this exact layout, palette, spacing, and aspect ratio
