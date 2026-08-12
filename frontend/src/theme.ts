/**
 * Shared colour palette.
 *
 * Five accents carry meaning rather than decoration: TEAL is the consumer
 * side (link safety), EMBER the developer side (scanning), and OCEAN / MOSS /
 * ROSE / GOLD signal information, safety, danger, and caution wherever a
 * result is shown. Keep inline styles and chart colours pointing here so the
 * whole app moves together.
 */
export const PALETTE = {
  teal: "#0f766e",
  tealSoft: "#14b8a6",
  ember: "#c2410c",
  emberSoft: "#ea7c3c",
  ocean: "#0369a1",
  oceanSoft: "#0ea5e9",
  moss: "#15803d",
  mossSoft: "#22c55e",
  rose: "#be123c",
  roseSoft: "#f43f5e",
  gold: "#b45309",
  goldSoft: "#f59e0b",
} as const;

/** Ink and surface tones — the warm paper base the app sits on. */
export const SURFACE = {
  page: "#f4efe6",
  card: "#fbf7ef",
  sunk: "#f0e9dc",
  border: "#e3d8c4",
  borderStrong: "#d6c9b0",
  ink: "#2b2318",
  inkSoft: "#4a4032",
  muted: "#6f6552",
  faint: "#948972",
} as const;

/** Severity → colour, used by findings, charts, and badges alike. */
export const SEVERITY_COLOR: Record<string, string> = {
  critical: PALETTE.rose,
  high: PALETTE.ember,
  medium: PALETTE.gold,
  low: PALETTE.ocean,
  minimal: PALETTE.moss,
  info: "#78716c",
};

/** Ordered accents for lists where each item should read distinctly. */
export const ACCENT_CYCLE = [
  PALETTE.teal,
  PALETTE.ocean,
  PALETTE.ember,
  PALETTE.moss,
  PALETTE.gold,
] as const;
