/**
 * Shared colour palette.
 *
 * The palette leans into the app mascot: teal skin, brown hat, and warm
 * report-paper surfaces. Accents still carry semantic meaning in findings,
 * charts, and badges.
 */
export const PALETTE = {
  teal: "#08756f",
  tealSoft: "#12a6a0",
  ember: "#8d5428",
  emberSoft: "#b98547",
  ocean: "#0b6f8f",
  oceanSoft: "#26a6c5",
  moss: "#1f7a4d",
  mossSoft: "#35b86f",
  rose: "#be123c",
  roseSoft: "#fb7185",
  gold: "#b7791f",
  goldSoft: "#efb25b",
} as const;

/** Ink and surface tones — the warm paper base the app sits on. */
export const SURFACE = {
  page: "#eef8f5",
  card: "#fbf7ef",
  sunk: "#dff0ec",
  border: "#b9d6cf",
  borderStrong: "#8fbab1",
  ink: "#123331",
  inkSoft: "#254c48",
  muted: "#4f716c",
  faint: "#66837d",
} as const;

/** Severity → colour, used by findings, charts, and badges alike. */
export const SEVERITY_COLOR: Record<string, string> = {
  critical: PALETTE.rose,
  high: "#b45309",
  medium: PALETTE.gold,
  low: PALETTE.ocean,
  minimal: PALETTE.moss,
  info: "#66837d",
};

/** Ordered accents for lists where each item should read distinctly. */
export const ACCENT_CYCLE = [
  PALETTE.teal,
  PALETTE.ocean,
  PALETTE.ember,
  PALETTE.moss,
  PALETTE.gold,
] as const;
