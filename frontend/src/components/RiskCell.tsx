import { SEVERITY_COLOR } from "../theme";
import type { Scan } from "../types";

const RISK_HEX: Record<string, string> = SEVERITY_COLOR;

/** Deterministic risk for a scan — matches the Scan Detail page.
 *  Shows the level+score only once the scan has a final risk. */
export default function RiskCell({ scan }: { scan: Scan }) {
  const terminal = ["completed", "failed", "cancelled"].includes(scan.status);
  if (!scan.final_risk) {
    return (
      <span className="text-xs text-[#948972]">{terminal ? "—" : "…"}</span>
    );
  }
  const hex = RISK_HEX[scan.final_risk] ?? "#8a8173";
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs capitalize"
      style={{ color: hex, borderColor: `${hex}55`, background: `${hex}18` }}
    >
      {scan.final_risk || "minimal"}
    </span>
  );
}
