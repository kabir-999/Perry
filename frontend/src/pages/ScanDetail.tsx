import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { scansApi } from "../services/api";
import { SEVERITY_COLOR } from "../theme";
import type {
  AttackCoverageEntry,
  AttackMatrixRow,
  AttackStatus,
  Finding,
  RiskLevel,
  ScanSnapshot,
} from "../types";

const TERMINAL = ["completed", "failed", "cancelled"];
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const STAT_ORDER = ["critical", "high", "medium", "low", "minimal"];

const CHECK_GROUPS = [
  "Headers",
  "Information Exposure",
  "Configuration",
  "API Checks",
  "Input Validation",
];

const STATUS_LABEL: Record<string, string> = {
  queued: "Queued",
  fast_scanning: "Fast scan",
  initial_result_ready: "Initial result",
  deep_scanning: "Deep scan",
  ai_analysis: "AI analysis",
  completed: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
  pending: "Pending",
  running: "Running",
};

const RISK: Record<string, { hex: string; label: string }> = {
  critical: { hex: SEVERITY_COLOR.critical, label: "Critical" },
  high: { hex: SEVERITY_COLOR.high, label: "High" },
  medium: { hex: SEVERITY_COLOR.medium, label: "Medium" },
  low: { hex: SEVERITY_COLOR.low, label: "Low" },
  minimal: { hex: SEVERITY_COLOR.minimal, label: "Minimal" },
};
const SEV: Record<string, string> = SEVERITY_COLOR;

function riskHex(level: string): string {
  return RISK[level]?.hex ?? "#8a8173";
}

// MUST-run modules first, then the ADVANCED ones. Attacks not listed here
// fall back to object order.
const ATTACK_ORDER = [
  "sqli",
  "xss",
  "path_traversal",
  "command_injection",
  "open_redirect",
  "ssrf",
  "auth",
  "idor",
  "csrf",
  "xxe",
  "ssti",
  "deserialization",
];

// Cap the initial matrix render so a large surface doesn't lock the page.
const MATRIX_CAP = 200;

const ATTACK_STATUS_STYLE: Record<
  AttackStatus,
  { bg: string; fg: string; label: string }
> = {
  VULNERABLE: { bg: "#fbe7e7", fg: "#b91c1c", label: "Vulnerable" },
  NOT_VULNERABLE: { bg: "#e7f4ec", fg: "#0f7a52", label: "Not vulnerable" },
  NOT_TESTED: { bg: "#fdf3e3", fg: "#b45309", label: "Not tested" },
  INCONCLUSIVE: { bg: "#f1ecfb", fg: "#6d4fb8", label: "Inconclusive" },
  NOT_APPLICABLE: { bg: "#f4efe6", fg: "#948972", label: "N/A" },
};

function StatusChip({ status }: { status: AttackStatus }) {
  const s = ATTACK_STATUS_STYLE[status] ?? ATTACK_STATUS_STYLE.NOT_APPLICABLE;
  return (
    <span
      className="inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide"
      style={{ background: s.bg, color: s.fg }}
    >
      {s.label}
    </span>
  );
}

export default function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>();
  const [snap, setSnap] = useState<ScanSnapshot | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const lastFindingCount = useRef(-1);
  const fetchedTerminal = useRef(false);

  const isTerminal = snap ? TERMINAL.includes(snap.status) : false;

  useEffect(() => {
    if (!scanId) return;
    let source: EventSource | null = null;
    let pollTimer: number | undefined;
    let cancelled = false;

    scansApi
      .live(scanId)
      .then((initial) => {
        if (cancelled) return;
        setSnap(initial);
        if (TERMINAL.includes(initial.status)) return;
        source = scansApi.openStream(
          scanId,
          (s) => {
            setSnap(s);
            if (TERMINAL.includes(s.status)) source?.close();
          },
          () => {
            source?.close();
            source = null;
            if (pollTimer === undefined) {
              pollTimer = window.setInterval(async () => {
                try {
                  const s = await scansApi.live(scanId);
                  setSnap(s);
                  if (TERMINAL.includes(s.status)) window.clearInterval(pollTimer);
                } catch {
                  /* keep polling */
                }
              }, 2000);
            }
          },
        );
      })
      .catch(() => setError("Failed to load scan."));

    return () => {
      cancelled = true;
      source?.close();
      if (pollTimer !== undefined) window.clearInterval(pollTimer);
    };
  }, [scanId]);

  useEffect(() => {
    if (!scanId) return;
    if (isTerminal && !fetchedTerminal.current) {
      fetchedTerminal.current = true;
      scansApi.findings(scanId).then(setFindings).catch(() => undefined);
      return;
    }
    if (!snap || snap.findings_count === lastFindingCount.current) return;
    lastFindingCount.current = snap.findings_count;
    if (snap.findings_count > 0) {
      scansApi.findings(scanId).then(setFindings).catch(() => undefined);
    }
  }, [scanId, snap, isTerminal]);

  const fast = snap?.fast_result ?? null;
  const target = fast?.target || snap?.id || "";
  // The deterministic engine owns the score: overall_risk = highest confirmed
  // finding, always present; final_risk is its categorical level.
  const riskLevel: RiskLevel = (snap?.final_risk ?? "") as RiskLevel;
  const riskScore = snap?.overall_risk ?? snap?.risk_score ?? 0;

  // Severity distribution derived from the deduplicated findings.
  const severityCounts = useMemo(() => {
    const c: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      minimal: 0,
      info: 0,
    };
    for (const f of findings) c[f.severity] = (c[f.severity] ?? 0) + 1;
    return c;
  }, [findings]);
  const totalSev = STAT_ORDER.reduce((n, k) => n + (severityCounts[k] ?? 0), 0);

  const checksDone = useMemo(
    () => new Set(snap?.checks_done ?? []),
    [snap?.checks_done],
  );

  // Per-attack coverage rollup, ordered by the module order when available.
  const attackRows = useMemo(() => {
    const cov = snap?.attack_coverage ?? {};
    const entries = Object.entries(cov);
    entries.sort((a, b) => {
      const ia = ATTACK_ORDER.indexOf(a[0]);
      const ib = ATTACK_ORDER.indexOf(b[0]);
      return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
    });
    return entries.map(([, v]) => v);
  }, [snap?.attack_coverage]);

  const matrix = snap?.attack_matrix ?? [];
  const matrixShown = matrix.slice(0, MATRIX_CAP);

  const sortedFindings = useMemo(
    () =>
      [...findings].sort(
        (a, b) =>
          SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
      ),
    [findings],
  );

  async function handleCancel() {
    if (!scanId) return;
    try {
      await scansApi.cancel(scanId);
    } catch {
      /* ignore */
    }
  }

  function handleDownloadPdf() {
    if (!snap) return;
    const html = buildReportHtml(target, snap, sortedFindings);
    const win = window.open("", "_blank", "width=900,height=1000");
    if (!win) return;
    win.document.write(html);
    win.document.close();
    win.focus();
    setTimeout(() => win.print(), 300);
  }

  if (error) {
    return (
      <div className="rounded-xl border border-[#e7b7ad] bg-[#fbeae6] p-4 text-[#9f1239]">
        {error}
      </div>
    );
  }
  if (!snap) return <p className="text-[#6f6552]">Loading scan…</p>;

  if (snap.status === "failed") {
    return (
      <div className="mx-auto max-w-xl space-y-4">
        <div className="rounded-xl border border-[#e7b7ad] bg-[#fbeae6] p-6">
          <h2 className="text-lg font-semibold text-[#9f1239]">Scan failed</h2>
          <p className="mt-2 text-sm text-[#b4322f]">
            {snap.error_message ||
              "Unable to reach this website. Please check the URL or try again."}
          </p>
        </div>
        <Link to="/scans/new" className="text-sm text-[#0369a1] hover:underline">
          &larr; Try another website
        </Link>
      </div>
    );
  }

  const accent = isTerminal ? riskHex(riskLevel || "minimal") : "#8a8173";

  return (
    <div className="mx-auto max-w-4xl space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold tracking-tight">Security Assessment</h2>
          <p className="font-mono text-sm text-[#6f6552]">{target}</p>
        </div>
        <div className="flex items-center gap-2">
          {!isTerminal && (
            <button
              onClick={handleCancel}
              className="rounded-lg border border-[#d6c9b0] px-3 py-1.5 text-sm text-[#4a4032] transition-colors hover:bg-[#e6dcca]"
            >
              Cancel
            </button>
          )}
          {isTerminal && findings.length > 0 && (
            <button
              onClick={handleDownloadPdf}
              className="lift rounded-lg bg-[#c2410c] px-3 py-1.5 text-sm font-medium text-white shadow-sm transition-colors hover:bg-[#9a3412]"
            >
              Download PDF
            </button>
          )}
          <Link
            to="/"
            className="rounded-lg px-3 py-1.5 text-sm text-[#6f6552] transition-colors hover:text-[#3a3122]"
          >
            Dashboard
          </Link>
        </div>
      </div>

      {/* Risk hero */}
      <div
        className="relative overflow-hidden rounded-2xl border p-6"
        style={{
          borderColor: `${accent}55`,
          background: `linear-gradient(135deg, ${accent}26 0%, #fbf7ef 60%)`,
        }}
      >
        <div className="flex flex-col gap-6 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-2 text-xs uppercase tracking-widest text-[#6f6552]">
              {!isTerminal && (
                <span className="inline-block h-2 w-2 animate-pulse rounded-full bg-[#0369a1]" />
              )}
              {STATUS_LABEL[snap.status] ?? snap.status}
            </div>
            {isTerminal ? (
              <div className="mt-1 flex items-baseline gap-3">
                <span
                  className="text-4xl font-bold capitalize"
                  style={{ color: accent }}
                >
                  {RISK[riskLevel]?.label ?? "Minimal"}
                </span>
                <span className="text-sm text-[#6f6552]">overall risk</span>
              </div>
            ) : (
              <div className="mt-1 text-2xl font-semibold text-[#4a4032]">
                Analyzing…
              </div>
            )}
          </div>

          {isTerminal && <ScoreRing score={riskScore} color={accent} />}
        </div>

        {/* Severity bar, derived from the deduplicated findings */}
        {isTerminal && totalSev > 0 && (
          <div className="mt-5">
            <div className="flex h-2 overflow-hidden rounded-full bg-[#e6dcca]">
              {STAT_ORDER.map((s) =>
                severityCounts[s] ? (
                  <div
                    key={s}
                    style={{
                      width: `${(severityCounts[s] / totalSev) * 100}%`,
                      background: SEV[s],
                    }}
                  />
                ) : null,
              )}
            </div>
            <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-[#6f6552]">
              {STAT_ORDER.filter((s) => severityCounts[s]).map((s) => (
                <span key={s} className="inline-flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full" style={{ background: SEV[s] }} />
                  <span className="capitalize">{s}</span>
                  <span className="font-semibold text-[#4a4032]">{severityCounts[s]}</span>
                </span>
              ))}
            </div>
          </div>
        )}

        {isTerminal &&
          (snap.assessment_confidence ||
            typeof snap.assessment_coverage === "number") && (
          <div className="mt-5 flex flex-wrap items-center gap-3 border-t border-[#e3d8c4] pt-4">
            <span className="text-xs uppercase tracking-widest text-[#6f6552]">
              Assessment
            </span>
            {snap.assessment_confidence && (
              <ConfidenceBadge confidence={snap.assessment_confidence} />
            )}
            {typeof snap.assessment_coverage === "number" && (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-[#e3d8c4] bg-[#fbf7ef] px-2.5 py-1 text-xs font-semibold text-[#4a4032]">
                Coverage {snap.assessment_coverage}%
              </span>
            )}
          </div>
        )}
        {isTerminal && snap.assessment_warning && (
          <p className="mt-2 text-xs text-[#8a6d1f]">{snap.assessment_warning}</p>
        )}
      </div>

      {/* Progress while running */}
      {!isTerminal && (
        <div className="rounded-xl border border-[#e3d8c4] bg-[#fbf7ef] p-4">
          <div className="mb-2 flex items-center justify-between text-sm">
            <span className="text-[#4a4032]">{snap.ai_status || "Scanning…"}</span>
            <span className="text-[#6f6552]">{snap.deep_progress}%</span>
          </div>
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-[#e6dcca]">
            <div
              className="h-full rounded-full transition-all duration-500"
              style={{
                background: "linear-gradient(90deg,#0f766e,#0369a1,#c2410c)",
                width: `${snap.deep_progress}%`,
              }}
            />
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            {CHECK_GROUPS.map((group) => {
              const done = checksDone.has(group);
              return (
                <span
                  key={group}
                  className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs ${
                    done
                      ? "border-[#a7d3bf] bg-[#e7f4ec] text-[#0f7a52]"
                      : "border-[#d6c9b0] bg-[#fbf7ef] text-[#6f6552]"
                  }`}
                >
                  <span>{done ? "✓" : "⟳"}</span>
                  {group}
                </span>
              );
            })}
          </div>
        </div>
      )}

      {/* Preliminary observations (factual, from fast scan) */}
      {fast && (
        <Panel title="Preliminary Observations">
          <div className="grid gap-2 sm:grid-cols-2">
            {fast.checks.map((c) => (
              <div
                key={c.label}
                className="flex items-start gap-2 rounded-lg border border-[#e3d8c4] bg-[#f0e9dc] px-3 py-2"
              >
                <CheckDot status={c.status} />
                <div>
                  <p className="text-sm font-medium text-[#3a3122]">{c.label}</p>
                  <p className="text-xs text-[#6f6552]">{c.detail}</p>
                </div>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {/* Attack Coverage — the 12 attack modules and their per-attack rollup */}
      {attackRows.length > 0 && (
        <Panel title="Attack Coverage">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="text-left text-[11px] uppercase tracking-wide text-[#948972]">
                  <th className="py-2 pr-3 font-medium">Attack</th>
                  <th className="py-2 pr-3 font-medium">Status</th>
                  <th className="py-2 pr-3 text-right font-medium">Eligible</th>
                  <th className="py-2 pr-3 text-right font-medium">Tested</th>
                  <th className="py-2 text-right font-medium">Vulnerable</th>
                </tr>
              </thead>
              <tbody>
                {attackRows.map((a: AttackCoverageEntry) => (
                  <tr key={a.attack} className="border-t border-[#e6dcca]">
                    <td className="py-2 pr-3 font-medium text-[#3a3122]">
                      {a.display}
                    </td>
                    <td className="py-2 pr-3">
                      <StatusChip status={a.status} />
                    </td>
                    <td className="py-2 pr-3 text-right tabular-nums text-[#4a4032]">
                      {a.eligible}
                    </td>
                    <td className="py-2 pr-3 text-right tabular-nums text-[#4a4032]">
                      {a.tested}
                    </td>
                    <td
                      className="py-2 text-right tabular-nums font-semibold"
                      style={{ color: a.vulnerable > 0 ? "#b91c1c" : "#948972" }}
                    >
                      {a.vulnerable}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      {/* Test Matrix — every (endpoint, parameter, attack) cell and its outcome */}
      {matrix.length > 0 && (
        <Panel title={`Test Matrix (${matrix.length})`}>
          <div className="max-h-[28rem] overflow-auto">
            <table className="w-full border-collapse text-sm">
              <thead className="sticky top-0 bg-[#fbf7ef]">
                <tr className="text-left text-[11px] uppercase tracking-wide text-[#948972]">
                  <th className="py-2 pr-3 font-medium">Endpoint</th>
                  <th className="py-2 pr-3 font-medium">Parameter</th>
                  <th className="py-2 pr-3 font-medium">Attack</th>
                  <th className="py-2 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {matrixShown.map((row: AttackMatrixRow) => (
                  <tr key={row.test_id} className="border-t border-[#e6dcca] align-top">
                    <td className="py-2 pr-3 font-mono text-xs text-[#4a4032]">
                      <span className="font-semibold text-[#6f6552]">
                        {row.method}
                      </span>{" "}
                      {row.normalized_route || row.endpoint}
                    </td>
                    <td className="py-2 pr-3 font-mono text-xs text-[#4a4032]">
                      {row.parameter || "—"}
                      {row.location && (
                        <span className="text-[#948972]"> ({row.location})</span>
                      )}
                    </td>
                    <td className="py-2 pr-3 text-xs text-[#3a3122]">
                      {row.attack_display}
                    </td>
                    <td className="py-2">
                      <StatusChip status={row.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {matrix.length > MATRIX_CAP && (
            <p className="mt-3 text-xs text-[#948972]">
              Showing the first {MATRIX_CAP} of {matrix.length} tests.
            </p>
          )}
        </Panel>
      )}

      {/* Scan statistics */}
      <div className="grid grid-cols-3 gap-px overflow-hidden rounded-xl border border-[#e3d8c4] bg-[#e6dcca] sm:grid-cols-6">
        <Stat label="Findings" value={snap.findings_count} />
        <Stat label="URLs" value={snap.urls_discovered} />
        <Stat label="APIs" value={snap.apis_discovered} />
        <Stat label="Params" value={snap.parameters_discovered} />
        <Stat label="Subdomains" value={snap.subdomains_discovered} />
        <Stat label="Requests" value={snap.requests_made} />
      </div>

      {/* Expanded discovery coverage — real counts from browser crawling +
          network capture, not just the static crawler. */}
      {snap.coverage && (
        <div className="grid grid-cols-3 gap-px overflow-hidden rounded-xl border border-[#e3d8c4] bg-[#e6dcca] sm:grid-cols-5">
          <Stat label="Forms" value={snap.coverage.forms_discovered} />
          <Stat label="JS Bundles" value={snap.coverage.js_bundles_discovered} />
          <Stat label="Network Reqs" value={snap.coverage.network_requests_captured} />
          <Stat label="Auth Routes" value={snap.coverage.auth_routes_discovered} />
          <Stat label="Uploads" value={snap.coverage.upload_endpoints_discovered} />
        </div>
      )}

      {/* Deduplicated scanner findings (evidence) */}
      <Panel title={`Findings (${findings.length})`}>
        {findings.length === 0 ? (
          <p className="text-sm text-[#948972]">
            {isTerminal
              ? "No findings reported."
              : "Findings appear here when the scan completes…"}
          </p>
        ) : (
          <ul className="divide-y divide-[#e6dcca]">
            {sortedFindings.map((f) => (
              <FindingRow key={f.id} finding={f} />
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}

/* ------------------------------- components ------------------------------ */

const CONFIDENCE_STYLE: Record<string, { bg: string; fg: string; label: string }> = {
  HIGH: { bg: "#e7f4ec", fg: "#0f7a52", label: "High confidence" },
  MEDIUM: { bg: "#fdf3e3", fg: "#b45309", label: "Medium confidence" },
  LOW: { bg: "#fdf3e3", fg: "#b45309", label: "Low confidence" },
  INSUFFICIENT: { bg: "#fbe7e7", fg: "#b91c1c", label: "Insufficient confidence" },
};

function ConfidenceBadge({ confidence }: { confidence: string }) {
  const style = CONFIDENCE_STYLE[confidence];
  if (!style) return null;
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold"
      style={{ background: style.bg, color: style.fg }}
    >
      {style.label}
    </span>
  );
}

function ScoreRing({ score, color }: { score: number; color: string }) {
  const r = 30;
  const circ = 2 * Math.PI * r;
  const dash = (Math.min(100, Math.max(0, score)) / 100) * circ;
  return (
    <div className="relative h-[76px] w-[76px] shrink-0">
      <svg viewBox="0 0 76 76" className="h-full w-full -rotate-90">
        <circle cx="38" cy="38" r={r} fill="none" stroke="#e6dcca" strokeWidth="7" />
        <circle
          cx="38"
          cy="38"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="7"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${circ}`}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-xl font-bold text-[#2b2318]">{score}</span>
        <span className="text-[10px] text-[#948972]">/ 100</span>
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="bg-[#fbf7ef] px-3 py-3 text-center">
      <p className="text-lg font-semibold text-[#2b2318]">{value}</p>
      <p className="text-[11px] uppercase tracking-wide text-[#948972]">{label}</p>
    </div>
  );
}

function Panel({
  title,
  children,
  accent,
}: {
  title: string;
  children: React.ReactNode;
  accent?: string;
}) {
  return (
    <div className="rounded-xl border border-[#e3d8c4] bg-[#fbf7ef] p-5">
      <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-[#3a3122]">
        {accent && <span className="h-3.5 w-1 rounded-full" style={{ background: accent }} />}
        {title}
      </h3>
      {children}
    </div>
  );
}

function CheckDot({ status }: { status: string }) {
  const map: Record<string, string> = {
    pass: "#16a34a",
    fail: "#e11d48",
    warning: "#d97706",
    error: "#e11d48",
    info: "#8a8173",
  };
  const glyph: Record<string, string> = {
    pass: "✓",
    fail: "✗",
    warning: "!",
    error: "✗",
    info: "•",
  };
  return (
    <span className="mt-0.5 font-bold" style={{ color: map[status] ?? "#8a8173" }}>
      {glyph[status] ?? "•"}
    </span>
  );
}

function FindingRow({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const color = SEV[finding.severity] ?? "#78716c";
  return (
    <li>
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-3 py-3 text-left"
      >
        <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: color }} />
        <span
          className="shrink-0 rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase"
          style={{ background: `${color}22`, color }}
        >
          {finding.severity}
        </span>
        <span className="min-w-0 flex-1 truncate text-sm text-[#3a3122]">
          {finding.title}
        </span>
        <span className="shrink-0 text-[#b0a48c]">{open ? "▾" : "▸"}</span>
      </button>
      {open && (
        <div className="space-y-2 pb-3 pl-5 text-sm">
          {finding.url && (
            <p className="break-all font-mono text-xs text-[#948972]">
              {finding.url}
              {finding.parameter && ` · ${finding.parameter}`}
            </p>
          )}
          {finding.description && <Detail label="Description" text={finding.description} />}
          {finding.evidence && <Detail label="Evidence" text={finding.evidence} mono />}
          {finding.impact && <Detail label="Impact" text={finding.impact} />}
          {finding.remediation && <Detail label="Fix" text={finding.remediation} />}
        </div>
      )}
    </li>
  );
}

function Detail({ label, text, mono }: { label: string; text: string; mono?: boolean }) {
  return (
    <div>
      <span className="text-xs font-medium uppercase tracking-wide text-[#948972]">
        {label}:{" "}
      </span>
      <span
        className={`whitespace-pre-wrap break-words text-[#4a4032] ${
          mono ? "font-mono text-xs" : ""
        }`}
      >
        {text}
      </span>
    </div>
  );
}

/* --------------------------------- report -------------------------------- */

const SEV_HEX: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#0369a1",
  minimal: "#059669",
  info: "#0891b2",
};

function esc(s: string): string {
  return (s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function buildReportHtml(
  target: string,
  snap: ScanSnapshot,
  findings: Finding[],
): string {
  const riskLevel = snap.final_risk ?? "";
  const riskScore = snap.overall_risk ?? snap.risk_score ?? 0;

  const findingRows = findings
    .map((f) => {
      const color = SEV_HEX[f.severity] ?? "#666";
      const rows: string[] = [];
      if (f.url)
        rows.push(
          `<div class="kv"><b>Location</b> ${esc(f.url)}${
            f.parameter ? ` (param: ${esc(f.parameter)})` : ""
          }</div>`,
        );
      if (f.evidence) rows.push(`<div class="kv"><b>Evidence</b> <code>${esc(f.evidence)}</code></div>`);
      if (f.remediation) rows.push(`<div class="kv"><b>Fix</b> ${esc(f.remediation)}</div>`);
      return `<div class="finding"><div class="fhead"><span class="sev" style="background:${color}">${esc(
        f.severity,
      )}</span><span class="ftitle">${esc(f.title)}</span></div>${rows.join("")}</div>`;
    })
    .join("");

  const riskBadge = `<span class="risk" style="background:${
    SEV_HEX[riskLevel] ?? "#8a8173"
  }">${esc(riskLevel || "minimal")} · ${riskScore}/100</span>`;

  const COVERAGE_STATUS: Record<string, string> = {
    NOT_APPLICABLE: '<span style="color:#999">N/A</span>',
    NOT_TESTED: '<span style="color:#b45309">Not tested</span>',
    INCONCLUSIVE: '<span style="color:#6d4fb8">Inconclusive</span>',
    NOT_VULNERABLE: '<span style="color:#0f7a52">✓ Not vulnerable</span>',
    VULNERABLE: '<span style="color:#b91c1c;font-weight:700">Vulnerable</span>',
  };

  const coverageRows = Object.values(snap.attack_coverage ?? {})
    .map((a) => {
      const out = COVERAGE_STATUS[a.status] ?? esc(a.status);
      return `<tr><td>${esc(a.display)}</td><td style="text-align:center">${a.tested}/${a.eligible}</td><td style="text-align:right">${out}</td></tr>`;
    })
    .join("");

  const confidenceLine = snap.assessment_confidence
    ? `<div class="muted">Confidence: ${esc(snap.assessment_confidence)}${
        typeof snap.assessment_coverage === "number"
          ? ` &nbsp;•&nbsp; Coverage: ${snap.assessment_coverage}%`
          : ""
      }${snap.assessment_warning ? ` &nbsp;•&nbsp; ${esc(snap.assessment_warning)}` : ""}</div>`
    : "";

  return `<!doctype html><html><head><meta charset="utf-8">
<title>Security Report — ${esc(target)}</title>
<style>
  *{box-sizing:border-box}
  body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#111;margin:32px;font-size:12px;line-height:1.45}
  h1{font-size:20px;margin:0 0 2px}
  h2{font-size:13px;margin:22px 0 8px;border-bottom:1px solid #ddd;padding-bottom:4px;text-transform:uppercase;letter-spacing:.04em;color:#333}
  .muted{color:#666}
  .risk{display:inline-block;padding:6px 14px;border-radius:8px;color:#fff;font-weight:700;font-size:14px}
  .finding{border:1px solid #e2e2e2;border-radius:6px;padding:10px 12px;margin:10px 0;page-break-inside:avoid}
  .fhead{display:flex;align-items:center;gap:8px;margin-bottom:6px}
  .sev{color:#fff;text-transform:capitalize;font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px}
  .ftitle{font-weight:600}
  .kv{margin:3px 0}
  .kv b{display:inline-block;min-width:90px;color:#444}
  code{background:#f4f4f4;padding:1px 4px;border-radius:3px;word-break:break-all}
  table.tests{width:100%;border-collapse:collapse}
  table.tests td{padding:5px 8px;border-bottom:1px solid #eee}
  @media print{body{margin:12mm}}
</style></head><body>
  <h1>Website Security Assessment</h1>
  <div class="muted">${esc(target)} &nbsp;•&nbsp; ${new Date().toLocaleString()}</div>
  <div style="margin:14px 0">${riskBadge}</div>
  ${confidenceLine}
  <div class="muted">${findings.length} findings &nbsp;•&nbsp; ${snap.urls_discovered} URLs &nbsp;•&nbsp; ${snap.apis_discovered} APIs &nbsp;•&nbsp; ${snap.parameters_discovered} params &nbsp;•&nbsp; ${snap.subdomains_discovered} subdomains &nbsp;•&nbsp; ${snap.requests_made} requests</div>

  ${coverageRows ? `<h2>Attack Coverage</h2><table class="tests">${coverageRows}</table>` : ""}

  <h2>Findings (${findings.length})</h2>
  ${findingRows || '<div class="muted">No findings reported.</div>'}
</body></html>`;
}
