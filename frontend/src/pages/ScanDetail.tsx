import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { scansApi } from "../services/api";
import { SEVERITY_COLOR } from "../theme";
import type {
  AttackCoverageEntry,
  AttackGraph,
  AttackGraphNode,
  AttackLogLevel,
  AttackLogRecord,
  AttackMatrixRow,
  AttackStatus,
  CrawlLogRecord,
  CrawlStats,
  CrawlStrategies,
  DomainAnomaly,
  Finding,
  ScanSnapshot,
} from "../types";

const TERMINAL = ["completed", "failed", "cancelled"];
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

const CHECK_GROUPS = [
  "Headers",
  "Information Exposure",
  "Configuration",
  "API Checks",
  "Input Validation",
];

const SEV: Record<string, string> = SEVERITY_COLOR;

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

const LOG_LEVEL_STYLE: Record<
  AttackLogLevel,
  { bg: string; fg: string; dot: string }
> = {
  DEBUG: { bg: "#eef0f2", fg: "#6b7280", dot: "#9ca3af" },
  INFO: { bg: "#eaf2fb", fg: "#1d4ed8", dot: "#3b82f6" },
  SUCCESS: { bg: "#e7f4ec", fg: "#0f7a52", dot: "#16a34a" },
  WARNING: { bg: "#fdf3e3", fg: "#b45309", dot: "#d97706" },
  ERROR: { bg: "#fbe7e7", fg: "#b91c1c", dot: "#dc2626" },
  ALERT: { bg: "#fbe3ef", fg: "#a1123f", dot: "#e11d48" },
};

const ANOMALY_LEVEL_COLOR: Record<string, string> = {
  critical: "#b91c1c",
  high: "#c2410c",
  medium: "#b45309",
  low: "#0369a1",
  minimal: "#0f7a52",
  not_tested: "#948972",
};

function anomalyColor(level: string): string {
  return ANOMALY_LEVEL_COLOR[level] ?? "#948972";
}

/** Small horizontal 0–100 anomaly bar with a numeric label. */
function AnomalyBar({
  score,
  level,
}: {
  score: number | null;
  level: string;
}) {
  if (score === null) {
    return <span className="text-xs text-[#b0a48c]">—</span>;
  }
  const color = anomalyColor(level);
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-[#e6dcca]">
        <div
          className="h-full rounded-full"
          style={{ width: `${Math.min(100, Math.max(0, score))}%`, background: color }}
        />
      </div>
      <span className="tabular-nums text-xs font-semibold" style={{ color }}>
        {score}
      </span>
    </div>
  );
}

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

  // Structured attack logs, grouped by attack id so each attack box can show
  // its own production JSON log stream when expanded.
  const logsByAttack = useMemo(() => {
    const map: Record<string, AttackLogRecord[]> = {};
    for (const rec of snap?.attack_logs ?? []) {
      (map[rec.attack] ??= []).push(rec);
    }
    for (const key of Object.keys(map)) {
      map[key].sort((a, b) => a.seq - b.seq);
    }
    return map;
  }, [snap?.attack_logs]);

  const [expandedAttack, setExpandedAttack] = useState<string | null>(null);

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

  return (
    <div className="mx-auto max-w-4xl space-y-5">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-3">
        <div className="min-w-0">
          <h2 className="text-lg font-semibold tracking-tight">Security Assessment</h2>
          <p className="break-all font-mono text-sm text-[#6f6552]">{target}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
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
            to="/projects"
            className="rounded-lg px-3 py-1.5 text-sm text-[#6f6552] transition-colors hover:text-[#3a3122]"
          >
            Projects
          </Link>
        </div>
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

      {/* Overall anomaly score — the baseline-vs-fuzz suspicion signal. */}
      {isTerminal && snap.anomaly && snap.anomaly.overall.domains_tested > 0 && (
        <AnomalyOverviewPanel anomaly={snap.anomaly} />
      )}

      {/* Attack Coverage — the attack modules and their per-attack rollup.
          Each row shows its anomaly score and expands to its production JSON logs. */}
      {attackRows.length > 0 && (
        <Panel title="Attack Coverage">
          <p className="mb-3 text-xs text-[#948972]">
            Click any attack to expand its baseline-vs-fuzz anomaly breakdown and
            production JSON logs — every attempt is recorded, vulnerable or not.
          </p>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="text-left text-[11px] uppercase tracking-wide text-[#948972]">
                  <th className="py-2 pr-3 font-medium">Attack</th>
                  <th className="py-2 pr-3 font-medium">Status</th>
                  <th className="py-2 pr-3 font-medium">Anomaly</th>
                  <th className="py-2 pr-3 text-right font-medium">Tested</th>
                  <th className="py-2 pr-3 text-right font-medium">Vulnerable</th>
                  <th className="py-2 text-right font-medium">Logs</th>
                </tr>
              </thead>
              <tbody>
                {attackRows.map((a: AttackCoverageEntry) => {
                  const logs = logsByAttack[a.attack] ?? [];
                  const open = expandedAttack === a.attack;
                  return (
                    <AttackCoverageRow
                      key={a.attack}
                      attack={a}
                      anomaly={snap.anomaly?.domains?.[a.attack]}
                      logs={logs}
                      open={open}
                      onToggle={() =>
                        setExpandedAttack(open ? null : a.attack)
                      }
                    />
                  );
                })}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      {/* Attack Surface Graph — Combined / BFS / DFS, node-link or tree view */}
      {snap.attack_graph && (snap.attack_graph.node_count ?? 0) > 0 && (
        <AttackSurfaceGraphPanel
          combined={snap.attack_graph}
          strategies={snap.crawl_strategies}
          target={target}
        />
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

/* ------------------------------ attack logs ------------------------------ */

function fmtLogTime(ts: string): string {
  // ISO like 2026-08-14T09:12:33.123Z -> 09:12:33.123
  const m = /T(\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?)/.exec(ts);
  return m ? m[1] : ts;
}

function LogLevelChip({ level }: { level: AttackLogLevel }) {
  const s = LOG_LEVEL_STYLE[level] ?? LOG_LEVEL_STYLE.INFO;
  return (
    <span
      className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide"
      style={{ background: s.bg, color: s.fg }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: s.dot }} />
      {level}
    </span>
  );
}

function LogRecordRow({ record }: { record: AttackLogRecord }) {
  const [open, setOpen] = useState(false);
  const target =
    record.endpoint &&
    `${record.method || ""} ${record.endpoint}`.trim() +
      (record.parameter ? ` [${record.location}:${record.parameter}]` : "");
  return (
    <div className="border-b border-[#efe7d6] last:border-b-0">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-start gap-2 py-1.5 text-left font-mono text-xs hover:bg-[#f3ecdd]"
      >
        <span className="shrink-0 text-[#b0a48c]">{fmtLogTime(record.timestamp)}</span>
        <LogLevelChip level={record.level} />
        <span className="min-w-0 flex-1 whitespace-pre-wrap break-words text-[#3a3122]">
          {record.message}
        </span>
        <span className="shrink-0 text-[#c2b79e]">{open ? "▾" : "▸"}</span>
      </button>
      {open && (
        <div className="space-y-1.5 pb-2 pl-2 font-mono text-[11px] text-[#6f6552]">
          {target && (
            <div>
              <span className="text-[#948972]">target: </span>
              <span className="break-all text-[#4a4032]">{target}</span>
            </div>
          )}
          {record.payload && (
            <div>
              <span className="text-[#948972]">payload: </span>
              <span className="break-all text-[#b45309]">{record.payload}</span>
            </div>
          )}
          {record.evidence && (
            <div>
              <span className="text-[#948972]">evidence: </span>
              <span className="break-words text-[#4a4032]">{record.evidence}</span>
            </div>
          )}
          <pre className="overflow-x-auto rounded bg-[#2b2318] p-2 text-[10px] leading-relaxed text-[#e6dcca]">
            {JSON.stringify(record, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

function AttackLogView({ records }: { records: AttackLogRecord[] }) {
  const [rawAll, setRawAll] = useState(false);
  if (records.length === 0) {
    return (
      <p className="py-2 text-xs text-[#948972]">
        No logs recorded for this attack.
      </p>
    );
  }
  const counts = records.reduce<Record<string, number>>((acc, r) => {
    acc[r.level] = (acc[r.level] ?? 0) + 1;
    return acc;
  }, {});
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[11px] uppercase tracking-wide text-[#948972]">
          {records.length} log record{records.length === 1 ? "" : "s"}
        </span>
        {(Object.keys(counts) as AttackLogLevel[]).map((lvl) => (
          <LogLevelChip key={lvl} level={lvl} />
        ))}
        <button
          onClick={() => setRawAll((v) => !v)}
          className="ml-auto rounded border border-[#d6c9b0] px-2 py-0.5 text-[11px] text-[#6f6552] hover:bg-[#e6dcca]"
        >
          {rawAll ? "Formatted view" : "Raw JSON"}
        </button>
      </div>
      {rawAll ? (
        <pre className="max-h-[24rem] overflow-auto rounded bg-[#2b2318] p-3 text-[10px] leading-relaxed text-[#e6dcca]">
          {JSON.stringify(records, null, 2)}
        </pre>
      ) : (
        <div className="max-h-[24rem] overflow-auto rounded border border-[#e6dcca] bg-[#fcf8f0] px-2">
          {records.map((r) => (
            <LogRecordRow key={r.seq} record={r} />
          ))}
        </div>
      )}
    </div>
  );
}

function AttackCoverageRow({
  attack,
  anomaly,
  logs,
  open,
  onToggle,
}: {
  attack: AttackCoverageEntry;
  anomaly?: DomainAnomaly;
  logs: AttackLogRecord[];
  open: boolean;
  onToggle: () => void;
}) {
  return (
    <>
      <tr
        onClick={onToggle}
        className={`cursor-pointer border-t border-[#e6dcca] transition-colors hover:bg-[#f3ecdd] ${
          open ? "bg-[#f3ecdd]" : ""
        }`}
      >
        <td className="py-2 pr-3 font-medium text-[#3a3122]">
          <span className="mr-1.5 inline-block text-[#b0a48c]">
            {open ? "▾" : "▸"}
          </span>
          {attack.display}
        </td>
        <td className="py-2 pr-3">
          <StatusChip status={attack.status} />
        </td>
        <td className="py-2 pr-3">
          <AnomalyBar
            score={anomaly?.score ?? null}
            level={anomaly?.level ?? "not_tested"}
          />
        </td>
        <td className="py-2 pr-3 text-right tabular-nums text-[#4a4032]">
          {attack.tested}
        </td>
        <td
          className="py-2 pr-3 text-right tabular-nums font-semibold"
          style={{ color: attack.vulnerable > 0 ? "#b91c1c" : "#948972" }}
        >
          {attack.vulnerable}
        </td>
        <td className="py-2 text-right tabular-nums text-[#6f6552]">
          {logs.length}
        </td>
      </tr>
      {open && (
        <tr className="border-t border-[#e6dcca] bg-[#fbf7ef]">
          <td colSpan={6} className="px-2 py-3">
            {anomaly && anomaly.score !== null && (
              <AnomalyBreakdown anomaly={anomaly} />
            )}
            <AttackLogView records={logs} />
          </td>
        </tr>
      )}
    </>
  );
}

function AnomalyBreakdown({ anomaly }: { anomaly: DomainAnomaly }) {
  const color = anomalyColor(anomaly.level);
  const cells: Array<[string, string]> = [
    ["Anomaly score", `${anomaly.score} / 100`],
    ["Level", anomaly.level],
    ["Peak probe", anomaly.max.toFixed(2)],
    ["Mean probe", anomaly.mean.toFixed(2)],
    ["Tested", String(anomaly.tested)],
    ["Anomalous", String(anomaly.anomalous)],
    ["Measured diffs", String(anomaly.measured)],
    ["Vulnerable", String(anomaly.vulnerable)],
  ];
  return (
    <div className="mb-3 rounded-lg border border-[#e6dcca] bg-[#fcf8f0] p-3">
      <div className="mb-2 flex items-center gap-2">
        <span className="text-[11px] uppercase tracking-wide text-[#948972]">
          Baseline-vs-fuzz anomaly
        </span>
        <span
          className="rounded px-1.5 py-0.5 text-[10px] font-bold uppercase"
          style={{ background: `${color}22`, color }}
        >
          {anomaly.level}
        </span>
      </div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs sm:grid-cols-4">
        {cells.map(([k, v]) => (
          <div key={k} className="flex justify-between gap-2">
            <span className="text-[#948972]">{k}</span>
            <span className="font-semibold text-[#4a4032]">{v}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function AnomalyOverviewPanel({ anomaly }: { anomaly: NonNullable<ScanSnapshot["anomaly"]> }) {
  const { overall, domains } = anomaly;
  const color = anomalyColor(overall.level);
  const ranked = Object.values(domains)
    .filter((d) => d.score !== null)
    .sort((a, b) => (b.score ?? 0) - (a.score ?? 0))
    .slice(0, 6);
  return (
    <Panel title="Anomaly Score" accent={color}>
      <p className="mb-4 text-xs text-[#948972]">
        How anomalously the application behaved under attack, scored by comparing
        each fuzz response against its baseline. A suspicion signal — separate
        from the finding-severity risk score.
      </p>
      <div className="flex flex-col gap-5 sm:flex-row sm:items-center">
        <div className="flex items-center gap-4">
          <ScoreRing score={overall.score} color={color} />
          <div>
            <div className="text-2xl font-bold capitalize" style={{ color }}>
              {overall.level}
            </div>
            <div className="text-xs text-[#6f6552]">
              {overall.domains_anomalous} of {overall.domains_tested} tested
              domains anomalous
            </div>
            {overall.top_domain_display && (
              <div className="mt-1 text-xs text-[#6f6552]">
                Peak: <span className="font-semibold text-[#4a4032]">
                  {overall.top_domain_display}
                </span>{" "}
                ({overall.top_domain_score})
              </div>
            )}
          </div>
        </div>
        <div className="flex-1 space-y-1.5">
          {ranked.map((d) => (
            <div key={d.attack} className="flex items-center gap-3">
              <span className="w-44 shrink-0 truncate text-xs text-[#4a4032]">
                {d.display}
              </span>
              <div className="h-2 flex-1 overflow-hidden rounded-full bg-[#e6dcca]">
                <div
                  className="h-full rounded-full"
                  style={{
                    width: `${Math.min(100, Math.max(0, d.score ?? 0))}%`,
                    background: anomalyColor(d.level),
                  }}
                />
              </div>
              <span
                className="w-8 shrink-0 text-right tabular-nums text-xs font-semibold"
                style={{ color: anomalyColor(d.level) }}
              >
                {d.score}
              </span>
            </div>
          ))}
        </div>
      </div>
    </Panel>
  );
}

/* --------------------------- attack-surface graph ------------------------ */

function scoreColor(score: number): string {
  if (score >= 60) return "#b91c1c";
  if (score >= 40) return "#c2410c";
  if (score >= 20) return "#b45309";
  return "#0f7a52";
}

function graphToDot(graph: AttackGraph): string {
  const idx = new Map<string, number>();
  graph.nodes.forEach((n, i) => idx.set(n.id, i));
  const esc = (s: string) => (s || "").replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  const lines: string[] = [
    "digraph attack_surface {",
    "  rankdir=LR;",
    '  node [shape=box, style=rounded, fontname="Helvetica", fontsize=10];',
  ];
  for (const n of graph.nodes) {
    const i = idx.get(n.id)!;
    if (n.synthetic) {
      lines.push(`  n${i} [label="${esc(n.label)}", style="rounded,filled", fillcolor="#eeeeee"];`);
    } else {
      const extra = `\\nscore=${n.score}${n.param_count ? ` · ${n.param_count}p` : ""}`;
      lines.push(`  n${i} [label="${esc(n.label)}${esc(extra)}"];`);
    }
  }
  for (const e of graph.edges) {
    const p = idx.get(e.parent);
    const c = idx.get(e.child);
    if (p === undefined || c === undefined) continue;
    const lbl = e.via ? ` [label="${esc(e.via)}", fontsize=8]` : "";
    lines.push(`  n${p} -> n${c}${lbl};`);
  }
  lines.push("}");
  return lines.join("\n");
}

function download(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

const DISCOVERY_LABEL: Record<string, string> = {
  seed: "seed",
  page: "page",
  link: "link",
  form: "form",
  "form-get": "form submit",
  interaction: "interaction",
  xhr: "XHR/fetch",
  navigation: "navigation",
  api: "API",
  js_bundle: "JS bundle",
  discovery: "discovery",
  group: "group",
};

function GraphTreeNode({
  node,
  childrenMap,
  nodeMap,
  via,
  depth,
  ancestry,
}: {
  node: AttackGraphNode;
  childrenMap: Map<string, Array<{ id: string; via: string }>>;
  nodeMap: Map<string, AttackGraphNode>;
  via: string;
  depth: number;
  ancestry: Set<string>;
}) {
  const kids = (childrenMap.get(node.id) ?? []).filter((k) => !ancestry.has(k.id));
  const [open, setOpen] = useState(depth < 1);
  const hasKids = kids.length > 0;
  const color = node.synthetic ? "#948972" : scoreColor(node.score);
  return (
    <div>
      <div
        className="flex items-center gap-2 rounded px-1.5 py-1 hover:bg-[#f3ecdd]"
        style={{ marginLeft: depth * 16 }}
      >
        <button
          onClick={() => hasKids && setOpen((o) => !o)}
          className={`w-3 shrink-0 text-[#b0a48c] ${hasKids ? "" : "invisible"}`}
        >
          {open ? "▾" : "▸"}
        </button>
        {!node.synthetic && (
          <span
            className="shrink-0 rounded px-1 py-0.5 text-[10px] font-bold tabular-nums"
            style={{ background: `${color}22`, color }}
            title="Attack-surface score"
          >
            {node.score}
          </span>
        )}
        <span
          className={`min-w-0 flex-1 truncate font-mono text-xs ${
            node.synthetic ? "font-semibold text-[#6f6552]" : "text-[#3a3122]"
          }`}
          title={node.url || node.label}
        >
          {node.label}
        </span>
        {node.is_api && (
          <span className="shrink-0 rounded bg-[#eaf2fb] px-1 text-[10px] font-semibold text-[#1d4ed8]">
            API
          </span>
        )}
        {node.is_form && (
          <span className="shrink-0 rounded bg-[#f1ecfb] px-1 text-[10px] font-semibold text-[#6d4fb8]">
            form
          </span>
        )}
        {node.param_count > 0 && (
          <span className="shrink-0 text-[10px] text-[#948972]">{node.param_count}p</span>
        )}
        {via && (
          <span className="shrink-0 text-[10px] text-[#b0a48c]">{DISCOVERY_LABEL[via] ?? via}</span>
        )}
      </div>
      {open &&
        kids.map((k) => {
          const child = nodeMap.get(k.id);
          if (!child) return null;
          return (
            <GraphTreeNode
              key={k.id}
              node={child}
              childrenMap={childrenMap}
              nodeMap={nodeMap}
              via={k.via}
              depth={depth + 1}
              ancestry={new Set([...ancestry, node.id])}
            />
          );
        })}
    </div>
  );
}

function buildChildrenMap(graph: AttackGraph, nodeMap: Map<string, AttackGraphNode>) {
  const m = new Map<string, Array<{ id: string; via: string }>>();
  for (const e of graph.edges) {
    if (!m.has(e.parent)) m.set(e.parent, []);
    m.get(e.parent)!.push({ id: e.child, via: e.via });
  }
  for (const arr of m.values()) {
    arr.sort((a, b) => (nodeMap.get(b.id)?.score ?? 0) - (nodeMap.get(a.id)?.score ?? 0));
  }
  return m;
}

function graphRoots(graph: AttackGraph): string[] {
  return graph.roots.length
    ? graph.roots
    : graph.nodes.filter((n) => !graph.edges.some((e) => e.child === n.id)).map((n) => n.id);
}

function GraphTreeView({ graph }: { graph: AttackGraph }) {
  const nodeMap = useMemo(() => {
    const m = new Map<string, AttackGraphNode>();
    for (const n of graph.nodes) m.set(n.id, n);
    return m;
  }, [graph.nodes]);
  const childrenMap = useMemo(() => buildChildrenMap(graph, nodeMap), [graph, nodeMap]);
  const roots = graphRoots(graph);
  return (
    <div className="max-h-[32rem] overflow-auto rounded border border-[#e6dcca] bg-[#fcf8f0] p-2">
      {roots.map((rid) => {
        const root = nodeMap.get(rid);
        if (!root) return null;
        return (
          <GraphTreeNode
            key={rid}
            node={root}
            childrenMap={childrenMap}
            nodeMap={nodeMap}
            via=""
            depth={0}
            ancestry={new Set()}
          />
        );
      })}
    </div>
  );
}

const GRAPH_NODE_CAP = 160;
const COL_W = 210;
const ROW_H = 40;
const NODE_W = 178;
const NODE_H = 26;
const PAD = 14;

/** Actual node-link graph: nodes laid out in columns by depth, edges drawn as
 *  curves. Capped for readability on large surfaces. */
function GraphNodeLink({ graph }: { graph: AttackGraph }) {
  const layout = useMemo(() => {
    const nodeMap = new Map<string, AttackGraphNode>();
    for (const n of graph.nodes) nodeMap.set(n.id, n);
    const childrenMap = buildChildrenMap(graph, nodeMap);
    const roots = graphRoots(graph);

    // Layer = shortest distance from a root (BFS over edges).
    const layer = new Map<string, number>();
    const q: string[] = [];
    for (const r of roots) {
      if (nodeMap.has(r)) {
        layer.set(r, 0);
        q.push(r);
      }
    }
    while (q.length) {
      const id = q.shift()!;
      const l = layer.get(id)!;
      for (const c of childrenMap.get(id) ?? []) {
        if (!layer.has(c.id) && nodeMap.has(c.id)) {
          layer.set(c.id, l + 1);
          q.push(c.id);
        }
      }
    }
    for (const n of graph.nodes) if (!layer.has(n.id)) layer.set(n.id, n.depth || 0);

    // Cap: keep the shallowest, highest-scoring nodes.
    let kept = [...graph.nodes];
    const truncated = kept.length > GRAPH_NODE_CAP;
    if (truncated) {
      kept = kept
        .slice()
        .sort((a, b) => (layer.get(a.id)! - layer.get(b.id)!) || b.score - a.score)
        .slice(0, GRAPH_NODE_CAP);
    }
    const keptIds = new Set(kept.map((n) => n.id));

    // Position: column by layer, stacked within the column.
    const byLayer = new Map<number, AttackGraphNode[]>();
    for (const n of kept) {
      const l = layer.get(n.id)!;
      if (!byLayer.has(l)) byLayer.set(l, []);
      byLayer.get(l)!.push(n);
    }
    const pos = new Map<string, { x: number; y: number }>();
    let maxRows = 0;
    for (const [l, arr] of byLayer) {
      arr.sort((a, b) => b.score - a.score);
      arr.forEach((n, i) => pos.set(n.id, { x: l * COL_W + PAD, y: i * ROW_H + PAD }));
      maxRows = Math.max(maxRows, arr.length);
    }
    const numLayers = Math.max(...[...byLayer.keys()].map((l) => l + 1), 1);
    const edges = graph.edges.filter((e) => keptIds.has(e.parent) && keptIds.has(e.child));
    return {
      nodeMap,
      kept,
      edges,
      pos,
      width: numLayers * COL_W + PAD,
      height: Math.max(maxRows * ROW_H + PAD, 60),
      truncated,
      total: graph.nodes.length,
    };
  }, [graph]);

  if (!layout.kept.length) {
    return <p className="py-4 text-xs text-[#948972]">No graph nodes.</p>;
  }

  return (
    <div className="overflow-auto rounded border border-[#e6dcca] bg-[#fcf8f0]" style={{ maxHeight: "34rem" }}>
      <svg width={layout.width} height={layout.height} style={{ display: "block", minWidth: "100%" }}>
        {layout.edges.map((e, i) => {
          const p = layout.pos.get(e.parent);
          const c = layout.pos.get(e.child);
          if (!p || !c) return null;
          const x1 = p.x + NODE_W;
          const y1 = p.y + NODE_H / 2;
          const x2 = c.x;
          const y2 = c.y + NODE_H / 2;
          const mx = (x1 + x2) / 2;
          return (
            <path
              key={i}
              d={`M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`}
              fill="none"
              stroke="#d6c9b0"
              strokeWidth={1}
            />
          );
        })}
        {layout.kept.map((n) => {
          const p = layout.pos.get(n.id)!;
          const color = n.synthetic ? "#948972" : scoreColor(n.score);
          return (
            <g key={n.id} transform={`translate(${p.x},${p.y})`}>
              <title>{`${n.label}${n.url ? `\n${n.url}` : ""}${n.synthetic ? "" : `\nscore ${n.score} · ${n.param_count}p · ${n.discovery}`}`}</title>
              <rect
                width={NODE_W}
                height={NODE_H}
                rx={5}
                fill={n.synthetic ? "#f0e9dc" : `${color}18`}
                stroke={color}
                strokeWidth={n.synthetic ? 1 : 1.4}
              />
              {!n.synthetic && <rect width={4} height={NODE_H} rx={2} fill={color} />}
              <text x={10} y={NODE_H / 2 + 4} fontSize={11} fontFamily="ui-monospace, monospace" fill="#3a3122">
                {n.label.length > 26 ? n.label.slice(0, 25) + "…" : n.label}
              </text>
              {!n.synthetic && (
                <text x={NODE_W - 8} y={NODE_H / 2 + 4} fontSize={10} textAnchor="end" fontWeight="700" fill={color}>
                  {n.score}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      {layout.truncated && (
        <p className="px-2 py-1 text-[11px] text-[#948972]">
          Showing {GRAPH_NODE_CAP} of {layout.total} nodes (shallowest, highest-scoring). Download the
          JSON/DOT for the full graph.
        </p>
      )}
    </div>
  );
}

const CRAWL_EVENT_STYLE: Record<string, { fg: string; bg: string }> = {
  navigate: { fg: "#1d4ed8", bg: "#eaf2fb" },
  interact: { fg: "#6d4fb8", bg: "#f1ecfb" },
  discover: { fg: "#0f7a52", bg: "#e7f4ec" },
  error: { fg: "#b91c1c", bg: "#fbe7e7" },
};

function CrawlLogView({ log }: { log: CrawlLogRecord[] }) {
  const [open, setOpen] = useState(false);
  if (!log.length) return null;
  return (
    <div className="mt-3">
      <button
        onClick={() => setOpen((o) => !o)}
        className="text-xs font-medium text-[#6f6552] hover:text-[#3a3122]"
      >
        {open ? "▾" : "▸"} Crawl log ({log.length})
      </button>
      {open && (
        <div className="mt-2 max-h-[20rem] overflow-auto rounded border border-[#e6dcca] bg-[#fcf8f0] px-2">
          {log.map((r) => {
            const s = CRAWL_EVENT_STYLE[r.event] ?? { fg: "#6f6552", bg: "#eee" };
            return (
              <div key={r.seq} className="flex items-start gap-2 border-b border-[#efe7d6] py-1 font-mono text-[11px] last:border-b-0">
                <span className="shrink-0 text-[#b0a48c]">{fmtLogTime(r.timestamp)}</span>
                <span
                  className="shrink-0 rounded px-1 text-[10px] font-bold uppercase"
                  style={{ background: s.bg, color: s.fg }}
                >
                  {r.event}
                </span>
                <span className="min-w-0 flex-1 truncate text-[#4a4032]" title={r.url || r.detail}>
                  {r.detail ? `${r.detail} ` : ""}
                  {r.url}
                </span>
                {typeof r.depth === "number" && <span className="shrink-0 text-[#b0a48c]">d{r.depth}</span>}
                {typeof r.score === "number" && <span className="shrink-0 text-[#948972]">s{r.score}</span>}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function StrategyStatsRow({ stats, score }: { stats: CrawlStats; score: number }) {
  const cells: Array<[string, string | number]> = [
    ["Discovery score", `${score}/100`],
    ["Endpoints", stats.endpoints],
    ["APIs", stats.apis],
    ["Forms", stats.forms],
    ["Params", stats.params],
    ["Interactions", stats.interactions],
    ["Pages rendered", stats.pages_rendered],
    ["Max depth", stats.max_depth_reached],
  ];
  return (
    <div className="mb-3 grid grid-cols-2 gap-x-4 gap-y-1 rounded-lg border border-[#e6dcca] bg-[#fcf8f0] p-3 text-xs sm:grid-cols-4">
      {cells.map(([k, v]) => (
        <div key={k} className="flex justify-between gap-2">
          <span className="text-[#948972]">{k}</span>
          <span className="font-semibold text-[#4a4032]">{v}</span>
        </div>
      ))}
    </div>
  );
}

function AttackSurfaceGraphPanel({
  combined,
  strategies,
  target,
}: {
  combined: AttackGraph;
  strategies?: CrawlStrategies;
  target: string;
}) {
  type Sel = "combined" | "bfs" | "dfs";
  const [sel, setSel] = useState<Sel>("combined");
  const [view, setView] = useState<"graph" | "tree">("graph");

  const active =
    sel === "combined" ? combined : strategies?.[sel]?.graph ?? combined;
  const strat = sel === "combined" ? undefined : strategies?.[sel];
  const safeName = `${(target || "scan").replace(/[^a-z0-9.-]+/gi, "_").slice(0, 40)}-${sel}`;

  const tab = (key: Sel, label: string, score?: number) => (
    <button
      onClick={() => setSel(key)}
      className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
        sel === key ? "bg-[#c2410c] text-white" : "border border-[#d6c9b0] text-[#4a4032] hover:bg-[#e6dcca]"
      }`}
    >
      {label}
      {typeof score === "number" && (
        <span className={`ml-1.5 tabular-nums ${sel === key ? "text-white/80" : "text-[#948972]"}`}>
          {score}
        </span>
      )}
    </button>
  );

  return (
    <Panel title={`Attack Surface Graph (${active.node_count} nodes, ${active.edge_count} edges)`}>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        {tab("combined", "Combined")}
        {strategies && tab("bfs", "BFS", strategies.bfs?.score)}
        {strategies && tab("dfs", "DFS", strategies.dfs?.score)}
        <span className="mx-1 h-4 w-px bg-[#d6c9b0]" />
        <button
          onClick={() => setView("graph")}
          className={`rounded px-2 py-1 text-xs ${view === "graph" ? "bg-[#e6dcca] font-semibold text-[#3a3122]" : "text-[#6f6552]"}`}
        >
          Graph
        </button>
        <button
          onClick={() => setView("tree")}
          className={`rounded px-2 py-1 text-xs ${view === "tree" ? "bg-[#e6dcca] font-semibold text-[#3a3122]" : "text-[#6f6552]"}`}
        >
          Tree
        </button>
        <div className="ml-auto flex gap-2">
          <button
            onClick={() => download(`attack-surface-${safeName}.json`, JSON.stringify(active, null, 2), "application/json")}
            className="rounded border border-[#d6c9b0] px-2 py-1 text-xs text-[#4a4032] hover:bg-[#e6dcca]"
          >
            JSON
          </button>
          <button
            onClick={() => download(`attack-surface-${safeName}.dot`, graphToDot(active), "text/vnd.graphviz")}
            className="rounded border border-[#d6c9b0] px-2 py-1 text-xs text-[#4a4032] hover:bg-[#e6dcca]"
          >
            DOT
          </button>
        </div>
      </div>

      <p className="mb-3 text-xs text-[#948972]">
        {sel === "combined"
          ? "Union of both crawl strategies. Endpoints are de-duplicated by shape (/users/1 and /users/2 collapse to one)."
          : `${sel.toUpperCase()} crawl only — its own discovered surface, score, and log.`}
      </p>

      {strat && <StrategyStatsRow stats={strat.stats} score={strat.score} />}

      {view === "graph" ? <GraphNodeLink graph={active} /> : <GraphTreeView graph={active} />}

      {strat && <CrawlLogView log={strat.log} />}
    </Panel>
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
  }">${esc(riskLevel || "minimal")}</span>`;

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
