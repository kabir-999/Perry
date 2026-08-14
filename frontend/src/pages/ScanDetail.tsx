import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type ReactNode,
} from "react";
import { Link, useParams } from "react-router-dom";
import { scansApi } from "../services/api";
import { SEVERITY_COLOR } from "../theme";
import type {
  Finding,
  RepoInfo,
  RiskFactor,
  RiskLevel,
  ScanSnapshot,
  SourceFinding,
  TestResult,
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

export default function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>();
  const [snap, setSnap] = useState<ScanSnapshot | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [sourceFindings, setSourceFindings] = useState<SourceFinding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const lastFindingCount = useRef(-1);
  const fetchedSource = useRef(false);
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

  // Source findings are written in the same commit that sets repo_info, so
  // its presence means the rows are queryable.
  useEffect(() => {
    if (!scanId || !snap?.repo_info || fetchedSource.current) return;
    fetchedSource.current = true;
    scansApi
      .sourceFindings(scanId)
      .then(setSourceFindings)
      .catch(() => undefined);
  }, [scanId, snap?.repo_info]);

  const fast = snap?.fast_result ?? null;
  const target = fast?.target || snap?.id || "";
  const aiOk = !!snap?.ai_analyzed;
  // The deterministic engine owns the score; the AI layer only narrates it.
  const sentinel = snap?.sentinel_risk;
  const riskLevel: RiskLevel = (sentinel?.severity?.toLowerCase() ??
    (aiOk ? snap!.final_risk : "")) as RiskLevel;
  const riskScore = sentinel?.score ?? (aiOk ? snap!.risk_score : 0);
  const riskFactors: RiskFactor[] = snap?.risk_factors ?? [];

  // Severity distribution: prefer Groq's statistics, else derive from findings.
  const severityCounts = useMemo(() => {
    const c: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      minimal: 0,
      info: 0,
    };
    if (aiOk && snap?.ai_statistics) {
      for (const k of STAT_ORDER) c[k] = snap.ai_statistics[k] ?? 0;
      return c;
    }
    for (const f of findings) c[f.severity] = (c[f.severity] ?? 0) + 1;
    return c;
  }, [aiOk, snap?.ai_statistics, findings]);
  const totalSev = STAT_ORDER.reduce((n, k) => n + (severityCounts[k] ?? 0), 0);

  const checksDone = useMemo(
    () => new Set(snap?.checks_done ?? []),
    [snap?.checks_done],
  );

  // Dependency advisories render as a compact list; everything else gets a
  // code block, most severe first.
  const codeIssues = useMemo(
    () =>
      sourceFindings
        .filter((sf) => sf.finding_type !== "dependency")
        .sort(
          (a, b) =>
            SEVERITY_ORDER.indexOf(a.severity) -
            SEVERITY_ORDER.indexOf(b.severity),
        ),
    [sourceFindings],
  );
  const vulnDeps = useMemo(
    () => sourceFindings.filter((sf) => sf.finding_type === "dependency"),
    [sourceFindings],
  );

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

  const accent = aiOk ? riskHex(riskLevel || "minimal") : "#8a8173";

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
            {aiOk ? (
              <div className="mt-1 flex items-baseline gap-3">
                <span
                  className="text-4xl font-bold capitalize"
                  style={{ color: accent }}
                >
                  {RISK[riskLevel]?.label ?? "Minimal"}
                </span>
                <span className="text-sm text-[#6f6552]">final risk</span>
              </div>
            ) : (
              <div className="mt-1 text-2xl font-semibold text-[#4a4032]">
                {isTerminal ? "AI analysis unavailable" : "Analyzing…"}
              </div>
            )}
          </div>

          {aiOk && <ScoreRing score={riskScore} color={accent} />}
        </div>

        {/* Severity bar (from Groq stats, or findings) */}
        {aiOk && totalSev > 0 && (
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

        {!aiOk && isTerminal && snap.ai_error && (
          <p className="mt-3 text-sm text-[#6f6552]">{snap.ai_error}</p>
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

      {/* AI Security Summary */}
      {aiOk ? (
        <Panel title="AI Security Summary" accent={accent}>
          <p className="whitespace-pre-wrap text-sm leading-relaxed text-[#4a4032]">
            {snap.ai_summary || "No summary returned."}
          </p>
        </Panel>
      ) : (
        isTerminal && (
          <p className="rounded-xl border border-[#e3d8c4] bg-[#fbf7ef] px-4 py-3 text-sm text-[#948972]">
            {snap.ai_error || "AI analysis unavailable."}
          </p>
        )
      )}

      {/* Sentinel Risk — deterministic score with its contributors.
          Scans predating the risk engine carry an empty object, so the guard
          checks for real content rather than mere truthiness. */}
      {sentinel && typeof sentinel.score === "number" && (
        <Panel title={`Sentinel Overall Risk — ${sentinel.score}/100 ${sentinel.severity}`}>
          <p className="mb-1 text-sm text-[#4a4032]">
            {sentinel.explanation ?? ""}
          </p>
          {sentinel.aggregation && (
            <p className="mb-2 text-xs text-[#4a4032]">
              {sentinel.aggregation.base} pts from the strongest finding
              {sentinel.aggregation.other_findings > 0 &&
                ` + ${sentinel.aggregation.added_by_others} pts from ${sentinel.aggregation.other_findings} other finding(s)`}
              {" = "}
              {sentinel.score} / 100. {sentinel.aggregation.formula}.
            </p>
          )}
          <p className="mb-4 text-xs text-[#948972]">
            {sentinel.methodology ?? "Sentinel Risk Model"} ·{" "}
            {sentinel.findings_considered ?? 0} finding(s) considered
            {(sentinel.third_party_excluded ?? 0) > 0 &&
              ` · ${sentinel.third_party_excluded} third-party observation(s) excluded`}
          </p>
          <ul className="space-y-2">
            {(sentinel.contributors ?? []).map((c, i) => (
              <li
                key={c.finding_id + i}
                className="rounded-lg border border-[#e3d8c4] bg-[#f0e9dc] p-3"
              >
                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="text-xs font-bold text-[#6f6552]">
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  <span className="text-sm font-semibold text-[#2b2318]">
                    {c.title}
                  </span>
                  {c.cvss && (
                    <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold"
                      style={{ background: "#be123c22", color: "#be123c" }}>
                      CVSS v4.0 {c.cvss.base_score} {c.cvss.severity}
                    </span>
                  )}
                  {c.hardening && (
                    <span className="rounded bg-[#b4530922] px-1.5 py-0.5 text-[10px] font-semibold text-[#b45309]">
                      Hardening
                    </span>
                  )}
                  <span className="ml-auto text-xs font-medium text-[#4a4032]">
                    +{c.applied_points ?? 0} pts
                  </span>
                </div>
                <p className="mt-1 text-xs text-[#6f6552]">
                  Confidence {Math.round(c.confidence * 100)}% ·{" "}
                  {c.affected_urls} endpoint(s) · {c.detection_status}
                  {c.hardening?.means && (
                    <span className="block text-[#948972]">
                      {c.hardening.means}
                    </span>
                  )}
                  {c.cvss?.vector && (
                    <span className="block break-all font-mono text-[10px] text-[#948972]">
                      {c.cvss.vector}
                    </span>
                  )}
                </p>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      {/* Risk Factors (Groq) */}
      {aiOk && riskFactors.length > 0 && (
        <Panel title={`Risk Factors (${riskFactors.length})`}>
          <ul className="space-y-3">
            {riskFactors.map((rf, i) => (
              <RiskFactorCard key={i} rf={rf} />
            ))}
          </ul>
        </Panel>
      )}

      {/* Source Code Analysis */}
      {snap.repo_info && (
        <Panel title="Source Code Analysis" accent="#0ea5e9">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <p className="text-sm font-semibold text-[#3a3122]">
                <a href={snap.repo_info.url} target="_blank" rel="noreferrer" className="hover:underline">
                  {snap.repo_info.provider === "github" ? "GitHub" : "GitLab"}: {snap.repo_info.owner}/{snap.repo_info.name}
                </a>
              </p>
              <p className="text-xs text-[#6f6552]">
                {repoSourceLabel(snap.repo_info)}
              </p>
            </div>
            <div className="flex gap-4 text-center">
              <div>
                <p className="text-lg font-bold text-[#3a3122]">{snap.repo_info.files_analyzed}</p>
                <p className="text-[10px] uppercase tracking-wide text-[#6f6552]">Files</p>
              </div>
              <div>
                <p className="text-lg font-bold text-[#3a3122]">{snap.repo_info.source_findings_count}</p>
                <p className="text-[10px] uppercase tracking-wide text-[#6f6552]">Code Issues</p>
              </div>
              <div>
                <p className="text-lg font-bold text-[#3a3122]">{snap.repo_info.dependency_findings_count}</p>
                <p className="text-[10px] uppercase tracking-wide text-[#6f6552]">Dependencies</p>
              </div>
            </div>
          </div>
          {snap.repo_info.status === "error" && (
            <p className="mt-3 text-xs text-[#e11d48]">
              {snap.repo_info.error ||
                "Analysis failed or was skipped due to repository size limits."}
            </p>
          )}

          {codeIssues.length > 0 && (
            <ul className="mt-5 space-y-3 border-t border-[#e6dcca] pt-4">
              {codeIssues.map((sf) => (
                <SourceFindingCard key={sf.id} sf={sf} repoUrl={snap.repo_info!.url} />
              ))}
            </ul>
          )}

          {vulnDeps.length > 0 && (
            <div className="mt-5 border-t border-[#e6dcca] pt-4">
              <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-[#6f6552]">
                Vulnerable dependencies
              </p>
              <ul className="space-y-2">
                {vulnDeps.map((sf) => (
                  <DependencyRow key={sf.id} sf={sf} />
                ))}
              </ul>
            </div>
          )}

          {snap.repo_info.status !== "error" &&
            sourceFindings.length === 0 && (
              <p className="mt-3 text-xs text-[#6f6552]">
                No source-code issues found in the analyzed files.
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

      {/* Full test matrix — every test that ran and its outcome */}
      {(snap.test_results?.length ?? 0) > 0 && (
        <Panel title="Security Tests">
          <div className="grid gap-2 sm:grid-cols-2">
            {snap.test_results.map((t) => (
              <TestRow key={t.name} test={t} />
            ))}
          </div>
        </Panel>
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

      {/* Overall recommendation (Groq) */}
      {aiOk && snap.ai_recommendation && (
        <Panel title="Overall Recommendation" accent={accent}>
          <p className="whitespace-pre-wrap text-sm leading-relaxed text-[#4a4032]">
            {snap.ai_recommendation}
          </p>
        </Panel>
      )}
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
  children: ReactNode;
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

function RiskFactorCard({ rf }: { rf: RiskFactor }) {
  const color = SEV[rf.severity] ?? "#78716c";
  const confidence = Math.round((rf.confidence ?? 0) * 100);
  return (
    <li className="rounded-lg border border-[#e3d8c4] bg-[#f0e9dc] p-4">
      <div className="flex flex-wrap items-center gap-2">
        <span
          className="rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase"
          style={{ background: `${color}22`, color }}
        >
          {rf.severity}
        </span>
        <span className="text-sm font-semibold text-[#2b2318]">{rf.title}</span>
        <span className="ml-auto flex items-center gap-3 text-xs text-[#6f6552]">
          {rf.affected_urls > 0 && <span>{rf.affected_urls} affected</span>}
          <span>{confidence}% confidence</span>
        </span>
      </div>
      <div className="mt-2 space-y-1.5 text-sm">
        {rf.explanation && <Detail label="Explanation" text={rf.explanation} />}
        {rf.evidence && <Detail label="Evidence" text={rf.evidence} mono />}
        {rf.impact && <Detail label="Impact" text={rf.impact} />}
        {rf.recommendation && <Detail label="Fix" text={rf.recommendation} />}
      </div>
    </li>
  );
}

/** How the scanner found this repo, in the user's words. */
const REPO_SOURCE_LABEL: Record<string, string> = {
  git_config: "Found in an exposed .git/config on the site",
  package_json: "Found in the site's package.json",
  composer_json: "Found in the site's composer.json",
  security_txt: "Found in the site's security.txt",
  humans_txt: "Found in the site's humans.txt",
  page_link: "Linked from the site",
  github_pages_dns: "Matched via GitHub Pages DNS",
  github_search: "Matched by GitHub search",
  user_supplied: "Repository you provided",
};

function repoSourceLabel(info: RepoInfo): string {
  const how = REPO_SOURCE_LABEL[info.discovery_source ?? ""] ?? "Auto-discovered";
  const confidence = info.verified
    ? "confirmed"
    : `${Math.round(info.confidence * 100)}% match confidence`;
  return `${how} · ${confidence}`;
}

const SOURCE_ISSUE_LABEL: Record<string, string> = {
  hardcoded_secret: "Hardcoded secret",
  env_secret: "Secret in .env file",
  sql_injection: "Possible SQL injection",
  command_injection: "Possible command injection",
  weak_crypto: "Weak hash function (MD5/SHA1)",
};

const SOURCE_ISSUE_FIX: Record<string, string> = {
  hardcoded_secret:
    "Rotate this credential, move it to an environment variable, and purge it from git history.",
  env_secret:
    "Rotate this credential and remove the .env file from the repository (add it to .gitignore).",
  sql_injection:
    "Use parameterised queries or an ORM instead of building SQL with string concatenation.",
  command_injection:
    "Avoid passing user input to shell execution; use an argument array and validate inputs.",
  weak_crypto:
    "Use SHA-256 or stronger; for passwords use bcrypt, scrypt, or Argon2.",
};

function SourceFindingCard({ sf, repoUrl }: { sf: SourceFinding; repoUrl: string }) {
  const color = SEV[sf.severity] ?? "#78716c";
  const label =
    SOURCE_ISSUE_LABEL[sf.finding_type] ??
    sf.finding_type.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase());
  const fix = SOURCE_ISSUE_FIX[sf.finding_type];
  // GitHub and GitLab share the /blob/<ref>/<path>#L<n> shape.
  const fileUrl = `${repoUrl}/blob/HEAD/${sf.file}#L${sf.line}`;

  return (
    <li className="rounded-lg border border-[#e3d8c4] bg-[#f0e9dc] p-4">
      <div className="flex flex-wrap items-center gap-2">
        <span
          className="rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase"
          style={{ background: `${color}22`, color }}
        >
          {sf.severity}
        </span>
        <span className="text-sm font-semibold text-[#2b2318]">{label}</span>
        <span className="ml-auto text-xs text-[#6f6552]">{sf.confidence}</span>
      </div>

      <a
        href={fileUrl}
        target="_blank"
        rel="noreferrer"
        className="mt-2 block break-all font-mono text-xs text-[#6f6552] hover:underline"
      >
        {sf.file}:{sf.line}
      </a>

      {sf.code_context && (
        <pre className="mt-2 overflow-x-auto rounded-md border border-[#d9cdb6] bg-[#26221b] px-3 py-2.5 text-xs leading-relaxed text-[#f0e9dc]">
          <code>
            <span className="mr-3 select-none text-[#8a8173]">{sf.line}</span>
            {sf.code_context}
          </code>
        </pre>
      )}

      {sf.secret_type && sf.finding_type !== "hardcoded_secret" && (
        <p className="mt-2 text-xs text-[#6f6552]">
          Variable: <span className="font-mono">{sf.secret_type}</span>
        </p>
      )}
      {fix && <p className="mt-2 text-sm text-[#4a4032]">{fix}</p>}
    </li>
  );
}

function DependencyRow({ sf }: { sf: SourceFinding }) {
  const color = SEV[sf.severity] ?? "#78716c";
  return (
    <li className="flex flex-wrap items-center gap-2 rounded-lg border border-[#e3d8c4] bg-[#f0e9dc] px-3 py-2">
      <span
        className="rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase"
        style={{ background: `${color}22`, color }}
      >
        {sf.severity}
      </span>
      <span className="font-mono text-sm text-[#2b2318]">
        {sf.package}
        {sf.version && `@${sf.version}`}
      </span>
      {sf.ecosystem && (
        <span className="text-xs text-[#6f6552]">{sf.ecosystem}</span>
      )}
      {sf.advisory_id && (
        <a
          href={`https://osv.dev/vulnerability/${sf.advisory_id}`}
          target="_blank"
          rel="noreferrer"
          className="ml-auto text-xs text-[#0369a1] hover:underline"
        >
          {sf.advisory_id}
        </a>
      )}
    </li>
  );
}

function TestRow({ test }: { test: TestResult }) {
  const [open, setOpen] = useState(false);
  const log = test.log;
  const canExpand = !!log;
  const color = SEV[test.severity] ?? "#78716c";

  // Presentation per status — same colours as before, now inside an
  // expandable card.
  let wrapClass = "border-[#a7d3bf] bg-[#e7f4ec]";
  let wrapStyle: CSSProperties | undefined;
  let nameClass = "text-sm font-medium text-[#3a3122]";
  let badge: ReactNode;

  if (test.status === "not_authorized") {
    wrapClass = "border-[#e8d09a] bg-[#fdf3e3]";
    badge = (
      <span
        className="text-xs font-semibold text-[#b45309]"
        title="Active tests send crafted payloads, so they only run on a site you have confirmed you own."
      >
        Not run — needs authorization
      </span>
    );
  } else if (test.status === "not_applicable") {
    wrapClass = "border-[#ece3d3] bg-[#f4efe6] opacity-70";
    nameClass = "text-sm text-[#948972]";
    badge = <span className="text-xs text-[#b0a48c]">N/A</span>;
  } else if (test.status === "inconclusive") {
    wrapClass = "border-[#ddd6c8] bg-[#efece4]";
    badge = <span className="text-xs font-semibold text-[#948972]">Inconclusive</span>;
  } else if (test.status === "pass") {
    badge = (
      <span className="inline-flex items-center gap-1 text-xs font-semibold text-[#0f7a52]">
        ✓ Pass
      </span>
    );
  } else {
    wrapStyle = { borderColor: `${color}55`, background: `${color}12` };
    badge = (
      <span
        className="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase"
        style={{ background: `${color}22`, color }}
      >
        {test.severity}
        {test.count > 1 && <span className="opacity-80">×{test.count}</span>}
      </span>
    );
  }

  return (
    <div
      className={`rounded-lg border ${wrapStyle ? "" : wrapClass}`}
      style={wrapStyle}
    >
      <button
        type="button"
        disabled={!canExpand}
        onClick={() => setOpen((o) => !o)}
        className={`flex w-full items-center justify-between gap-2 px-3 py-2 text-left ${
          canExpand ? "cursor-pointer" : "cursor-default"
        }`}
      >
        <span className="flex min-w-0 items-center gap-2">
          {canExpand && (
            <span className="shrink-0 text-xs text-[#b0a48c]">
              {open ? "▾" : "▸"}
            </span>
          )}
          <span className={`truncate ${nameClass}`}>{test.name}</span>
        </span>
        {badge}
      </button>
      {open && log && (
        <div className="border-t border-black/5 px-3 pb-3 pt-2">
          <div className="mb-1.5 flex items-center justify-between text-[10px] uppercase tracking-wide text-[#948972]">
            <span>
              test_log · {log.test_type} · {log.finding_count} finding
              {log.finding_count === 1 ? "" : "s"} · {log.probe_requests} probe req
            </span>
            <button
              type="button"
              className="rounded border border-[#d9cdb6] px-2 py-0.5 text-[10px] normal-case text-[#7a6f57] hover:text-[#3a3122]"
              onClick={(e) => {
                e.stopPropagation();
                navigator.clipboard?.writeText(JSON.stringify(log, null, 2));
              }}
            >
              Copy JSON
            </button>
          </div>
          <pre className="max-h-96 overflow-auto rounded-md border border-[#d9cdb6] bg-[#26221b] px-3 py-2.5 text-xs leading-relaxed text-[#f0e9dc]">
            {JSON.stringify(log, null, 2)}
          </pre>
        </div>
      )}
    </div>
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
  const aiOk = snap.ai_analyzed;
  const riskLevel = aiOk ? snap.final_risk : "";
  const riskScore = aiOk ? snap.risk_score : 0;

  const factorRows = (snap.risk_factors ?? [])
    .map((rf) => {
      const color = SEV_HEX[rf.severity] ?? "#666";
      const rows: string[] = [];
      rows.push(
        `<div class="kv"><b>Severity</b> ${esc(rf.severity)} · ${Math.round(
          (rf.confidence ?? 0) * 100,
        )}% confidence · ${rf.affected_urls} affected</div>`,
      );
      if (rf.explanation) rows.push(`<div class="kv"><b>Explanation</b> ${esc(rf.explanation)}</div>`);
      if (rf.evidence) rows.push(`<div class="kv"><b>Evidence</b> <code>${esc(rf.evidence)}</code></div>`);
      if (rf.impact) rows.push(`<div class="kv"><b>Impact</b> ${esc(rf.impact)}</div>`);
      if (rf.recommendation) rows.push(`<div class="kv"><b>Fix</b> ${esc(rf.recommendation)}</div>`);
      return `<div class="finding"><div class="fhead"><span class="sev" style="background:${color}">${esc(
        rf.severity,
      )}</span><span class="ftitle">${esc(rf.title)}</span></div>${rows.join("")}</div>`;
    })
    .join("");

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

  const riskBadge = aiOk
    ? `<span class="risk" style="background:${SEV_HEX[riskLevel] ?? "#059669"}">${esc(
        riskLevel,
      )} · ${riskScore}/100</span>`
    : `<span class="risk" style="background:#8a8173">AI analysis unavailable</span>`;

  const testRows = (snap.test_results ?? [])
    .map((t) => {
      let out: string;
      if (t.status === "not_applicable") out = '<span style="color:#999">N/A</span>';
      else if (t.status === "pass") out = '<span style="color:#0f7a52">✓ Pass</span>';
      else {
        const c = SEV_HEX[t.severity] ?? "#666";
        out = `<span class="sev" style="background:${c}">${esc(t.severity)}${
          t.count > 1 ? ` ×${t.count}` : ""
        }</span>`;
      }
      return `<tr><td>${esc(t.name)}</td><td style="text-align:right">${out}</td></tr>`;
    })
    .join("");

  const repoRow = snap.repo_info
    ? `<h2>Source Code Analysis</h2><div class="muted">Analyzed ${snap.repo_info.files_analyzed} files in <a href="${esc(snap.repo_info.url)}">${esc(snap.repo_info.owner)}/${esc(snap.repo_info.name)}</a> (${Math.round(snap.repo_info.confidence * 100)}% match confidence). Found ${snap.repo_info.source_findings_count} code issues and ${snap.repo_info.dependency_findings_count} dependency vulnerabilities.</div>`
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
  <div class="muted">${findings.length} findings &nbsp;•&nbsp; ${snap.urls_discovered} URLs &nbsp;•&nbsp; ${snap.apis_discovered} APIs &nbsp;•&nbsp; ${snap.parameters_discovered} params &nbsp;•&nbsp; ${snap.subdomains_discovered} subdomains &nbsp;•&nbsp; ${snap.requests_made} requests</div>

  ${aiOk && snap.ai_summary ? `<h2>AI Security Summary</h2><div>${esc(snap.ai_summary)}</div>` : ""}
  ${repoRow}
  ${aiOk && factorRows ? `<h2>Risk Factors</h2>${factorRows}` : ""}
  ${aiOk && snap.ai_recommendation ? `<h2>Overall Recommendation</h2><div>${esc(snap.ai_recommendation)}</div>` : ""}
  ${!aiOk ? `<h2>AI Analysis</h2><div class="muted">${esc(snap.ai_error || "AI analysis unavailable.")}</div>` : ""}

  ${testRows ? `<h2>Security Tests</h2><table class="tests">${testRows}</table>` : ""}

  <h2>Findings (${findings.length})</h2>
  ${findingRows || '<div class="muted">No findings reported.</div>'}
</body></html>`;
}
