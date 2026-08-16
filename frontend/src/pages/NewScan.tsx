import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { scansApi } from "../services/api";
import { AUTHORIZATION_STATEMENT } from "../types";
import { ACCENT_CYCLE } from "../theme";

const CAPABILITIES = [
  "Crawling & attack surface",
  "API & subdomain discovery",
  "XSS · SQLi · traversal probes",
  "12 attack modules",
  "Deterministic risk scoring",
];

// Why a developer should run this before shipping.
const BENEFITS = [
  {
    title: "Early detection of vulnerabilities",
    body: "Security issues surface while you are still building, so they can be fixed on the spot instead of becoming an incident later.",
  },
  {
    title: "Improved code quality",
    body: "Findings point at the exact file and line, which encourages secure patterns and makes the same mistake less likely next time.",
  },
  {
    title: "Increased security awareness",
    body: "Every finding explains what the issue is, why it matters, and how attackers use it — so the team learns the class of bug, not just the one instance.",
  },
  {
    title: "Enhanced application security",
    body: "Fixing what the scan finds before deployment reduces the window in which a live application can be exploited.",
  },
];

export default function NewScan() {
  const navigate = useNavigate();

  const [targetUrl, setTargetUrl] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      // Scope, modules, concurrency, and limits are all chosen automatically.
      const scan = await scansApi.create({
        target_url: targetUrl.trim(),
        allowed_domains: [],
        modules: [],
        // Confirming ownership unlocks the active injection tests; without
        // it the same pipeline runs read-only.
        ...(authorized ? { authorization_statement: AUTHORIZATION_STATEMENT } : {}),
      });
      navigate(`/scans/${scan.id}`);
    } catch (err: any) {
      const detail = err?.response?.data?.detail;
      if (detail && typeof detail === "object") {
        setError(detail.message ?? "Request refused.");
      } else if (typeof detail === "string") {
        setError(detail);
      } else if (Array.isArray(detail) && detail[0]?.msg) {
        setError(String(detail[0].msg).replace(/^Value error, /, ""));
      } else {
        setError("Failed to start the scan. Please try again.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="mx-auto max-w-2xl pt-6 sm:pt-16">
      <div className="animate-rise mb-8 text-center">
        <h1 className="text-3xl font-bold tracking-tight text-[#123331]">
          Scan a website for security risks
        </h1>
        <p className="mx-auto mt-3 max-w-md text-sm text-[#4f716c]">
          Enter a URL and get an automated security assessment — no
          configuration needed. We handle the technical details.
        </p>
      </div>

      <form
        onSubmit={handleSubmit}
        className="animate-rise delay-1 rounded-2xl border border-[#b9d6cf] bg-[#fbf7ef] p-6 shadow-xl"
      >
        <label className="mb-1.5 block text-sm font-medium text-[#254c48]">
          Website URL
        </label>
        <input
          required
          autoFocus
          type="url"
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          placeholder="https://example.com"
          className="w-full rounded-lg border border-[#8fbab1] bg-[#eef8f5] px-4 py-3 text-base text-[#123331] outline-none transition-colors focus:border-[#08756f]"
        />

        <label className="mt-4 flex items-start gap-3 rounded-lg border border-[#b9d6cf] bg-[#dff0ec] p-3.5 text-sm text-[#254c48]">
          <input
            type="checkbox"
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
            className="mt-0.5 accent-[#08756f]"
          />
          <span>
            I own this site or have explicit authorization to test it.{" "}
            <span className="text-[#4f716c]">
              Required for active tests (XSS, SQL injection, traversal). Leave
              unchecked to run everything else read-only.
            </span>
          </span>
        </label>

        {error && (
          <div className="mt-4 rounded-lg border border-[#e7b7ad] bg-[#fbeae6] p-3 text-sm text-[#9f1239]">
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={submitting}
          className="lift mt-5 w-full rounded-xl bg-[#8d5428] px-4 py-3 text-sm font-semibold text-white shadow-md transition-colors hover:bg-[#6f3f1f] disabled:cursor-not-allowed disabled:opacity-60"
        >
          {submitting
            ? "Starting scan…"
            : authorized
              ? "Run full scan"
              : "Run read-only scan"}
        </button>
      </form>

      <div className="mt-6 flex flex-wrap justify-center gap-2">
        {CAPABILITIES.map((c) => (
          <span
            key={c}
            className="rounded-full border border-[#b9d6cf] bg-[#fbf7ef] px-3 py-1 text-xs text-[#4f716c]"
          >
            {c}
          </span>
        ))}
      </div>

      <section className="mt-10">
        <h2 className="text-center text-lg font-semibold text-[#123331]">
          Why scan before you deploy
        </h2>
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          {BENEFITS.map((b, i) => {
            const accent = ACCENT_CYCLE[i % ACCENT_CYCLE.length];
            return (
              <div
                key={b.title}
                className="lift animate-rise rounded-xl border border-[#b9d6cf] bg-[#fbf7ef] p-4 hover:shadow-md"
                style={{
                  animationDelay: `${i * 60}ms`,
                  borderLeft: `3px solid ${accent}`,
                }}
              >
                <div className="flex items-baseline gap-2">
                  <span
                    className="text-xs font-bold tabular-nums"
                    style={{ color: accent }}
                  >
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  <h3 className="text-sm font-semibold text-[#254c48]">
                    {b.title}
                  </h3>
                </div>
                <p className="mt-1.5 text-xs leading-relaxed text-[#4f716c]">
                  {b.body}
                </p>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}
