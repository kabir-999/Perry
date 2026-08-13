import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { scansApi, targetsApi } from "../services/api";
import type { VerificationChallenge } from "../services/api";
import { AUTHORIZATION_STATEMENT } from "../types";
import { ACCENT_CYCLE } from "../theme";
import { useAuth } from "../contexts/AuthContext";

const CAPABILITIES = [
  "Crawling & attack surface",
  "API & subdomain discovery",
  "XSS · SQLi · traversal probes",
  "Source code & dependency scan",
  "AI risk assessment",
];

const REPO_URL_RE =
  /^(?:https?:\/\/)?(?:www\.)?(?:github|gitlab)\.com\/[\w.-]+\/[\w.-]+\/?$/i;

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
  const { user } = useAuth();
  const isDeveloper = user?.role === "developer";

  const [targetUrl, setTargetUrl] = useState("");
  const [repoUrl, setRepoUrl] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Set when the backend refuses an active scan because the deployment has
  // not been verified. Drives the inline verification flow below.
  const [needsVerification, setNeedsVerification] = useState(false);
  const [challenge, setChallenge] = useState<VerificationChallenge | null>(null);
  const [targetId, setTargetId] = useState<string | null>(null);
  // Meta tag first: it is the least friction on managed hosts.
  const [method, setMethod] = useState<"dns" | "http" | "meta">("meta");
  const [verifying, setVerifying] = useState(false);
  const [verifyNote, setVerifyNote] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setNeedsVerification(false);
    setVerifyNote(null);
    const repo = repoUrl.trim();
    if (repo && !REPO_URL_RE.test(repo)) {
      setError(
        "Enter a repository URL like https://github.com/owner/repo, or leave it blank.",
      );
      return;
    }
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
        ...(repo ? { repo_url: repo } : {}),
      });
      navigate(`/scans/${scan.id}`);
    } catch (err: any) {
      const detail = err?.response?.data?.detail;
      // The verification refusal returns a structured detail object; older
      // errors return a plain string. Render both as readable text.
      if (detail && typeof detail === "object") {
        setError(detail.message ?? "Request refused.");
        setNeedsVerification(detail.error === "target_verification_required");
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
        <h1 className="text-3xl font-bold tracking-tight text-[#2b2318]">
          Scan a website for security risks
        </h1>
        <p className="mx-auto mt-3 max-w-md text-sm text-[#6f6552]">
          Enter a URL and get an automated security assessment — no
          configuration needed. We handle the technical details.
        </p>
      </div>

      <form
        onSubmit={handleSubmit}
        className="animate-rise delay-1 rounded-2xl border border-[#e3d8c4] bg-[#fbf7ef] p-6 shadow-xl"
      >
        <label className="mb-1.5 block text-sm font-medium text-[#4a4032]">
          Website URL
        </label>
        <input
          required
          autoFocus
          type="url"
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          placeholder="https://example.com"
          className="w-full rounded-lg border border-[#d6c9b0] bg-[#f4efe6] px-4 py-3 text-base text-[#2b2318] outline-none transition-colors focus:border-[#c2410c]"
        />

        {isDeveloper && (<><label className="mb-1.5 mt-4 block text-sm font-medium text-[#4a4032]">
          GitHub repository{" "}
          <span className="font-normal text-[#6f6552]">(optional)</span>
        </label>
        <input
          type="text"
          value={repoUrl}
          onChange={(e) => setRepoUrl(e.target.value)}
          placeholder="https://github.com/owner/repo"
          className="w-full rounded-lg border border-[#d6c9b0] bg-[#f4efe6] px-4 py-3 text-base text-[#2b2318] outline-none transition-colors focus:border-[#c2410c]"
        />
        <p className="mt-1.5 text-xs text-[#6f6552]">
          Adds source-code analysis: hardcoded secrets, injection patterns, and
          vulnerable dependencies, each reported with the exact file and line.
          Must be a public repo. Leave blank to skip source analysis entirely —
          we won't look for a repository on your behalf.
        </p></>)}

        <label className="mt-4 flex items-start gap-3 rounded-lg border border-[#e3d8c4] bg-[#f0e9dc] p-3.5 text-sm text-[#4a4032]">
          <input
            type="checkbox"
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
            className="mt-0.5 accent-[#c2410c]"
          />
          <span>
            I own this site or have explicit authorization to test it.{" "}
            <span className="text-[#6f6552]">
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

        {needsVerification && (
          <div className="animate-rise mt-4 rounded-xl border border-[#e8d09a] bg-[#fdf3e3] p-4">
            <h3 className="text-sm font-semibold text-[#b45309]">
              Target verification required
            </h3>
            <p className="mt-1 text-xs leading-relaxed text-[#4a4032]">
              Active tests send crafted payloads, so Sentinel runs them only
              against a deployment you control. Publishing the token below
              proves technical control of the host — it is not a claim of legal
              ownership. You can also uncheck the authorization box and run a
              read-only scan instead.
            </p>

            <div className="mt-3 flex gap-2">
              {(["meta", "http", "dns"] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => {
                    setMethod(m);
                    setChallenge(null);
                  }}
                  className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
                    method === m
                      ? "bg-[#b45309] text-white"
                      : "border border-[#e8d09a] text-[#6f6552]"
                  }`}
                >
                  {m === "meta"
                    ? "Meta tag"
                    : m === "http"
                      ? "HTTP file"
                      : "DNS record"}
                </button>
              ))}
              <button
                type="button"
                disabled={verifying}
                onClick={async () => {
                  setVerifying(true);
                  setVerifyNote(null);
                  try {
                    const res = await targetsApi.add(targetUrl.trim(), method);
                    setChallenge(res.verification);
                    setTargetId(res.target.id);
                  } catch {
                    setVerifyNote("Could not create the verification challenge.");
                  } finally {
                    setVerifying(false);
                  }
                }}
                className="ml-auto rounded-lg bg-[#c2410c] px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-60"
              >
                {challenge ? "Regenerate token" : "Get verification token"}
              </button>
            </div>

            {challenge && (
              <div className="mt-3">
                <p className="text-xs text-[#4a4032]">{challenge.instruction}</p>
                <pre className="mt-2 overflow-x-auto rounded-md border border-[#d9cdb6] bg-[#26221b] px-3 py-2 text-xs text-[#f0e9dc]">
                  <code>
                    {challenge.method === "meta"
                      ? challenge.tag
                      : challenge.method === "dns"
                        ? `${challenge.record_name}  ${challenge.record_type}\n${challenge.record_value}`
                        : `${challenge.file_path}\n${challenge.file_content}`}
                  </code>
                </pre>
                <button
                  type="button"
                  disabled={verifying || !targetId}
                  onClick={async () => {
                    if (!targetId) return;
                    setVerifying(true);
                    try {
                      const res = await targetsApi.verify(targetId);
                      if (res.verified) {
                        setNeedsVerification(false);
                        setError(null);
                        setVerifyNote(
                          "Verified. You can start the active scan now.",
                        );
                      } else {
                        setVerifyNote(res.detail);
                      }
                    } catch {
                      setVerifyNote("Verification could not be completed.");
                    } finally {
                      setVerifying(false);
                    }
                  }}
                  className="lift mt-3 w-full rounded-lg bg-[#0f766e] px-4 py-2.5 text-sm font-semibold text-white disabled:opacity-60"
                >
                  {verifying ? "Checking…" : "Verify Target"}
                </button>
              </div>
            )}

            {verifyNote && (
              <p className="mt-2 text-xs text-[#4a4032]">{verifyNote}</p>
            )}
          </div>
        )}

        <button
          type="submit"
          disabled={submitting}
          className="lift mt-5 w-full rounded-xl bg-[#c2410c] px-4 py-3 text-sm font-semibold text-white shadow-md transition-colors hover:bg-[#9a3412] disabled:cursor-not-allowed disabled:opacity-60"
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
            className="rounded-full border border-[#e3d8c4] bg-[#fbf7ef] px-3 py-1 text-xs text-[#6f6552]"
          >
            {c}
          </span>
        ))}
      </div>

      <section className="mt-10">
        <h2 className="text-center text-lg font-semibold text-[#2b2318]">
          Why scan before you deploy
        </h2>
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          {BENEFITS.map((b, i) => {
            const accent = ACCENT_CYCLE[i % ACCENT_CYCLE.length];
            return (
              <div
                key={b.title}
                className="lift animate-rise rounded-xl border border-[#e3d8c4] bg-[#fbf7ef] p-4 hover:shadow-md"
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
                  <h3 className="text-sm font-semibold text-[#3a3122]">
                    {b.title}
                  </h3>
                </div>
                <p className="mt-1.5 text-xs leading-relaxed text-[#6f6552]">
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
