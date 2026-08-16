import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import MascotLogo from "../components/MascotLogo";
import { useAuth } from "../contexts/AuthContext";
import type { UserRole } from "../types";

type Side = {
  id: UserRole;
  eyebrow: string;
  lead: string;
  emphasis: string;
  blurb: string;
  points: string[];
  accent: string;
  accentHover: string;
  tint: string;
  ring: string;
};

const SIDES: Side[] = [
  {
    id: "developer",
    eyebrow: "BUILD",
    lead: "For",
    emphasis: "Developers",
    blurb:
      "Scan a site you own end to end — attack surface and live vulnerabilities across 12 attack classes — before it ships.",
    points: [
      "Crawls your site and probes for real vulnerabilities",
      "Honest per-attack coverage: discovered vs. actually tested",
      "Deterministic risk scoring and a downloadable report",
    ],
    accent: "#08756f",
    accentHover: "#075f5a",
    tint: "rgba(18,166,160,0.12)",
    ring: "rgba(8,117,111,0.35)",
  },
];

export default function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const { login, signup } = useAuth();
  const params = new URLSearchParams(location.search);
  const rawNext = params.get("next");
  const next =
    rawNext && rawNext.startsWith("/") && !rawNext.startsWith("//")
      ? rawNext
      : "/projects";

  // Single audience: developers scanning sites they own.
  const side = SIDES[0];
  const [mode, setMode] = useState<"login" | "signup">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      if (mode === "login") {
        await login({ email: email.trim(), password });
      } else {
        await signup({
          email: email.trim(),
          password,
          display_name: displayName.trim(),
          role: "developer",
        });
      }
      navigate(next, { replace: true });
    } catch (err: any) {
      const detail = err?.response?.data?.detail;
      setError(
        typeof detail === "string"
          ? detail
          : Array.isArray(detail) && detail[0]?.msg
            ? String(detail[0].msg).replace(/^Value error, /, "")
            : "Something went wrong. Please try again.",
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="platypus-field min-h-screen bg-[#eef8f5]">
      <div className="mx-auto flex min-h-screen max-w-6xl flex-col px-5 py-8">
        <header className="flex items-center gap-2.5">
          <Link to="/" aria-label="Go to home">
            <MascotLogo size="md" />
          </Link>
        </header>

        <Hero />
        <AuthPanel
            side={side}
            mode={mode}
            setMode={(m) => {
              setMode(m);
              setError(null);
            }}
            email={email}
            setEmail={setEmail}
            password={password}
            setPassword={setPassword}
            displayName={displayName}
            setDisplayName={setDisplayName}
            error={error}
            submitting={submitting}
            onSubmit={handleSubmit}
        />
      </div>
    </div>
  );
}

/* --------------------------------- hero ---------------------------------- */

function Hero() {
  return (
    <div className="animate-rise pt-8 text-center sm:pt-10">
      <div className="flex justify-center">
        <MascotLogo size="lg" />
      </div>
      <p className="mx-auto mt-5 max-w-xl text-[15px] leading-relaxed text-[#4f716c]">
        Scan a site you own end to end — attack surface, live vulnerabilities,
        and the source behind them — before it ships.
      </p>
      <div className="mt-6 flex flex-wrap justify-center gap-2">
        {[
          "Crawl & attack surface",
          "12 attack modules",
          "Test matrix & coverage",
          "Deterministic risk scoring",
        ].map((c, i) => (
          <span
            key={c}
            className="animate-rise rounded-full border border-[#b9d6cf] bg-[#fbf7ef] px-3 py-1 text-xs text-[#4f716c]"
            style={{ animationDelay: `${i * 60}ms` }}
          >
            {c}
          </span>
        ))}
      </div>
    </div>
  );
}

/* ------------------------------- auth panel ------------------------------ */

interface PanelProps {
  side: Side;
  mode: "login" | "signup";
  setMode: (m: "login" | "signup") => void;
  email: string;
  setEmail: (v: string) => void;
  password: string;
  setPassword: (v: string) => void;
  displayName: string;
  setDisplayName: (v: string) => void;
  error: string | null;
  submitting: boolean;
  onSubmit: (e: React.FormEvent) => void;
}

function AuthPanel({
  side,
  mode,
  setMode,
  email,
  setEmail,
  password,
  setPassword,
  displayName,
  setDisplayName,
  error,
  submitting,
  onSubmit,
}: PanelProps) {
  const field =
    "w-full rounded-xl border border-[#8fbab1] bg-[#eef8f5] px-4 py-3 text-sm text-[#123331] outline-none transition-colors";

  return (
    <div className="flex flex-1 items-start justify-center py-10">
      <div className="w-full max-w-md">
        <div
          className="animate-slide-in overflow-hidden rounded-2xl border bg-[#fbf7ef] shadow-xl"
          style={{ borderColor: side.ring }}
        >
          <div
            className="px-7 py-5"
            style={{ background: side.tint, borderBottom: `1px solid ${side.ring}` }}
          >
            <p
              className="text-[10px] font-bold tracking-[0.14em]"
              style={{ color: side.accent }}
            >
              {side.eyebrow}
            </p>
            <h2 className="mt-1 text-xl font-bold tracking-tight text-[#123331]">
              {side.lead}{" "}
              <span className="italic" style={{ color: side.accent }}>
                {side.emphasis}
              </span>
            </h2>
            <p className="mt-1 text-xs text-[#4f716c]">
              {mode === "login"
                ? "Welcome back — sign in to continue."
                : side.id === "developer"
                  ? "You'll confirm you own each site before scanning it."
                  : "Free to use. No card, no setup."}
            </p>
          </div>

          <form onSubmit={onSubmit} className="px-7 py-6">
            <div className="mb-5 flex rounded-xl border border-[#b9d6cf] bg-[#dff0ec] p-1">
              {(["login", "signup"] as const).map((m) => {
                const active = mode === m;
                return (
                  <button
                    key={m}
                    type="button"
                    onClick={() => setMode(m)}
                    className="flex-1 rounded-lg px-3 py-2 text-sm font-medium transition-all"
                    style={
                      active
                        ? {
                            background: "#fbf7ef",
                            color: side.accent,
                            boxShadow: "0 1px 3px rgba(18,51,49,0.10)",
                          }
                        : { color: "#4f716c" }
                    }
                  >
                    {m === "login" ? "Sign in" : "Create account"}
                  </button>
                );
              })}
            </div>

            {mode === "signup" && (
              <div className="animate-fade mb-4">
                <label className="mb-1.5 block text-sm font-medium text-[#254c48]">
                  Name{" "}
                  <span className="font-normal text-[#4f716c]">(optional)</span>
                </label>
                <input
                  type="text"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="Ada"
                  className={field}
                  onFocus={(e) => (e.currentTarget.style.borderColor = side.accent)}
                  onBlur={(e) => (e.currentTarget.style.borderColor = "#8fbab1")}
                />
              </div>
            )}

            <label className="mb-1.5 block text-sm font-medium text-[#254c48]">
              Email
            </label>
            <input
              required
              type="email"
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              className={`${field} mb-4`}
              onFocus={(e) => (e.currentTarget.style.borderColor = side.accent)}
              onBlur={(e) => (e.currentTarget.style.borderColor = "#8fbab1")}
            />

            <label className="mb-1.5 block text-sm font-medium text-[#254c48]">
              Password
            </label>
            <input
              required
              type="password"
              autoComplete={mode === "login" ? "current-password" : "new-password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={mode === "signup" ? "At least 8 characters" : "Password"}
              className={field}
              onFocus={(e) => (e.currentTarget.style.borderColor = side.accent)}
              onBlur={(e) => (e.currentTarget.style.borderColor = "#8fbab1")}
            />
            {mode === "signup" && (
              <p className="mt-1.5 text-xs text-[#4f716c]">
                Mix letters with numbers or symbols.
              </p>
            )}

            {error && (
              <div className="animate-fade mt-4 rounded-xl border border-[#e7b7ad] bg-[#fbeae6] p-3 text-sm text-[#9f1239]">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={submitting}
              className="lift mt-6 w-full rounded-xl px-4 py-3 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:opacity-60"
              style={{
                background: side.accent,
                boxShadow: `0 10px 24px -12px ${side.accent}`,
              }}
            >
              {submitting
                ? "Please wait…"
                : mode === "login"
                  ? "Sign in"
                  : "Create account"}
            </button>

            <p className="mt-4 text-center text-[13px] text-[#4f716c]">
              {mode === "login" ? "Don't have an account? " : "Already have one? "}
              <button
                type="button"
                onClick={() => setMode(mode === "login" ? "signup" : "login")}
                className="font-semibold hover:underline"
                style={{ color: side.accent }}
              >
                {mode === "login" ? "Sign up." : "Sign in."}
              </button>
            </p>
          </form>
        </div>
      </div>
    </div>
  );
}
