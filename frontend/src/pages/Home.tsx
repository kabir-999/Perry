import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import MascotLogo from "../components/MascotLogo";
import PerryFaceReveal from "../components/PerryFaceReveal";
import { useAuth } from "../contexts/AuthContext";

const WORKFLOW = [
  {
    label: "Target",
    body: "Start with a deployed URL or pipeline target.",
    icon: "URL",
  },
  {
    label: "Discover",
    body: "Map URLs, APIs, forms, parameters, and assets.",
    icon: "MAP",
  },
  {
    label: "Test",
    body: "Run focused security checks across the attack surface.",
    icon: "TST",
  },
  {
    label: "Validate",
    body: "Confirm evidence before calling out a finding.",
    icon: "OK",
  },
  {
    label: "Report",
    body: "Give developers concise evidence and fixes.",
    icon: "PDF",
  },
];

const FEATURES = [
  "URL Scanning",
  "CI/CD Security",
  "Attack-Surface Discovery",
  "Evidence-Based Validation",
  "Code-Level Spy",
];

const STEPS = [
  "Enter your target",
  "Perry discovers the attack surface",
  "Security tests are executed",
  "Findings are validated",
  "Developers receive actionable evidence",
];

export default function Home() {
  const { user, loading, logout } = useAuth();
  const navigate = useNavigate();

  function handleLogout() {
    logout();
    navigate("/", { replace: true });
  }

  // A brief, full-screen reveal of Perry's face on first load — the same
  // "open with the icon" beat as Claude's own startup, before the page's
  // real content fades in underneath it. The dot-matrix face itself takes
  // ~950ms to finish assembling (PerryFaceReveal's per-dot delays), so the
  // hold is timed to let it fully form before the fade-out starts. Mounted
  // throughout the fade-out (opacity + pointer-events only) and unmounted
  // once the transition finishes, so it actually animates away instead of
  // vanishing instantly.
  const [introVisible, setIntroVisible] = useState(true);
  const [introMounted, setIntroMounted] = useState(true);

  useEffect(() => {
    const fadeStart = setTimeout(() => setIntroVisible(false), 1500);
    const unmount = setTimeout(() => setIntroMounted(false), 2000);
    return () => {
      clearTimeout(fadeStart);
      clearTimeout(unmount);
    };
  }, []);

  return (
    <section className="platypus-field min-h-screen bg-[#eef8f5] text-[#123331]">
      {introMounted && (
        <div
          className={`platypus-field fixed inset-0 z-50 grid place-items-center bg-[#eef8f5] transition-opacity duration-500 ${
            introVisible ? "opacity-100" : "pointer-events-none opacity-0"
          }`}
          aria-hidden="true"
        >
          <PerryFaceReveal className="h-[46vmin] w-[46vmin] max-h-[50vh] max-w-[50vw]" />
        </div>
      )}

      <div className="flex h-16 items-center justify-between bg-[#12b3ad] px-6">
        <Link to="/" aria-label="Go to home">
          <MascotLogo size="md" />
        </Link>
        {!loading && (
          <div className="flex items-center gap-3">
            {user ? (
              <>
                <span className="text-sm font-medium text-white" title={user.email}>
                  {user.display_name || user.email}
                </span>
                <button
                  onClick={handleLogout}
                  className="rounded-lg px-3 py-1.5 text-sm font-medium text-white/85 transition-colors hover:text-white"
                >
                  Sign out
                </button>
              </>
            ) : (
              <>
                <Link
                  to="/login"
                  className="rounded-lg px-3 py-1.5 text-sm font-medium text-white/85 transition-colors hover:text-white"
                >
                  Log in
                </Link>
                <Link
                  to="/login?next=%2Fprojects"
                  className="lift rounded-lg bg-[#8d5428] px-3.5 py-1.5 text-sm font-medium text-white shadow-sm transition-colors hover:bg-[#6f3f1f]"
                >
                  Sign up
                </Link>
              </>
            )}
          </div>
        )}
      </div>

      <div className="mx-auto max-w-7xl px-6 py-12 sm:px-8 lg:px-12">
        <div className="grid items-center gap-10 lg:grid-cols-[minmax(0,0.95fr)_minmax(24rem,0.8fr)]">
          <div>
            <p className="text-xs font-bold uppercase tracking-[0.2em] text-[#08756f]">
              Security scanning for teams without a security team
            </p>

            <h1 className="mt-4 max-w-4xl text-5xl font-black uppercase leading-[1.03] tracking-normal text-[#4b2104] sm:text-6xl lg:text-7xl">
              Find vulnerabilities
              <br />
              before attackers do
            </h1>

            <p className="mt-6 max-w-2xl text-lg leading-relaxed text-[#4f716c] sm:text-xl">
              Scan a deployed website or integrate security testing directly
              into your development workflow. Discover, test, validate, and
              understand vulnerabilities before they reach production.
            </p>

            <div className="mt-8 flex flex-wrap gap-4">
              <Link
                to="/login?next=%2Fscans%2Fnew"
                className="inline-flex h-14 items-center justify-center rounded-lg bg-[#8d5428] px-7 text-sm font-bold uppercase tracking-wide text-white shadow-sm transition-colors hover:bg-[#6f3f1f]"
              >
                Start a Scan
              </Link>
              <Link
                to="/login?next=%2Fprojects"
                className="inline-flex h-14 items-center justify-center rounded-lg border border-[#8fbab1] bg-[#fbf7ef] px-7 text-sm font-bold uppercase tracking-wide text-[#123331] transition-colors hover:border-[#08756f]"
              >
                View Projects
              </Link>
            </div>
          </div>

          <div className="rounded-xl border border-[#b9d6cf] bg-[#fbf7ef] p-4 shadow-sm">
            <div className="space-y-2">
              {WORKFLOW.map((item, index) => (
                <div key={item.label}>
                  <div className="flex items-center gap-3 rounded-lg border border-[#d5e7e2] bg-white/70 p-3">
                    <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-[#dff0ec] text-[10px] font-black text-[#08756f]">
                      {item.icon}
                    </span>
                    <div>
                      <p className="text-sm font-bold uppercase tracking-wide text-[#123331]">
                        {item.label}
                      </p>
                      <p className="text-xs leading-relaxed text-[#4f716c]">
                        {item.body}
                      </p>
                    </div>
                  </div>
                  {index < WORKFLOW.length - 1 && (
                    <div className="flex justify-center py-1 text-xs font-bold text-[#8fbab1]">
                      |
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="mt-10 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          {FEATURES.map((feature) => (
            <div
              key={feature}
              className="rounded-lg border border-[#b9d6cf] bg-[#fbf7ef] px-4 py-3 text-center text-xs font-bold uppercase tracking-wide text-[#254c48]"
            >
              {feature}
            </div>
          ))}
        </div>

        <section className="mt-10 rounded-xl border border-[#b9d6cf] bg-[#fbf7ef] p-5">
          <h2 className="text-lg font-bold text-[#123331]">How it works</h2>
          <div className="mt-4 grid gap-3 md:grid-cols-5">
            {STEPS.map((step, index) => (
              <div key={step} className="rounded-lg bg-[#eef8f5] p-4">
                <p className="text-xs font-bold text-[#8d5428]">
                  {String(index + 1).padStart(2, "0")}
                </p>
                <p className="mt-2 text-sm font-semibold text-[#254c48]">
                  {step}
                </p>
              </div>
            ))}
          </div>
        </section>
      </div>
    </section>
  );
}
