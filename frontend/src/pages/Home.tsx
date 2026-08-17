import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import Footer from "../components/Footer";
import MarketingHeader from "../components/MarketingHeader";
import PerryLogoMark from "../components/PerryLogoMark";
import Reveal from "../components/Reveal";
import TypewriterHeadline from "../components/TypewriterHeadline";

const HEADLINE_LINES = ["Find vulnerabilities", "before attackers do"];

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

const PRINCIPLES = [
  {
    title: "Evidence over noise",
    body: "Every finding ships with the request, response, and reasoning behind it — no unverified scanner output.",
  },
  {
    title: "Fits your workflow",
    body: "Scan a deployed URL from the browser, or run the CLI locally and in CI, without changing how your team already ships.",
  },
  {
    title: "Built for teams without a security team",
    body: "Perry discovers the attack surface, tests it, and hands developers fixes they can act on directly.",
  },
];

// Placeholder photos — swap in real headshots when available.
const TEAM = [
  "Kabir Mathur",
  "Aayush Chaudhari",
  "Aagnya Mistry",
  "Chhavi Rathod",
  "Chaahat Singh",
  "Daksh Goyal",
];

export default function Home() {
  // A brief, full-screen reveal of the Perry logo mark on first load — the
  // same "open with the icon" beat as Claude's own startup, before the
  // page's real content fades in underneath it. Mounted throughout the
  // fade-out (opacity + pointer-events only) and unmounted once the
  // transition finishes, so it actually animates away instead of vanishing
  // instantly.
  const [introVisible, setIntroVisible] = useState(true);
  const [introMounted, setIntroMounted] = useState(true);
  const location = useLocation();

  useEffect(() => {
    const fadeStart = setTimeout(() => setIntroVisible(false), 1500);
    const unmount = setTimeout(() => setIntroMounted(false), 2000);
    return () => {
      clearTimeout(fadeStart);
      clearTimeout(unmount);
    };
  }, []);

  // Deep links like /#how-it-works land here via client-side routing, which
  // doesn't get the browser's native hash scroll — so do it ourselves once
  // the section has had a chance to mount.
  useEffect(() => {
    if (!location.hash) return;
    const id = location.hash.slice(1);
    const t = setTimeout(() => {
      document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 100);
    return () => clearTimeout(t);
  }, [location.hash]);

  return (
    <section className="platypus-field min-h-screen bg-[#eef8f5] text-[#123331]">
      {introMounted && (
        <div
          className={`platypus-field fixed inset-0 z-50 grid place-items-center bg-[#eef8f5] transition-opacity duration-500 ${
            introVisible ? "opacity-100" : "pointer-events-none opacity-0"
          }`}
          aria-hidden="true"
        >
          <PerryLogoMark className="h-auto w-[70vmin] max-w-[560px]" />
        </div>
      )}

      <MarketingHeader />
      <div className="h-16 sm:h-[4.25rem]" aria-hidden="true" />

      <div className="mx-auto max-w-7xl px-6 pb-12 sm:px-8 lg:px-12">
        <div className="flex min-h-[calc(100vh-4.5rem)] flex-col justify-center">
        <div className="grid items-center gap-10 lg:grid-cols-[minmax(0,1.1fr)_minmax(20rem,0.7fr)]">
          <div>
            <p className="text-xs font-bold uppercase tracking-[0.2em] text-[#08756f]">
              Security scanning for teams without a security team
            </p>

            <h1 className="mt-4 max-w-4xl break-words text-4xl font-black uppercase leading-[1.03] tracking-normal text-[#4b2104] sm:text-5xl lg:text-6xl xl:text-7xl">
              <TypewriterHeadline lines={HEADLINE_LINES} start={!introVisible} />
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
        </div>

        <div
          id="about"
          className="mt-10 scroll-mt-24 rounded-xl border border-[#b9d6cf] bg-[#fbf7ef] p-5 sm:p-6"
        >
          <Reveal>
            <p className="text-xs font-bold uppercase tracking-[0.2em] text-[#08756f]">
              About Perry
            </p>
            <p className="mt-2 max-w-2xl text-sm leading-relaxed text-[#4f716c]">
              Perry discovers, tests, and validates vulnerabilities across a
              deployed site or codebase, then reports findings developers can
              act on immediately — as a hosted app or as the perry-spies CLI.
            </p>
          </Reveal>

          <Reveal delay={200}>
            <div className="mt-6 grid gap-3 sm:grid-cols-3">
              {PRINCIPLES.map((principle) => (
                <div
                  key={principle.title}
                  className="rounded-lg border border-[#d5e7e2] bg-white/70 p-4"
                >
                  <p className="text-sm font-bold uppercase tracking-wide text-[#123331]">
                    {principle.title}
                  </p>
                  <p className="mt-2 text-xs leading-relaxed text-[#4f716c]">
                    {principle.body}
                  </p>
                </div>
              ))}
            </div>

            <p className="mt-8 text-xs font-bold uppercase tracking-[0.2em] text-[#08756f]">
              The team
            </p>
            <div className="mt-4 grid gap-4 sm:grid-cols-3">
              {TEAM.map((name) => (
                <div
                  key={name}
                  className="rounded-lg border border-[#d5e7e2] bg-white/70 p-4 text-center"
                >
                  <div className="mx-auto grid h-16 w-16 place-items-center rounded-full border border-dashed border-[#8fbab1] bg-[#dff0ec] text-[9px] font-bold uppercase tracking-wide text-[#08756f]">
                    Photo
                  </div>
                  <p className="mt-3 text-sm font-bold text-[#123331]">
                    {name}
                  </p>
                </div>
              ))}
            </div>
          </Reveal>
        </div>

        <Reveal className="mt-10 rounded-xl border border-[#b9d6cf] bg-[#fbf7ef] p-5 sm:p-6">
          <p className="text-xs font-bold uppercase tracking-[0.2em] text-[#08756f]">
            Two ways to run Perry
          </p>
          <div className="mt-4 grid gap-4 sm:grid-cols-2">
            <div className="flex flex-col justify-between gap-4 rounded-lg border border-[#d5e7e2] bg-white/70 p-4">
              <div>
                <p className="text-sm font-bold uppercase tracking-wide text-[#123331]">
                  CLI package
                </p>
                <p className="mt-1 text-sm leading-relaxed text-[#4f716c]">
                  Install perry-spies from PyPI and run scans locally or in
                  CI.
                </p>
              </div>
              <Link
                to="/install"
                className="inline-flex h-11 items-center justify-center rounded-lg bg-[#8d5428] px-5 text-sm font-bold uppercase tracking-wide text-white shadow-sm transition-colors hover:bg-[#6f3f1f]"
              >
                How to install the package
              </Link>
            </div>

            <div className="flex flex-col justify-between gap-4 rounded-lg border border-[#d5e7e2] bg-white/70 p-4">
              <div>
                <p className="text-sm font-bold uppercase tracking-wide text-[#123331]">
                  Hosted app
                </p>
                <p className="mt-1 text-sm leading-relaxed text-[#4f716c]">
                  Sign in and scan a deployed target from the browser — no
                  install required.
                </p>
              </div>
              <Link
                to="/login?next=%2Fscans%2Fnew"
                className="inline-flex h-11 items-center justify-center rounded-lg border border-[#8fbab1] bg-[#fbf7ef] px-5 text-sm font-bold uppercase tracking-wide text-[#123331] transition-colors hover:border-[#08756f]"
              >
                Checkout the website version
              </Link>
            </div>
          </div>
        </Reveal>

        <Reveal className="mt-10 grid gap-3 sm:grid-cols-2 lg:grid-cols-5" delay={80}>
          {FEATURES.map((feature) => (
            <div
              key={feature}
              className="rounded-lg border border-[#b9d6cf] bg-[#fbf7ef] px-4 py-3 text-center text-xs font-bold uppercase tracking-wide text-[#254c48]"
            >
              {feature}
            </div>
          ))}
        </Reveal>

        <Reveal
          id="how-it-works"
          className="mt-10 scroll-mt-24 rounded-xl border border-[#b9d6cf] bg-[#fbf7ef] p-5"
        >
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
        </Reveal>
      </div>

      <Footer />
    </section>
  );
}
