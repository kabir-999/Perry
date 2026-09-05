import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import CardSwap, { Card } from "../components/CardSwap";
import ChromaGrid, { type ChromaItem } from "../components/ChromaGrid";
import FlowingMenu from "../components/FlowingMenu";
import Footer from "../components/Footer";
import MarketingHeader from "../components/MarketingHeader";
import PerryLogoMark from "../components/PerryLogoMark";
import Reveal from "../components/Reveal";
import { Terminal } from "../components/ui/terminal";
import kabirPhoto from "../Team/Kabir.jpeg";
import aayushPhoto from "../Team/aayush.jpeg";
import aagnyaPhoto from "../Team/Aagnya.jpeg";
import chhaviPhoto from "../Team/Chhavi.jpeg";
import chaahatPhoto from "../Team/chaahat.jpeg";
import dakshPhoto from "../Team/Daksh.jpeg";
import dakshAvatar from "../Team/Daksh_avatar.jpeg";
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
  { label: "Enter your target", color: "#08756f" },
  { label: "Perry discovers the attack surface", color: "#8d5428" },
  { label: "Security tests are executed", color: "#12b3ad" },
  { label: "Findings are validated", color: "#4b2104" },
  { label: "Developers receive actionable evidence", color: "#254c48" },
];

const TERMINAL_COMMANDS = [
  "pip install perry-spies",
  "perry scan https://example.com",
  "perry report --format pdf",
];

const TERMINAL_OUTPUTS = {
  0: ["Successfully installed perry-spies-1.0.0"],
  1: ["✔ Discovered 42 endpoints", "✔ Found 3 potential issues"],
  2: ["✔ Report saved to report.pdf"],
};

// `zoom`/`position` crop the full photo into the small circular thumbnail
// via CSS (transform-origin pinned near the face) — approved as-is for
// Kabir/Aayush/Chaahat, left untouched. `avatar` is a pre-cropped square
// file, used only for Daksh (his photo's aspect ratio made the CSS
// approach cut off part of his face). Aagnya and Chhavi use their photo
// directly with no crop at all — plain object-cover already frames them
// well. `photo` (the original, uncropped picture) is what the click
// preview shows full-size.
const TEAM: {
  name: string;
  photo?: string;
  avatar?: string;
  zoom?: number;
  position?: string;
}[] = [
  { name: "Kabir Mathur", photo: kabirPhoto, zoom: 1.35, position: "50% 24%" },
  { name: "Aayush Chaudhari", photo: aayushPhoto, zoom: 1.6, position: "50% 28%" },
  { name: "Aagnya Mistry", photo: aagnyaPhoto },
  { name: "Chhavi Rathod", photo: chhaviPhoto },
  { name: "Chaahat Singh", photo: chaahatPhoto },
  { name: "Daksh Goyal", photo: dakshPhoto, avatar: dakshAvatar },
];

const TEAM_COLORS = ["#08756f", "#8d5428", "#12b3ad", "#4b2104", "#254c48", "#6f3f1f"];

const TEAM_ITEMS: ChromaItem[] = TEAM.map((member, i) => {
  const { name, photo, avatar, zoom, position } = member;
  const borderColor = TEAM_COLORS[i % TEAM_COLORS.length];
  return {
    image: (avatar ?? photo)!,
    title: name,
    borderColor,
    gradient: `linear-gradient(160deg, ${borderColor}, #123331)`,
    imageStyle: avatar
      ? undefined
      : { objectPosition: position ?? "50% 50%", transform: zoom ? `scale(${zoom})` : undefined },
  };
});

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

      <div className="mx-auto max-w-7xl px-6 pb-12 pt-8 sm:px-8 lg:px-12">
        <div className="grid items-start gap-10 lg:grid-cols-[minmax(0,1.1fr)_minmax(20rem,0.7fr)]">
          <div>
            <h1 className="max-w-4xl break-words text-4xl font-black uppercase leading-[1.03] tracking-normal text-[#4b2104] sm:text-5xl lg:text-6xl xl:text-7xl">
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

          <div className="relative h-[440px]">
            <CardSwap width={440} height={320} cardDistance={70} verticalDistance={80} delay={4000}>
              {WORKFLOW.map((item) => (
                <Card key={item.label} className="flex flex-col gap-4 p-7">
                  <span className="grid h-12 w-12 shrink-0 place-items-center rounded-lg bg-[#dff0ec] text-xs font-black text-[#08756f]">
                    {item.icon}
                  </span>
                  <p className="text-lg font-bold uppercase tracking-wide text-[#123331]">
                    {item.label}
                  </p>
                  <p className="text-sm leading-relaxed text-[#4f716c]">
                    {item.body}
                  </p>
                </Card>
              ))}
            </CardSwap>
          </div>
        </div>

        <Reveal id="about" className="mt-24 scroll-mt-24 text-center">
          <h2 className="text-4xl font-black uppercase tracking-tight text-[#08756f] sm:text-5xl">
            About Us
          </h2>

          <p className="mx-auto mt-6 max-w-2xl text-base leading-relaxed text-[#4f716c]">
            Perry discovers, tests, and validates vulnerabilities across a
            deployed site or codebase, then reports findings developers can
            act on immediately — as a hosted app or as the perry-spies CLI.
          </p>

          <div id="how-it-works" className="mt-12 scroll-mt-24 text-left">
            <div className="flex flex-wrap items-center justify-center sm:flex-nowrap">
              {STEPS.map((step, i) => (
                <div key={step.label} className="flex items-center">
                  <span
                    className="grid h-36 w-36 shrink-0 place-items-center rounded-full border-2 bg-white p-4 text-center text-xs font-semibold text-[#254c48]"
                    style={{ borderColor: step.color }}
                  >
                    {step.label}
                  </span>
                  {i < STEPS.length - 1 && (
                    <span
                      className="-mx-2 shrink-0 text-xl"
                      style={{ color: step.color }}
                      aria-hidden="true"
                    >
                      →
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        </Reveal>

        <div className="mt-24">
          <Reveal className="rounded-xl border border-[#b9d6cf] bg-[#fbf7ef] p-5 sm:p-6">
            <p className="text-xs font-bold uppercase tracking-[0.2em] text-[#08756f]">
              Two ways to run Perry
            </p>
            <div className="mt-4 grid gap-6 lg:grid-cols-2 lg:items-center">
              <Terminal
                commands={TERMINAL_COMMANDS}
                outputs={TERMINAL_OUTPUTS}
                typingSpeed={45}
                delayBetweenCommands={1000}
              />

              <div className="text-left">
                <h3 className="text-2xl font-black uppercase tracking-tight text-[#123331]">
                  How to use
                </h3>
                <p className="mt-4 text-sm leading-relaxed text-[#4f716c]">
                  Install perry-spies from PyPI to scan locally or in CI, or
                  sign in and scan a deployed target straight from the
                  browser — no install required.
                </p>
                <div className="mt-6 flex flex-wrap gap-3">
                  <Link
                    to="/install"
                    className="inline-flex h-11 items-center justify-center rounded-lg bg-[#8d5428] px-5 text-sm font-bold uppercase tracking-wide text-white shadow-sm transition-colors hover:bg-[#6f3f1f]"
                  >
                    Install Package
                  </Link>
                  <Link
                    to="/login?next=%2Fscans%2Fnew"
                    className="inline-flex h-11 items-center justify-center rounded-lg border border-[#8fbab1] bg-[#fbf7ef] px-5 text-sm font-bold uppercase tracking-wide text-[#123331] transition-colors hover:border-[#08756f]"
                  >
                    Start a Scan
                  </Link>
                </div>
              </div>
            </div>
          </Reveal>

          <Reveal className="mt-10" delay={80}>
            <div style={{ height: 400, position: "relative" }}>
              <FlowingMenu
                items={FEATURES.map((text) => ({ text }))}
                speed={15}
                textColor="#eef8f5"
                bgColor="#123331"
                marqueeBgColor="#12b3ad"
                marqueeTextColor="#123331"
                borderColor="#2b5450"
              />
            </div>
          </Reveal>
        </div>

        <div className="mt-24">
          <Reveal>
            <p className="text-xs font-bold uppercase tracking-[0.2em] text-[#08756f]">
              The team
            </p>
            <div className="mt-4">
              <ChromaGrid items={TEAM_ITEMS} radius={280} columns={3} rows={2} />
            </div>
          </Reveal>
        </div>
      </div>

      <Footer />
    </section>
  );
}
