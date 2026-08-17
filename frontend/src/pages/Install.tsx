import CodeBlock from "../components/CodeBlock";
import Footer from "../components/Footer";
import MarketingHeader from "../components/MarketingHeader";
import Reveal from "../components/Reveal";

const INSTALL_STEPS = [
  {
    number: "01",
    title: "Install via PyPI",
    body: "Install the package directly from PyPI.",
    code: { label: "Terminal", code: "pip install perry-spies" },
  },
  {
    number: "02",
    title: "Local development installation",
    body: "For developers wishing to extend or test perry-spies locally.",
    code: {
      label: "Terminal",
      code: [
        "git clone https://github.com/aayushhh-operator/perry.git",
        "cd perry/backend",
        "pip install -e .",
      ].join("\n"),
    },
  },
];

const GETTING_STARTED = [
  {
    title: "Scan the current directory",
    code: { label: "Terminal", code: "perry scan" },
  },
  {
    title: "Scan a specific folder and fail if high/critical issues are found",
    code: {
      label: "Terminal",
      code: "perry scan /path/to/project --fail-on high",
    },
  },
  {
    title: "Run the default fuzzing suite against a live site (with authorization)",
    code: {
      label: "Terminal",
      code: "perry custom-test --url https://perryspies.vercel.app/ --authorized",
    },
  },
  {
    title: "Export definitive logs to a JSON file",
    code: { label: "Terminal", code: "perry scan --json report.json" },
  },
];

export default function Install() {
  return (
    <section className="platypus-field min-h-screen bg-[#eef8f5] text-[#123331]">
      <MarketingHeader />
      <div className="h-16 sm:h-[4.25rem]" aria-hidden="true" />

      <div className="mx-auto max-w-5xl px-6 py-12 sm:px-8 lg:px-12">
        <p className="text-xs font-bold uppercase tracking-[0.2em] text-[#08756f]">
          Perry CLI
        </p>
        <h1 className="mt-2 text-3xl font-black uppercase tracking-tight text-[#4b2104] sm:text-4xl">
          Installation
        </h1>
        <p className="mt-4 max-w-2xl text-base leading-relaxed text-[#4f716c]">
          perry-spies is Perry's command-line scanner — install it once and
          run security checks against any local project or live target.
        </p>

        <div className="mt-10 space-y-10">
          {INSTALL_STEPS.map((step, index) => (
            <Reveal
              key={step.number}
              className="grid items-start gap-6 md:grid-cols-2"
              delay={index * 80}
            >
              <div>
                <div className="mb-3 inline-flex items-center gap-2 rounded-lg border border-[#b9d6cf] px-2.5 py-1 text-xs font-bold text-[#08756f]">
                  {step.number}
                </div>
                <h2 className="text-lg font-bold text-[#123331]">
                  {step.title}
                </h2>
                <p className="mt-2 text-sm leading-relaxed text-[#4f716c]">
                  {step.body}
                </p>
              </div>
              <CodeBlock {...step.code} />
            </Reveal>
          ))}
        </div>

        <hr className="my-12 border-[#b9d6cf]" />

        <h2 className="text-2xl font-black uppercase tracking-tight text-[#4b2104]">
          Getting started
        </h2>

        <div className="mt-8 space-y-8">
          {GETTING_STARTED.map((item, index) => (
            <Reveal key={item.title} delay={index * 60}>
              <h3 className="text-base font-bold text-[#123331]">
                {item.title}
              </h3>
              <div className="mt-3 max-w-2xl">
                <CodeBlock {...item.code} />
              </div>
            </Reveal>
          ))}
        </div>

        <hr className="my-12 border-[#b9d6cf]" />

        <h2 className="text-2xl font-black uppercase tracking-tight text-[#4b2104]">
          License
        </h2>
        <p className="mt-4 text-sm leading-relaxed text-[#4f716c]">
          <code className="rounded bg-[#dff0ec] px-1.5 py-0.5 text-[#08756f]">
            perry-spies
          </code>{" "}
          is distributed under the MIT license.
        </p>
      </div>

      <Footer />
    </section>
  );
}
