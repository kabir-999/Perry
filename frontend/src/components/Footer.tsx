import PerryLogoMark from "./PerryLogoMark";

const SOCIALS = ["X", "GitHub", "LinkedIn", "YouTube", "Discord", "Email"];

/**
 * Closing section for every marketing page — socials, contact, and the
 * Perry mark. Icons are placeholders until real handles/links are supplied.
 */
export default function Footer() {
  return (
    <footer
      id="contact"
      className="mt-16 border-t border-white/10 bg-[#0b2321] text-white"
    >
      <div className="mx-auto max-w-6xl px-6 py-14 sm:px-8 lg:px-12">
        <div className="flex flex-col gap-10 sm:flex-row sm:items-start sm:justify-between">
          <div className="max-w-sm">
            <PerryLogoMark className="h-14 w-36" />
            <p className="mt-4 text-sm leading-relaxed text-white/60">
              Security scanning for teams without a security team — as a
              hosted app or as the perry-spies CLI.
            </p>
          </div>

          <div>
            <p className="text-xs font-bold uppercase tracking-[0.2em] text-[#5fd6cd]">
              Contact &amp; socials
            </p>
            <div className="mt-4 flex flex-wrap gap-2">
              {SOCIALS.map((label) => (
                <span
                  key={label}
                  className="grid h-10 w-10 place-items-center rounded-full border border-white/15 bg-white/5 text-[11px] font-semibold uppercase text-white/70"
                  title={`${label} (coming soon)`}
                >
                  {label.slice(0, 2)}
                </span>
              ))}
            </div>
          </div>
        </div>

        <div className="mt-10 border-t border-white/10 pt-6 text-xs text-white/40">
          © {new Date().getFullYear()} Perry. Built for teams shipping
          without a dedicated security team.
        </div>
      </div>
    </footer>
  );
}
