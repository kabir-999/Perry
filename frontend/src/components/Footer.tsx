import { useState } from "react";
import PerryLogoMark from "./PerryLogoMark";

const PHONE = "+91 88304 66403";
const EMAIL = "mathurkabir336@gmail.com";

const INSTAGRAM_ICON = (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className="h-[18px] w-[18px]">
    <rect x="3" y="3" width="18" height="18" rx="5" />
    <circle cx="12" cy="12" r="4" />
    <circle cx="17.5" cy="6.5" r="1" fill="currentColor" stroke="none" />
  </svg>
);

const X_ICON = (
  <svg viewBox="0 0 24 24" fill="currentColor" className="h-[15px] w-[15px]">
    <path d="M18.9 2H22l-7.5 8.6L23.3 22H16.6l-5.2-6.8L5.4 22H2.3l8-9.2L1 2h6.9l4.7 6.2L18.9 2Zm-1.2 18h1.7L7.4 3.9H5.6L17.7 20Z" />
  </svg>
);

const LINKEDIN_ICON = (
  <svg viewBox="0 0 24 24" fill="currentColor" className="h-[17px] w-[17px]">
    <path d="M4.98 3.5a2.5 2.5 0 1 1 0 5 2.5 2.5 0 0 1 0-5ZM3 9h4v12H3V9Zm7 0h3.8v1.64h.05c.53-.98 1.83-2.02 3.77-2.02 4.03 0 4.78 2.5 4.78 5.76V21h-4v-6.02c0-1.44-.03-3.28-2.05-3.28-2.05 0-2.37 1.55-2.37 3.17V21h-4V9Z" />
  </svg>
);

const SOCIALS = [
  { label: "Instagram", icon: INSTAGRAM_ICON },
  { label: "X", icon: X_ICON },
  { label: "LinkedIn", icon: LINKEDIN_ICON },
];

/** A social icon whose real link isn't live yet — hovering (desktop) or
 * tapping (touch, where hover doesn't exist) surfaces an honest status
 * instead of a dead link. */
function SocialBadge({ label, icon }: { label: string; icon: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <span
      className="relative inline-block"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
    >
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-label={`${label} — launching soon`}
        className="grid h-10 w-10 place-items-center rounded-full border border-white/15 bg-white/5 text-white/70 transition hover:border-[#5fd6cd]/60 hover:text-white"
      >
        {icon}
      </button>
      <span
        role="status"
        className={`pointer-events-none absolute bottom-full left-1/2 z-10 mb-2 -translate-x-1/2 whitespace-nowrap rounded-md bg-[#123331] px-3 py-1.5 text-xs font-medium text-white shadow-lg transition ${
          open ? "opacity-100" : "opacity-0"
        }`}
      >
        Launching soon
        <span className="absolute left-1/2 top-full -translate-x-1/2 border-4 border-transparent border-t-[#123331]" />
      </span>
    </span>
  );
}

/**
 * Closing section for every marketing page — contact details, socials, and
 * the Perry mark. Social icons are placeholders until real handles/links
 * are supplied.
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
            <div className="mt-4 flex flex-col gap-1.5 text-sm text-white/70">
              <a href={`tel:${PHONE.replace(/\s+/g, "")}`} className="transition hover:text-white">
                {PHONE}
              </a>
              <a href={`mailto:${EMAIL}`} className="transition hover:text-white">
                {EMAIL}
              </a>
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              {SOCIALS.map((s) => (
                <SocialBadge key={s.label} label={s.label} icon={s.icon} />
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
