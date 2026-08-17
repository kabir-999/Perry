import { useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import MascotLogo from "./MascotLogo";

const PRODUCT_ITEMS = [
  {
    key: "cli",
    title: "CLI",
    description:
      "Install perry-spies from PyPI and run security scans from your terminal or CI pipeline.",
    to: "/install",
  },
  {
    key: "web",
    title: "Website version",
    description:
      "Sign in and scan a deployed target straight from the browser — no install required.",
    to: "/login?next=%2Fscans%2Fnew",
  },
];

/** Smooth-scrolls to an in-page anchor on the homepage, or navigates there first. */
function AnchorLink({
  id,
  className,
  children,
}: {
  id: string;
  className?: string;
  children: React.ReactNode;
}) {
  const location = useLocation();
  const navigate = useNavigate();

  function handleClick(e: React.MouseEvent) {
    if (location.pathname === "/") {
      e.preventDefault();
      document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
    } else {
      e.preventDefault();
      navigate(`/#${id}`);
    }
  }

  return (
    <Link to={`/#${id}`} onClick={handleClick} className={className}>
      {children}
    </Link>
  );
}

/**
 * Header for the public marketing pages (Home, Installation, About). Starts
 * as a full-width bar, then — once the page scrolls past a small threshold —
 * shrinks into a rounded, floating pill docked near the top, matching the
 * "condensed nav" pattern used by most modern marketing sites.
 */
export default function MarketingHeader() {
  const [scrolled, setScrolled] = useState(false);
  const [productOpen, setProductOpen] = useState(false);
  const productRef = useRef<HTMLDivElement>(null);
  const { user, loading, logout } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    function onScroll() {
      setScrolled(window.scrollY > 24);
    }
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => {
    if (!productOpen) return;
    function onClickOutside(e: MouseEvent) {
      if (!productRef.current?.contains(e.target as Node)) {
        setProductOpen(false);
      }
    }
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, [productOpen]);

  function handleLogout() {
    logout();
    navigate("/", { replace: true });
  }

  const navLinkClass = scrolled
    ? "whitespace-nowrap rounded-full px-2.5 py-1.5 text-sm font-medium text-[#123331]/75 transition-colors hover:text-[#123331]"
    : "whitespace-nowrap rounded-full px-3 py-1.5 text-sm font-medium text-white/80 transition-colors hover:text-white";

  return (
    <div
      className={`fixed inset-x-0 top-0 z-50 flex justify-center transition-[padding] duration-500 ${
        scrolled ? "px-4" : "px-0"
      }`}
    >
      <div
        className={`flex w-full items-center justify-between gap-3 transition-all duration-500 ease-[cubic-bezier(0.22,1,0.36,1)] ${
          scrolled
            ? "mt-3 max-w-6xl rounded-full border border-white/40 bg-white/35 px-4 py-2 shadow-lg shadow-black/10 backdrop-blur-xl backdrop-saturate-150"
            : "mt-0 max-w-none rounded-none border-b border-transparent bg-[#12b3ad] px-4 py-2 sm:px-6"
        }`}
      >
        <Link
          to="/"
          aria-label="Go to home"
          className="flex shrink-0 items-center gap-2 rounded-full transition-colors"
        >
          <MascotLogo size="nav" />
        </Link>

        <nav className="hidden items-center gap-0.5 sm:flex">
          <div ref={productRef} className="relative">
            <button
              type="button"
              onClick={() => setProductOpen((v) => !v)}
              className={`${navLinkClass} inline-flex items-center gap-1`}
              aria-expanded={productOpen}
            >
              Product
              <span
                className={`text-[10px] transition-transform ${productOpen ? "rotate-180" : ""}`}
                aria-hidden="true"
              >
                ▾
              </span>
            </button>

            {productOpen && (
              <div className="absolute left-1/2 top-full mt-3 w-[22rem] -translate-x-1/2 rounded-2xl border border-white/10 bg-[#0b2321] p-3 text-left shadow-xl shadow-black/30">
                {PRODUCT_ITEMS.map((item) => (
                  <Link
                    key={item.key}
                    to={item.to}
                    onClick={() => setProductOpen(false)}
                    className="flex gap-3 rounded-xl p-2.5 transition-colors hover:bg-white/5"
                  >
                    <div className="grid h-16 w-24 shrink-0 place-items-center rounded-lg border border-dashed border-white/15 bg-white/5 text-[9px] uppercase tracking-wide text-white/40">
                      Screenshot
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-white">
                        {item.title}
                      </p>
                      <p className="mt-0.5 text-xs leading-relaxed text-white/60">
                        {item.description}
                      </p>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </div>

          <AnchorLink id="about" className={navLinkClass}>
            About Us
          </AnchorLink>

          <AnchorLink id="how-it-works" className={navLinkClass}>
            How it Works
          </AnchorLink>

          <AnchorLink
            id="contact"
            className={`ml-1 whitespace-nowrap rounded-full border px-3.5 py-1.5 text-sm font-medium transition-colors ${
              scrolled
                ? "border-[#123331]/25 text-[#123331] hover:bg-[#123331]/10"
                : "border-white/20 text-white hover:bg-white/10"
            }`}
          >
            Contact Us
          </AnchorLink>
        </nav>

        {!loading && (
          <div className="flex shrink-0 items-center gap-2 sm:gap-3">
            {user ? (
              <>
                <span
                  className={`hidden max-w-[7rem] truncate text-sm font-medium sm:block ${
                    scrolled ? "text-[#123331]" : "text-white"
                  }`}
                  title={user.email}
                >
                  {user.display_name || user.email}
                </span>
                <button
                  onClick={handleLogout}
                  className={`rounded-full px-3 py-1.5 text-sm font-medium transition-colors ${
                    scrolled
                      ? "text-[#123331]/80 hover:text-[#123331]"
                      : "text-white/85 hover:text-white"
                  }`}
                >
                  Sign out
                </button>
              </>
            ) : (
              <>
                <Link
                  to="/login"
                  className={`rounded-full px-3 py-1.5 text-sm font-medium transition-colors ${
                    scrolled
                      ? "text-[#123331]/80 hover:text-[#123331]"
                      : "text-white/85 hover:text-white"
                  }`}
                >
                  Log in
                </Link>
                <Link
                  to="/login?next=%2Fprojects"
                  className="lift rounded-full bg-[#8d5428] px-3.5 py-1.5 text-sm font-medium text-white shadow-sm transition-colors hover:bg-[#6f3f1f]"
                >
                  Sign up
                </Link>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
