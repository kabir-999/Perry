import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import MascotLogo from "./MascotLogo";
import StaggeredMenu, { type StaggeredMenuItem } from "./StaggeredMenu";

/**
 * Header for the public marketing pages (Home, Installation, About). Starts
 * as a full-width bar, then — once the page scrolls past a small threshold —
 * shrinks into a rounded, floating pill docked near the top, matching the
 * "condensed nav" pattern used by most modern marketing sites.
 *
 * Navigation lives in a closable, staggered panel that slides in from the
 * right so the header itself stays uncluttered.
 */
export default function MarketingHeader() {
  const [scrolled, setScrolled] = useState(false);
  const { user, loading, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    function onScroll() {
      setScrolled(window.scrollY > 24);
    }
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  function handleLogout() {
    logout();
    navigate("/", { replace: true });
  }

  function anchorClick(id: string) {
    return (e: React.MouseEvent<HTMLAnchorElement>) => {
      if (location.pathname === "/") {
        e.preventDefault();
        document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
      } else {
        e.preventDefault();
        navigate(`/#${id}`);
      }
    };
  }

  const menuItems: StaggeredMenuItem[] = [
    {
      label: "CLI",
      ariaLabel: "Install perry-spies from PyPI",
      link: "/install",
    },
    {
      label: "Web App",
      ariaLabel: "Sign in and scan from the browser",
      link: "/login?next=%2Fscans%2Fnew",
    },
    {
      label: "About Us",
      ariaLabel: "Learn about us",
      link: "/#about",
      onClick: anchorClick("about"),
    },
    {
      label: "How it Works",
      ariaLabel: "See how it works",
      link: "/#how-it-works",
      onClick: anchorClick("how-it-works"),
    },
    {
      label: "Contact Us",
      ariaLabel: "Get in touch",
      link: "/#contact",
      onClick: anchorClick("contact"),
    },
  ];

  if (!loading) {
    if (user) {
      menuItems.push({
        label: "Sign out",
        ariaLabel: "Sign out of your account",
        link: "#",
        onClick: (e) => {
          e.preventDefault();
          handleLogout();
        },
      });
    } else {
      menuItems.push(
        { label: "Log in", ariaLabel: "Log in to your account", link: "/login" },
        { label: "Sign up", ariaLabel: "Create an account", link: "/login?next=%2Fprojects" }
      );
    }
  }

  return (
    <div
      className={`fixed inset-x-0 top-0 z-[250] flex justify-center transition-[padding] duration-500 ${
        scrolled ? "px-4" : "px-0"
      }`}
    >
      <div
        className={`flex w-full items-center justify-between gap-3 transition-all duration-500 ease-[cubic-bezier(0.22,1,0.36,1)] ${
          scrolled
            ? "mt-3 max-w-6xl rounded-full border border-white/40 bg-white/35 px-4 py-2 shadow-lg shadow-black/10 backdrop-blur-xl backdrop-saturate-150"
            : "mt-0 max-w-none rounded-none border-b border-transparent bg-transparent px-4 py-2 sm:px-6"
        }`}
      >
        <Link
          to="/"
          aria-label="Go to home"
          className="flex shrink-0 items-center gap-2 rounded-full transition-colors"
        >
          <MascotLogo size="md" />
        </Link>

        {user && (
          <span
            className="hidden max-w-[10rem] truncate text-sm font-medium text-[#123331] sm:block"
            title={user.email}
          >
            {user.display_name || user.email}
          </span>
        )}

        <StaggeredMenu
          position="right"
          items={menuItems}
          displaySocials={false}
          displayItemNumbering
          menuButtonColor="#123331"
          openMenuButtonColor="#123331"
          changeMenuColorOnOpen
          colors={["#8fe0da", "#12b3ad"]}
          accentColor="#8d5428"
          logoSlot={<MascotLogo size="nav" showWordmark />}
        />
      </div>
    </div>
  );
}
