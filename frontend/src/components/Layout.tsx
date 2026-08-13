import { Link, NavLink, Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";

export default function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  function handleLogout() {
    logout();
    navigate("/login", { replace: true });
  }

  return (
    <div className="min-h-screen bg-[#f4efe6] text-[#2b2318]">
      <header className="sticky top-0 z-10 border-b border-[#e3d8c4] bg-[#f4efe6]/90 backdrop-blur">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-3.5">
          <Link to="/" className="flex items-center gap-2.5">
            <span
              className="grid h-8 w-8 place-items-center rounded-lg text-white"
              style={{
                background: "linear-gradient(135deg,#0f766e,#0369a1 55%,#c2410c)",
              }}
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </span>
            <div className="leading-tight">
              <p className="text-sm font-semibold tracking-tight">Sentinel</p>
              <p className="text-[11px] text-[#948972]">Web Security Scanner</p>
            </div>
          </Link>
          <nav className="flex items-center gap-1">
            <NavLink
              to="/"
              end
              className={({ isActive }) =>
                `rounded-lg px-3 py-1.5 text-sm font-medium transition-colors ${
                  isActive
                    ? "text-[#c2410c]"
                    : "text-[#6f6552] hover:text-[#3a3122]"
                }`
              }
            >
              Dashboard
            </NavLink>
            <NavLink
              to="/projects"
              className={({ isActive }) =>
                `rounded-lg px-3 py-1.5 text-sm font-medium transition-colors ${
                  isActive
                    ? "text-[#c2410c]"
                    : "text-[#6f6552] hover:text-[#3a3122]"
                }`
              }
            >
              Projects
            </NavLink>
            <Link
              to="/scans/new"
              className="lift rounded-lg bg-[#c2410c] px-3.5 py-1.5 text-sm font-medium text-white shadow-sm transition-colors hover:bg-[#9a3412]"
            >
              New Scan
            </Link>

            {user && (
              <div className="ml-2 flex items-center gap-2 border-l border-[#e3d8c4] pl-3">
                <span
                  className="hidden text-xs text-[#6f6552] sm:block"
                  title={user.email}
                >
                  {user.display_name || user.email}
                </span>
                <button
                  onClick={handleLogout}
                  className="rounded-lg px-2.5 py-1.5 text-sm font-medium text-[#6f6552] transition-colors hover:text-[#3a3122]"
                >
                  Sign out
                </button>
              </div>
            )}
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-5xl px-6 py-8">
        <Outlet />
      </main>
    </div>
  );
}
