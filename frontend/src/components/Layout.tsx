import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import MascotLogo from "./MascotLogo";

export default function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const isHome = location.pathname === "/";

  function handleLogout() {
    logout();
    navigate("/login", { replace: true });
  }

  return (
    <div className="platypus-field min-h-screen bg-[#eef8f5] text-[#123331]">
      {!isHome && (
        <header className="sticky top-0 z-10 border-b border-[#b9d6cf] bg-[#eef8f5]/90 backdrop-blur">
        <div className="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-x-4 gap-y-2 px-4 py-3 sm:px-6 sm:py-3.5">
          <Link to="/" className="flex items-center gap-2.5">
            <MascotLogo size="md" />
          </Link>
          <nav className="flex flex-wrap items-center gap-1">
            <NavLink
              to="/projects"
              className={({ isActive }) =>
                `rounded-lg px-3 py-1.5 text-sm font-medium transition-colors ${
                  isActive
                    ? "text-[#08756f]"
                    : "text-[#4f716c] hover:text-[#123331]"
                }`
              }
            >
              Projects
            </NavLink>
            <Link
              to="/scans/new"
              className="lift rounded-lg bg-[#8d5428] px-3.5 py-1.5 text-sm font-medium text-white shadow-sm transition-colors hover:bg-[#6f3f1f]"
            >
              New Scan
            </Link>

            {user && (
              <div className="ml-2 flex items-center gap-2 border-l border-[#b9d6cf] pl-3">
                <span
                  className="hidden max-w-[10rem] truncate text-xs text-[#4f716c] sm:block"
                  title={user.email}
                >
                  {user.display_name || user.email}
                </span>
                <button
                  onClick={handleLogout}
                  className="rounded-lg px-2.5 py-1.5 text-sm font-medium text-[#4f716c] transition-colors hover:text-[#123331]"
                >
                  Sign out
                </button>
              </div>
            )}
          </nav>
        </div>
        </header>
      )}
      <main className={isHome ? "p-6" : "mx-auto max-w-5xl px-4 py-6 sm:px-6 sm:py-8"}>
        <Outlet />
      </main>
    </div>
  );
}
