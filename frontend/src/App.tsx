import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import Layout from "./components/Layout";
import { AuthProvider, useAuth } from "./contexts/AuthContext";
import Home from "./pages/Home";
import Install from "./pages/Install";
import Login from "./pages/Login";
import NewScan from "./pages/NewScan";
import ProjectDetail from "./pages/ProjectDetail";
import Projects from "./pages/Projects";
import ScanDetail from "./pages/ScanDetail";
import type { UserRole } from "./types";
import PerryLogoMark from "./components/PerryLogoMark";

function safeNext(raw: string | null) {
  if (!raw || !raw.startsWith("/") || raw.startsWith("//")) return "/projects";
  return raw;
}

function Splash() {
  return (
    <div className="platypus-field grid min-h-screen place-items-center bg-[#eef8f5]">
      <div className="animate-rise flex flex-col items-center gap-3">
        <PerryLogoMark className="h-28 w-72 sm:h-36 sm:w-96" />
        <p className="text-sm font-medium text-[#4f716c]">Loading...</p>
      </div>
    </div>
  );
}

/** Blocks a route until signed in, and optionally until the role matches. */
function Guard({
  children,
}: {
  role?: UserRole;
  children: React.ReactNode;
}) {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) return <Splash />;
  if (!user) {
    const next = `${location.pathname}${location.search}`;
    return <Navigate to={`/login?next=${encodeURIComponent(next)}`} replace />;
  }
  return <>{children}</>;
}

function LoginRoute() {
  const { user, loading } = useAuth();
  const location = useLocation();
  const params = new URLSearchParams(location.search);
  const next = safeNext(params.get("next"));
  if (loading) return <Splash />;
  if (user) return <Navigate to={next} replace />;
  return <Login />;
}

function Routing() {
  return (
    <Routes>
      <Route index element={<Home />} />
      <Route path="/install" element={<Install />} />
      <Route path="/about" element={<Navigate to="/#about" replace />} />
      <Route path="/login" element={<LoginRoute />} />

      <Route
        element={
          <Guard>
            <Layout />
          </Guard>
        }
      >
        <Route path="projects" element={<Projects />} />
        <Route path="projects/:targetId" element={<ProjectDetail />} />
        <Route path="scans/new" element={<NewScan />} />
        <Route path="scans/:scanId" element={<ScanDetail />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <Routing />
    </AuthProvider>
  );
}
