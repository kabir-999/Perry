import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import { AuthProvider, useAuth } from "./contexts/AuthContext";
import Dashboard from "./pages/Dashboard";
import Login from "./pages/Login";
import NewScan from "./pages/NewScan";
import ScanDetail from "./pages/ScanDetail";
import type { UserRole } from "./types";

function Splash() {
  return (
    <div className="grid min-h-screen place-items-center bg-[#f4efe6]">
      <p className="text-sm text-[#6f6552]">Loading…</p>
    </div>
  );
}

/** Blocks a route until signed in, and optionally until the role matches. */
function Guard({
  role,
  children,
}: {
  role?: UserRole;
  children: React.ReactNode;
}) {
  const { user, loading } = useAuth();
  if (loading) return <Splash />;
  if (!user) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

function LoginRoute() {
  const { user, loading } = useAuth();
  if (loading) return <Splash />;
  if (user) return <Navigate to="/" replace />;
  return <Login />;
}

function Routing() {
  return (
    <Routes>
      <Route path="/login" element={<LoginRoute />} />

      <Route
        element={
          <Guard>
            <Layout />
          </Guard>
        }
      >
        <Route index element={<Dashboard />} />
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
