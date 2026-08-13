import { Link } from "react-router-dom";
import { useProjects } from "../hooks/useProjects";
import { SEVERITY_COLOR } from "../theme";

const RISK_HEX: Record<string, string> = SEVERITY_COLOR;

export default function Projects() {
  const { projects, loading, error } = useProjects();

  if (loading) {
    return <p className="text-[#6f6552]">Loading projects…</p>;
  }

  if (error) {
    return (
      <div className="rounded-lg border border-[#e7b7ad] bg-[#fbeae6] p-4 text-[#9f1239]">
        {error}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold">Projects</h2>
          <p className="mt-1 text-sm text-[#6f6552]">
            Every website you've scanned. Scanning the same URL again adds to
            its history here instead of creating a new project.
          </p>
        </div>
        <Link
          to="/scans/new"
          className="lift rounded-xl bg-[#c2410c] px-4 py-2 text-sm font-medium text-white shadow-md hover:bg-[#9a3412]"
        >
          Scan a Website
        </Link>
      </div>

      {!projects || projects.length === 0 ? (
        <div className="rounded-lg border border-[#e3d8c4] bg-[#fbf7ef] p-6 text-center text-sm text-[#948972]">
          No projects yet.{" "}
          <Link to="/scans/new" className="text-[#c2410c] hover:underline">
            Scan a website
          </Link>{" "}
          to create your first one.
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {projects.map((project) => {
            const hex = RISK_HEX[project.latest_final_risk] ?? "#8a8173";
            const terminal = ["completed", "failed", "cancelled"].includes(
              project.latest_status,
            );
            return (
              <Link
                key={project.target_id}
                to={`/projects/${project.target_id}`}
                className="lift rounded-xl border border-[#e3d8c4] bg-[#fbf7ef] p-5 hover:shadow-md"
              >
                <div className="flex items-start justify-between gap-2">
                  <h3 className="truncate text-sm font-semibold text-[#2b2318]">
                    {project.label}
                  </h3>
                  {terminal && (
                    <span
                      className="shrink-0 rounded-full border px-2 py-0.5 text-xs capitalize"
                      style={{ color: hex, borderColor: `${hex}55`, background: `${hex}18` }}
                    >
                      {project.latest_final_risk || "minimal"} · {project.latest_risk_score}
                    </span>
                  )}
                </div>
                <p className="mt-2 text-xs text-[#948972]">
                  {project.scan_count} scan{project.scan_count === 1 ? "" : "s"} · last{" "}
                  {new Date(project.latest_scan_at).toLocaleDateString()}
                </p>
                <p className="mt-1 text-xs capitalize text-[#6f6552]">
                  Latest: {project.latest_status}
                </p>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}
