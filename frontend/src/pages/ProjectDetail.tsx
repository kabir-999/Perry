import { Link, useParams } from "react-router-dom";
import ProjectChart from "../components/ProjectChart";
import RiskCell from "../components/RiskCell";
import { useProjectSeries } from "../hooks/useProjectSeries";
import { useProjects } from "../hooks/useProjects";
import { useScans } from "../hooks/useScans";

export default function ProjectDetail() {
  const { targetId } = useParams<{ targetId: string }>();
  const { series, loading: seriesLoading } = useProjectSeries(targetId);
  const { scans, loading: scansLoading, error: scansError } = useScans(targetId);
  // The projects list already has this project's label/base_url — reuse it
  // rather than adding a third "get one project" endpoint just for a title.
  const { projects } = useProjects();
  const project = projects?.find((p) => p.target_id === targetId);
  const chart = series?.[0];

  return (
    <div className="space-y-6">
      <div>
        <Link to="/projects" className="text-xs text-[#c2410c] hover:underline">
          ← All projects
        </Link>
        <h2 className="mt-1 text-xl font-semibold text-[#2b2318]">
          {project?.label ?? "Project"}
        </h2>
        {project && (
          <p className="mt-1 text-sm text-[#6f6552]">{project.base_url}</p>
        )}
      </div>

      {seriesLoading ? (
        <p className="text-[#6f6552]">Loading chart…</p>
      ) : chart ? (
        <ProjectChart project={chart} height={260} />
      ) : (
        <div className="rounded-lg border border-[#e3d8c4] bg-[#fbf7ef] p-6 text-sm text-[#948972]">
          No completed scans yet for this project — the chart appears once a
          scan finishes.
        </div>
      )}

      <div className="rounded-lg border border-[#e3d8c4] bg-[#fbf7ef] p-5">
        <h3 className="mb-4 text-sm font-medium text-[#4a4032]">
          Scan History
        </h3>
        {scansError ? (
          <p className="text-sm text-[#9f1239]">{scansError}</p>
        ) : scansLoading ? (
          <p className="text-sm text-[#948972]">Loading…</p>
        ) : !scans || scans.length === 0 ? (
          <p className="text-sm text-[#948972]">No scans yet.</p>
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="text-[#948972]">
              <tr>
                <th className="pb-2 font-normal">Scan ID</th>
                <th className="pb-2 font-normal">Status</th>
                <th className="pb-2 font-normal">Risk</th>
                <th className="pb-2 font-normal">Findings</th>
                <th className="pb-2 font-normal">Timestamp</th>
                <th className="pb-2 font-normal">Report</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#e6dcca]">
              {scans.map((scan) => {
                const terminal = ["completed", "failed", "cancelled"].includes(
                  scan.status,
                );
                return (
                  <tr key={scan.id} className="hover:bg-[#efe6d5]">
                    <td className="py-2 font-mono text-xs text-[#4a4032]">
                      <Link to={`/scans/${scan.id}`} className="hover:underline">
                        {scan.id.slice(0, 8)}
                      </Link>
                    </td>
                    <td className="py-2 capitalize text-[#4a4032]">{scan.status}</td>
                    <td className="py-2">
                      <RiskCell scan={scan} />
                    </td>
                    <td className="py-2 text-[#4a4032]">{scan.findings_count}</td>
                    <td className="py-2 text-[#6f6552]">
                      {new Date(scan.created_at).toLocaleString()}
                    </td>
                    <td className="py-2">
                      {terminal ? (
                        <Link
                          to={`/scans/${scan.id}`}
                          className="text-xs text-[#c2410c] hover:underline"
                        >
                          View / Download PDF
                        </Link>
                      ) : (
                        <span className="text-xs text-[#948972]">—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
