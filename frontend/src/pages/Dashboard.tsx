import { Link } from "react-router-dom";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import RiskCell from "../components/RiskCell";
import StatCard from "../components/StatCard";
import { useDashboardSummary } from "../hooks/useDashboardSummary";
import { SEVERITY_COLOR } from "../theme";

export default function Dashboard() {
  const { summary, loading, error } = useDashboardSummary();

  if (loading) {
    return <p className="text-[#6f6552]">Loading dashboard…</p>;
  }

  if (error || !summary) {
    return (
      <div className="rounded-lg border border-[#e7b7ad] bg-[#fbeae6] p-4 text-[#9f1239]">
        {error ?? "Unable to load dashboard data."}
      </div>
    );
  }

  const chartData = summary.severity_distribution.map((s) => ({
    severity: s.severity,
    count: s.count,
  }));

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold">Dashboard</h2>
        <div className="flex gap-2">
          <Link
            to="/projects"
            className="lift rounded-xl border border-[#e3d8c4] bg-[#fbf7ef] px-4 py-2 text-sm font-medium text-[#4a4032] shadow-sm hover:bg-[#efe6d5]"
          >
            View Projects
          </Link>
          <Link
            to="/scans/new"
            className="lift rounded-xl bg-[#c2410c] px-4 py-2 text-sm font-medium text-white shadow-md hover:bg-[#9a3412]"
          >
            Scan a Website
          </Link>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard label="Total Scans" value={summary.total_scans} />
        <StatCard label="Active Scans" value={summary.active_scans} />
        <StatCard label="Total Findings" value={summary.total_findings} />
      </div>

      <div className="rounded-lg border border-[#e3d8c4] bg-[#fbf7ef] p-5">
        <h3 className="mb-4 text-sm font-medium text-[#4a4032]">
          Severity Distribution
        </h3>
        {chartData.length === 0 ? (
          <p className="text-sm text-[#948972]">
            No findings yet. Run a scan to populate this.
          </p>
        ) : (
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e6dcca" />
              <XAxis dataKey="severity" stroke="#78716c" />
              <YAxis stroke="#78716c" allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: "#fbf7ef", border: "1px solid #e6dcca" }}
              />
              {/* Each bar carries its severity's colour, so the chart reads
                  the same way as the badges elsewhere in the app. */}
              <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                {chartData.map((row) => (
                  <Cell
                    key={row.severity}
                    fill={SEVERITY_COLOR[String(row.severity).toLowerCase()] ?? "#78716c"}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>

      <div className="rounded-lg border border-[#e3d8c4] bg-[#fbf7ef] p-5">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-sm font-medium text-[#4a4032]">Recent Scans</h3>
          <Link to="/projects" className="text-xs text-[#c2410c] hover:underline">
            See per-project history →
          </Link>
        </div>
        {summary.recent_scans.length === 0 ? (
          <p className="text-sm text-[#948972]">No scans yet.</p>
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="text-[#948972]">
              <tr>
                <th className="pb-2 font-normal">Scan ID</th>
                <th className="pb-2 font-normal">Status</th>
                <th className="pb-2 font-normal">Risk</th>
                <th className="pb-2 font-normal">Findings</th>
                <th className="pb-2 font-normal">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#e6dcca]">
              {summary.recent_scans.map((scan) => (
                <tr
                  key={scan.id}
                  className="cursor-pointer hover:bg-[#efe6d5]"
                  onClick={() => {
                    window.location.href = `/scans/${scan.id}`;
                  }}
                >
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
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
