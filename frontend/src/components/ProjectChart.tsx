import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { PALETTE } from "../theme";
import type { ProjectSeries } from "../types";

/** One project's risk-score-over-time chart. A single series names itself
 *  via the card title, so no legend is needed — color here is decorative
 *  brand consistency, not an identity encoding, so it's the same accent
 *  for every project rather than a categorical palette. */
export default function ProjectChart({
  project,
  height = 180,
}: {
  project: ProjectSeries;
  height?: number;
}) {
  const data = project.points.map((p) => ({
    date: new Date(p.created_at).toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
    }),
    risk_score: p.risk_score,
    findings_count: p.findings_count,
  }));

  return (
    <div className="rounded-lg border border-[#e3d8c4] bg-[#fbf7ef] p-5">
      <h4 className="mb-1 text-sm font-medium text-[#4a4032]">{project.label}</h4>
      <p className="mb-3 text-xs text-[#948972]">
        {project.points.length} completed scan{project.points.length === 1 ? "" : "s"}
      </p>
      {data.length === 0 ? (
        <p className="text-sm text-[#948972]">No completed scans yet.</p>
      ) : (
        <ResponsiveContainer width="100%" height={height}>
          <LineChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -16 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e6dcca" />
            <XAxis dataKey="date" stroke="#78716c" tick={{ fontSize: 11 }} />
            <YAxis
              stroke="#78716c"
              tick={{ fontSize: 11 }}
              allowDecimals={false}
              domain={[0, 100]}
            />
            <Tooltip
              contentStyle={{ background: "#fbf7ef", border: "1px solid #e6dcca" }}
              formatter={(value: number, name: string) =>
                name === "risk_score" ? [value, "Risk score"] : [value, "Findings"]
              }
            />
            <Line
              type="monotone"
              dataKey="risk_score"
              stroke={PALETTE.ember}
              strokeWidth={2}
              dot={{ r: 4, fill: PALETTE.ember, strokeWidth: 0 }}
              activeDot={{ r: 5 }}
            />
          </LineChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
