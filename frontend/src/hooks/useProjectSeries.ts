import { useEffect, useState } from "react";
import { dashboardApi } from "../services/api";
import type { ProjectSeries } from "../types";

/** Pass `targetId` to fetch just one project's risk-score history (the
 *  project detail page's personalized chart); omit it for every project's
 *  history at once. */
export function useProjectSeries(targetId?: string) {
  const [series, setSeries] = useState<ProjectSeries[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);

    dashboardApi
      .projectSeries(targetId)
      .then((data) => {
        if (!cancelled) setSeries(data);
      })
      .catch((err) => {
        if (!cancelled) {
          setError(
            err?.response?.data?.detail ?? "Failed to load project history.",
          );
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [targetId]);

  return { series, loading, error };
}
