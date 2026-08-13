import { useEffect, useState } from "react";
import { scansApi } from "../services/api";
import type { Scan } from "../types";

/** Pass `targetId` to scope this to one project's scan history. */
export function useScans(targetId?: string) {
  const [scans, setScans] = useState<Scan[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);

    scansApi
      .list(targetId)
      .then((data) => {
        if (!cancelled) setScans(data);
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err?.response?.data?.detail ?? "Failed to load scans.");
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [targetId]);

  return { scans, loading, error };
}
