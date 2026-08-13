export type ScanStatus =
  | "queued"
  | "fast_scanning"
  | "initial_result_ready"
  | "deep_scanning"
  | "ai_analysis"
  | "completed"
  | "failed"
  | "cancelled"
  // legacy states (older scans)
  | "pending"
  | "running";

export type RiskLevel = "critical" | "high" | "medium" | "low" | "minimal" | "";

export interface Scan {
  id: string;
  target_id: string;
  status: ScanStatus;
  modules: string;
  max_requests: number;
  concurrency: number;
  rate_limit_per_second: number;
  request_timeout_seconds: number;
  scan_timeout_seconds: number;
  max_response_bytes: number;
  requests_made: number;
  error_message: string;
  initial_risk: RiskLevel;
  final_risk: RiskLevel;
  risk_score: number;
  ai_analyzed: boolean;
  ai_error: string;
  ai_summary: string;
  ai_recommendation: string;
  deep_progress: number;
  urls_discovered: number;
  apis_discovered: number;
  parameters_discovered: number;
  subdomains_discovered: number;
  security_checks_completed: number;
  findings_count: number;
  ai_status: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

/** One row of the full security-test matrix (every test + its outcome). */
export interface TestResult {
  name: string;
  status: "pass" | "finding" | "not_applicable" | "not_authorized";
  severity: string;
  count: number;
  detail: string;
}

/** A Groq-analyzed risk factor (authoritative severity/confidence). */
export interface RiskFactor {
  title: string;
  severity: string;
  confidence: number;
  affected_urls: number;
  evidence: string;
  impact: string;
  explanation: string;
  recommendation: string;
}

export interface FastCheckItem {
  label: string;
  status: "pass" | "warning" | "fail" | "info" | "error";
  detail: string;
}

export interface FastResult {
  reachable: boolean;
  target: string;
  initial_risk: RiskLevel;
  server: string;
  title: string;
  status_code: number | null;
  error_message: string;
  checks: FastCheckItem[];
}

export interface RepoInfo {
  provider: string;
  owner: string;
  name: string;
  url: string;
  confidence: number;
  /** Which signal found the repo, e.g. "git_config", "package_json". */
  discovery_source?: string;
  /** True when the provider API confirmed the repo points back at the site. */
  verified?: boolean;
  status: string;
  error?: string;
  files_analyzed: number;
  source_findings_count: number;
  dependency_findings_count: number;
}

/** One issue found in the repository's source code (GET /scans/:id/source-findings). */
export interface SourceFinding {
  id: string;
  scan_id: string;
  repository_id: string | null;
  finding_type: string;
  file: string;
  line: number;
  severity: string;
  confidence: string;
  evidence: string;
  secret_type: string;
  redacted_value: string;
  /** Redacted source line — rendered as a code block. */
  code_context: string;
  package: string;
  version: string;
  ecosystem: string;
  advisory_id: string;
  fixed_version: string;
  created_at: string;
}

/** Live snapshot streamed over SSE (and returned by GET /scans/:id/live). */
export interface ScanSnapshot {
  id: string;
  status: ScanStatus;
  initial_risk: RiskLevel;
  final_risk: RiskLevel;
  deep_progress: number;
  urls_discovered: number;
  apis_discovered: number;
  parameters_discovered: number;
  subdomains_discovered: number;
  security_checks_completed: number;
  findings_count: number;
  ai_status: string;
  ai_analyzed: boolean;
  ai_error: string;
  risk_score: number;
  ai_summary: string;
  ai_recommendation: string;
  risk_factors: RiskFactor[];
  ai_statistics: Record<string, number>;
  test_results: TestResult[];
  requests_made: number;
  error_message: string;
  checks_done: string[];
  fast_result: FastResult | null;
  repo_info: RepoInfo | null;
  /** Sentinel Risk Model v1 — deterministic, authoritative score. */
  sentinel_risk?: SentinelRisk;
  /** Read-only scan: active injection tests were not run. */
  passive_only?: boolean;
}

export interface RiskContributor {
  finding_id: string;
  title: string;
  type: "VULNERABILITY" | "SECURITY_HARDENING" | "INFORMATIONAL";
  confidence: number;
  affected_urls: number;
  detection_status: string;
  contribution: number;
  contribution_note: string;
  /** This finding's share of the final score; these sum to `score`. */
  applied_points?: number;
  cvss?: {
    version: string;
    vector: string;
    base_score: number;
    severity: string;
    undetermined_metrics: string[];
  };
  hardening?: { model: string; rule: string; base_impact: number; means?: string };
}

export interface SentinelRisk {
  /** Absent on scans that ran before the risk engine existed. */
  score?: number;
  severity?: string;
  methodology?: string;
  findings_considered?: number;
  third_party_excluded?: number;
  contributors?: RiskContributor[];
  aggregation?: {
    base: number;
    base_from: string;
    added_by_others: number;
    other_findings: number;
    formula: string;
    note: string;
  };
  explanation?: string;
}

export interface Subdomain {
  id: string;
  scan_id: string;
  hostname: string;
  resolved_ip: string;
  source: string;
  created_at: string;
}

export interface ScanEvent {
  id: string;
  scan_id: string;
  event_type: string;
  message: string;
  created_at: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  title: string;
  category: string;
  severity: string;
  confidence: string;
  url: string;
  method: string;
  parameter: string;
  evidence: string;
  request_summary: string;
  response_summary: string;
  description: string;
  impact: string;
  remediation: string;
  risk_score: number;
  llm_verdict: string | null;
  llm_confidence: number | null;
  llm_explanation: string | null;
  llm_false_positive_reason: string | null;
  created_at: string;
}

export interface DiscoveredEndpoint {
  id: string;
  scan_id: string;
  url: string;
  method: string;
  source: string;
  discovery_method: string;
  status_code: number | null;
  content_type: string;
  response_size: number | null;
  created_at: string;
}

export interface SeverityCount {
  severity: string;
  count: number;
}

export interface DashboardSummary {
  total_scans: number;
  active_scans: number;
  total_findings: number;
  severity_distribution: SeverityCount[];
  recent_scans: Scan[];
}

/* ---------------------------------- auth --------------------------------- */

export type UserRole = "developer" | "customer";

export interface User {
  id: string;
  email: string;
  display_name: string;
  role: UserRole;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  user: User;
}

export interface SignupPayload {
  email: string;
  password: string;
  display_name?: string;
  role: UserRole;
}

export interface LoginPayload {
  email: string;
  password: string;
}

export const AUTHORIZATION_STATEMENT =
  "I confirm that I have authorization to test this target.";

export interface CreateScanPayload {
  target_url: string;
  allowed_domains: string[];
  modules: string[];
  authorization_statement?: string;
  /** Optional public GitHub/GitLab repo to analyze alongside the site. */
  repo_url?: string;
  max_requests?: number;
  concurrency?: number;
  rate_limit_per_second?: number;
  request_timeout_seconds?: number;
  scan_timeout_seconds?: number;
  max_response_bytes?: number;
}
