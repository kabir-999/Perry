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
  ai_summary: string;
  ai_recommendation: string;
  risk_factors?: Record<string, unknown>;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

/** Outcome of a single (endpoint, parameter, attack) test, or of an attack
 *  as a whole. */
export type AttackStatus =
  | "VULNERABLE"
  | "HARDENING"
  | "NOT_VULNERABLE"
  | "NOT_TESTED"
  | "INCONCLUSIVE"
  | "NOT_APPLICABLE";

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

/** Discovery + testing crawl-coverage counts — every number here is real,
 *  taken directly off the scan's own discovery/test-execution results. */
export interface CoverageMetrics {
  urls_discovered: number;
  apis_discovered: number;
  forms_discovered: number;
  parameters_discovered: number;
  js_bundles_discovered: number;
  network_requests_captured: number;
  upload_endpoints_discovered: number;
  auth_routes_discovered: number;
  subdomains_discovered: number;
  vhosts_discovered: number;
  urls_tested: number;
  apis_tested: number;
  parameters_tested: number;
  forms_tested: number;
  security_tests_executed: number;
  security_tests_not_executed: number;
  inconclusive_tests: number;
  coverage_ratio: number;
}

export type AssessmentConfidence = "HIGH" | "MEDIUM" | "LOW" | "INSUFFICIENT" | "";

/** One (endpoint, parameter, attack) cell of the honest test matrix. */
export interface AttackMatrixRow {
  test_id: string;
  attack: string;
  attack_display: string;
  endpoint: string;
  normalized_route: string;
  method: string;
  parameter: string;
  location: string;
  status: AttackStatus;
  confidence: string;
  evidence: string;
}

/** Severity level of a structured attack log record. */
export type AttackLogLevel =
  | "DEBUG"
  | "INFO"
  | "SUCCESS"
  | "WARNING"
  | "ERROR"
  | "ALERT";

/** One production-grade structured JSON log record for a single attack event
 *  — emitted for every attack attempt regardless of outcome. */
export interface AttackLogRecord {
  seq: number;
  timestamp: string;
  level: AttackLogLevel;
  attack: string;
  attack_display: string;
  event: string;
  message: string;
  status: string;
  confidence: string;
  endpoint: string;
  method: string;
  parameter: string;
  location: string;
  payload: string;
  evidence: string;
  test_id: string;
  request_summary: string;
  response_summary: string;
  meta: Record<string, unknown>;
}

/** Baseline-vs-fuzz anomaly score for a single attack domain. */
export interface DomainAnomaly {
  attack: string;
  display: string;
  /** 0–100, or null when the domain was never tested (no comparison ran). */
  score: number | null;
  level: "minimal" | "low" | "medium" | "high" | "critical" | "not_tested";
  max: number;
  mean: number;
  tested: number;
  anomalous: number;
  measured: number;
  vulnerable: number;
}

/** Overall scan anomaly, aggregated across tested domains. */
export interface OverallAnomaly {
  score: number;
  level: "minimal" | "low" | "medium" | "high" | "critical" | "not_tested";
  domains_tested: number;
  domains_total: number;
  domains_anomalous: number;
  top_domain: string;
  top_domain_display: string;
  top_domain_score: number;
}

export interface ScanAnomaly {
  overall: OverallAnomaly;
  domains: Record<string, DomainAnomaly>;
}

/** One node in the attack-surface graph (a de-duplicated endpoint). */
export interface AttackGraphNode {
  id: string;
  url: string;
  path: string;
  label: string;
  depth: number;
  discovery: string;
  methods: string[];
  params: string[];
  param_count: number;
  is_api: boolean;
  is_form: boolean;
  score: number;
  synthetic?: boolean;
}

export interface AttackGraphEdge {
  parent: string;
  child: string;
  via: string;
}

export interface AttackGraph {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  roots: string[];
  node_count: number;
  edge_count: number;
}

export interface CrawlStats {
  endpoints: number;
  apis: number;
  forms: number;
  params: number;
  max_depth: number;
  avg_score: number;
  high_value: number;
  edges: number;
  pages_rendered: number;
  interactions: number;
  network_requests: number;
  max_depth_reached: number;
  errors: number;
}

export interface CrawlLogRecord {
  seq: number;
  timestamp: string;
  event: string;
  url?: string;
  depth?: number;
  via?: string;
  score?: number;
  status?: number | null;
  detail?: string;
}

/** One crawl strategy's discovery layer (BFS or DFS). */
export interface CrawlStrategy {
  strategy: string;
  graph: AttackGraph;
  stats: CrawlStats;
  score: number;
  log: CrawlLogRecord[];
}

export interface CrawlStrategies {
  bfs: CrawlStrategy;
  dfs: CrawlStrategy;
}

/** Per-attack coverage rollup, keyed by attack id. */
export interface AttackCoverageEntry {
  attack: string;
  display: string;
  status: AttackStatus;
  eligible: number;
  tested: number;
  skipped: number;
  inconclusive: number;
  vulnerable: number;
  not_vulnerable: number;
  hardening: number;
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
  ai_analyzed?: boolean;
  ai_error?: string;
  ai_summary?: string;
  ai_recommendation?: string;
  risk_factors?: Record<string, unknown>;
  risk_score: number;
  requests_made: number;
  error_message: string;
  checks_done: string[];
  fast_result: FastResult | null;
  /** Read-only scan: active injection tests were not run. */
  passive_only?: boolean;
  /** Deterministic overall risk = highest confirmed finding's score, 0-100. */
  overall_risk?: number;
  assessment_confidence?: AssessmentConfidence;
  /** 0-100%: how much of the discovered attack surface was actually tested. */
  assessment_coverage?: number;
  /** Non-empty when confidence is below HIGH — shown alongside the risk score. */
  assessment_warning?: string;
  /** Every (endpoint, parameter, attack) cell tested and its outcome. */
  attack_matrix?: AttackMatrixRow[];
  /** Per-attack coverage rollup for the 12 attack modules, keyed by attack id. */
  attack_coverage?: Record<string, AttackCoverageEntry>;
  /** Discovery + testing coverage — always present, real counts. */
  coverage?: CoverageMetrics;
  /** Production-grade structured JSON logs for every attack attempt, in
   *  emission order. Grouped by `attack` for display under each attack box. */
  attack_logs?: AttackLogRecord[];
  /** Per-domain + overall baseline-vs-fuzz anomaly scores. */
  anomaly?: ScanAnomaly;
  /** Full attack-surface graph (normalized, de-duplicated, parent/child). */
  attack_graph?: AttackGraph;
  /** Per-strategy crawl layer: BFS vs DFS graphs, scores, stats, logs. */
  crawl_strategies?: CrawlStrategies;
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

export interface ProjectSeriesPoint {
  scan_id: string;
  created_at: string;
  risk_score: number;
  findings_count: number;
}

/** One project's (Target's) risk-score history — a portfolio site's scans
 *  and this fuzzer project's own scans render as two separate series. */
export interface ProjectSeries {
  target_id: string;
  label: string;
  points: ProjectSeriesPoint[];
}

/** One row per distinct website ever scanned (a Target) — the Projects
 *  list page. The same URL scanned twice is one project with scan_count 2,
 *  not two projects. */
export interface ProjectSummary {
  target_id: string;
  label: string;
  base_url: string;
  scan_count: number;
  latest_scan_id: string;
  latest_scan_at: string;
  latest_status: string;
  latest_risk_score: number;
  latest_final_risk: string;
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
  max_requests?: number;
  concurrency?: number;
  rate_limit_per_second?: number;
  request_timeout_seconds?: number;
  scan_timeout_seconds?: number;
  max_response_bytes?: number;
}
