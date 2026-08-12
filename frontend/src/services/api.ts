import axios from "axios";
import type {
  CreateScanPayload,
  DashboardSummary,
  DiscoveredEndpoint,
  Finding,
  LoginPayload,
  Scan,
  ScanEvent,
  ScanSnapshot,
  SignupPayload,
  SourceFinding,
  Subdomain,
  TokenResponse,
  User,
} from "../types";

// Requests are proxied to the FastAPI backend by Vite (see vite.config.ts).
// The Groq API key never touches the frontend — all LLM calls happen
// server-side.
const client = axios.create({
  baseURL: "/api",
});

const TOKEN_KEY = "wf.token";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string | null): void {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

client.interceptors.request.use((config) => {
  const token = getToken();
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// A rejected token means the session is over — drop it so the app falls back
// to the login screen instead of retrying with a dead credential.
let onUnauthorized: (() => void) | null = null;
export function setUnauthorizedHandler(fn: (() => void) | null): void {
  onUnauthorized = fn;
}

client.interceptors.response.use(
  (res) => res,
  (error) => {
    if (error?.response?.status === 401) {
      setToken(null);
      onUnauthorized?.();
    }
    return Promise.reject(error);
  },
);

export const authApi = {
  signup: (payload: SignupPayload) =>
    client.post<TokenResponse>("/auth/signup", payload).then((r) => r.data),

  login: (payload: LoginPayload) =>
    client.post<TokenResponse>("/auth/login", payload).then((r) => r.data),

  me: () => client.get<User>("/auth/me").then((r) => r.data),
};

export interface VerificationChallenge {
  method: string;
  record_name?: string;
  record_type?: string;
  record_value?: string;
  url?: string;
  file_path?: string;
  file_content?: string;
  instruction: string;
}

export interface TargetRead {
  id: string;
  hostname: string;
  verification_status: string;
  verification_method: string;
  active_testing_enabled: boolean;
  last_error: string;
}

export const targetsApi = {
  add: (url: string, method: "dns" | "http") =>
    client
      .post<{ target: TargetRead; verification: VerificationChallenge }>(
        "/targets",
        { url, method },
      )
      .then((r) => r.data),

  verify: (targetId: string) =>
    client
      .post<{ verified: boolean; detail: string; target: TargetRead }>(
        `/targets/${targetId}/verify`,
      )
      .then((r) => r.data),

  list: () => client.get<TargetRead[]>("/targets").then((r) => r.data),
};

export const scansApi = {
  create: (payload: CreateScanPayload) =>
    client.post<Scan>("/scans", payload).then((r) => r.data),

  list: () => client.get<Scan[]>("/scans").then((r) => r.data),

  get: (scanId: string) => client.get<Scan>(`/scans/${scanId}`).then((r) => r.data),

  findings: (scanId: string) =>
    client.get<Finding[]>(`/scans/${scanId}/findings`).then((r) => r.data),

  endpoints: (scanId: string) =>
    client
      .get<DiscoveredEndpoint[]>(`/scans/${scanId}/endpoints`)
      .then((r) => r.data),

  sourceFindings: (scanId: string) =>
    client
      .get<SourceFinding[]>(`/scans/${scanId}/source-findings`)
      .then((r) => r.data),

  subdomains: (scanId: string) =>
    client.get<Subdomain[]>(`/scans/${scanId}/subdomains`).then((r) => r.data),

  events: (scanId: string) =>
    client.get<ScanEvent[]>(`/scans/${scanId}/events`).then((r) => r.data),

  live: (scanId: string) =>
    client.get<ScanSnapshot>(`/scans/${scanId}/live`).then((r) => r.data),

  report: (scanId: string) =>
    client.get(`/scans/${scanId}/report`).then((r) => r.data),

  cancel: (scanId: string) =>
    client.post<Scan>(`/scans/${scanId}/cancel`).then((r) => r.data),

  /** Open the live SSE progress stream. Returns the EventSource so the
   *  caller can close it on unmount. */
  openStream: (
    scanId: string,
    onSnapshot: (snap: ScanSnapshot) => void,
    onError?: () => void,
  ): EventSource => {
    // EventSource cannot set headers, so the token travels as a query param.
    const token = getToken();
    const source = new EventSource(
      `/api/scans/${scanId}/stream${token ? `?token=${encodeURIComponent(token)}` : ""}`,
    );
    source.onmessage = (e) => {
      try {
        onSnapshot(JSON.parse(e.data) as ScanSnapshot);
      } catch {
        /* ignore malformed frame */
      }
    };
    source.onerror = () => {
      onError?.();
    };
    return source;
  },
};

export const dashboardApi = {
  summary: () =>
    client.get<DashboardSummary>("/dashboard/summary").then((r) => r.data),
};
