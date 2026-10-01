/**
 * AI Cyber Security War Room - Centralized API Client
 * Connects Next.js Frontend to FastAPI Backend
 */

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export interface HealthStatus {
  status: string;
  database: string;
  models: {
    xgboost_detector: string;
    isolation_forest: string;
  };
  services: Record<string, string>;
}

export interface DashboardStats {
  total_security_events: number;
  threats_today: number;
  critical_incidents: number;
  high_severity_incidents: number;
  active_incidents: number;
  anomalies_detected: number;
  assets_monitored: number;
  threat_activity: Array<{
    time: string;
    threats: number;
    anomalies: number;
  }>;
  recent_incidents: Array<{
    id: string;
    db_id: number;
    attack: string;
    severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
    risk_score: number;
    confidence: number;
    sourceIp: string;
    target: string;
    technique: string;
    timestamp: string;
    status: string;
  }>;
}

export interface IncidentSummary {
  id: number;
  incident_id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  risk_score: number;
  status: string;
  source_ip?: string;
  user?: string;
  hostname?: string;
  summary?: string;
  created_at: string;
  updated_at: string;
  event_count: number;
  mitre_techniques: string[];
}

export interface TimelineItem {
  timestamp: string;
  event_id: number;
  event_type: string;
  severity: string;
  source_ip: string;
  destination_ip: string;
  user?: string;
  hostname?: string;
  prediction?: string;
  anomaly_score?: number;
  is_anomalous: boolean;
  description: string;
}

export interface SecurityEventDetail {
  id: number;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  source_port?: number;
  destination_port?: number;
  protocol: string;
  user?: string;
  hostname?: string;
  event_type: string;
  severity: string;
  raw_data: Record<string, any>;
  created_at: string;
  detections: Array<{
    id: number;
    model_name: string;
    predicted_class: string;
    confidence: number;
  }>;
  anomalies: Array<{
    id: number;
    anomaly_score: number;
    is_anomalous: boolean;
    model_name: string;
  }>;
}

export interface MitreTechnique {
  id: number;
  technique_id: string;
  name: string;
  description: string;
  tactic: string;
  external_id?: string;
  incident_count?: number;
}

export interface IncidentDetail extends IncidentSummary {
  events: SecurityEventDetail[];
  timeline: TimelineItem[];
  mitre_details: MitreTechnique[];
  evidence: Record<string, any>;
  audit_logs: Array<{
    id: number;
    action: string;
    actor: string;
    details: any;
    created_at: string;
  }>;
  verification_requests?: VerificationRequestItem[];
  response_actions?: ResponseActionItem[];
}

export interface InvestigationResult {
  incident_id: string;
  status: string;
  analysis_mode: "LLM_RAG" | "LLM" | "RULE_BASED" | string;
  llm_status?: "LLM" | "LLM_RAG" | "LLM_UNAVAILABLE" | string;
  llm_model?: string;
  confidence: number;
  incident_summary: string;
  observed_evidence: string[];
  likely_attack_pattern?: string;
  mitre_techniques?: Array<{ technique_id: string; name: string }>;
  root_cause_hypothesis?: string;
  investigation_steps: string[];
  prioritized_recommendations: string[];
  evidence_references: Array<{ document_id: string; title: string; technique_id?: string; relevance?: string }>;
  analyst_warning?: string;
  // Backward compatibility
  investigation_summary?: string;
  recommended_steps?: string[];
  recommended_actions?: string[];
  evidence_gathered?: Record<string, any>;
}

export interface VerificationRequestItem {
  id: number;
  challenge_id: string;
  user_id: string;
  status: "PENDING" | "CONFIRMED" | "DENIED" | "EXPIRED" | string;
  activity_summary: string;
  delivery_method: string;
  verification_url: string;
  created_at: string;
  expires_at: string;
  responses: Array<{
    id: number;
    response: "CONFIRMED" | "DENIED";
    authenticated: boolean;
    verification_method: string;
    client_ip?: string;
    responded_at: string;
  }>;
}

export interface ResponseActionItem {
  id: number;
  action: "BLOCK_SOURCE_IP" | "ISOLATE_HOST" | "REVOKE_USER_SESSION" | "FORENSIC_SNAPSHOT" | "DISABLE_ACCOUNT" | string;
  reason: string;
  status: "PENDING" | "APPROVED" | "EXECUTED" | "REJECTED" | "FAILED" | string;
  analyst_id: string;
  parameters: Record<string, any>;
  execution_log?: string;
  created_at: string;
  approved_at?: string;
  executed_at?: string;
}

export interface AnalyticsData {
  attacks_by_type: Array<{ name: string; count: number }>;
  severity_distribution: Array<{ severity: string; count: number }>;
  anomalies_timeline: Array<{ time: string; anomalies: number }>;
  confidence_distribution: Array<{ range: string; count: number }>;
  total_incidents: number;
  total_events: number;
}

export interface AttackGraphData {
  nodes: Array<{
    id: string;
    type?: string;
    position: { x: number; y: number };
    data: Record<string, any>;
  }>;
  edges: Array<{
    id: string;
    source: string;
    target: string;
    label?: string;
    animated?: boolean;
  }>;
}

export interface IncidentReport {
  report_id: string;
  incident_id: string;
  title: string;
  severity: string;
  risk_score: number;
  status: string;
  source_ip?: string;
  user?: string;
  hostname?: string;
  summary?: string;
  event_count: number;
  mitre_techniques: string[];
  generated_at: string;
}

async function fetchJson<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;
  try {
    const res = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(options?.headers || {}),
      },
      cache: "no-store",
    });

    if (!res.ok) {
      const errorBody = await res.text().catch(() => "");
      throw new Error(`API error ${res.status}: ${errorBody || res.statusText}`);
    }

    return await res.json();
  } catch (err: any) {
    console.error(`Fetch failed for ${endpoint}:`, err);
    throw err;
  }
}

export const api = {
  getHealth: () => fetchJson<HealthStatus>("/api/health"),

  getDashboardStats: () => fetchJson<DashboardStats>("/api/dashboard/stats"),

  getIncidents: (params?: { status?: string; severity?: string }) => {
    const query = new URLSearchParams();
    if (params?.status) query.append("status", params.status);
    if (params?.severity) query.append("severity", params.severity);
    const qs = query.toString() ? `?${query.toString()}` : "";
    return fetchJson<IncidentSummary[]>(`/api/incidents${qs}`);
  },

  getIncidentDetail: (idOrStr: string | number) =>
    fetchJson<IncidentDetail>(`/api/incidents/${idOrStr}`),

  investigateIncident: (idOrStr: string | number) =>
    fetchJson<InvestigationResult>(`/api/incidents/${idOrStr}/investigate`, {
      method: "POST",
    }),

  makeDecision: (
    idOrStr: string | number,
    payload: { status: string; action_notes?: string; actor?: string }
  ) =>
    fetchJson<IncidentSummary>(`/api/incidents/${idOrStr}/decision`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  getEvents: (params?: { limit?: number; offset?: number; severity?: string }) => {
    const query = new URLSearchParams();
    if (params?.limit) query.append("limit", params.limit.toString());
    if (params?.offset) query.append("offset", params.offset.toString());
    if (params?.severity) query.append("severity", params.severity);
    const qs = query.toString() ? `?${query.toString()}` : "";
    return fetchJson<SecurityEventDetail[]>(`/api/events${qs}`);
  },

  seedSynthetic: () =>
    fetchJson<{ status: string; details: any }>("/api/events/synthetic/seed", {
      method: "POST",
    }),

  simulateDemoAttack: () =>
    fetchJson<{
      status: string;
      scenario: string;
      events_count: number;
      incident_id: string;
      db_id: number;
      risk_score: number;
      severity: string;
    }>("/api/events/simulate-demo-attack", {
      method: "POST",
    }),

  createVerificationRequest: (
    incidentIdOrStr: string | number,
    payload?: {
      user_id?: string;
      activity_summary?: string;
      delivery_method?: string;
      expires_in_minutes?: number;
    }
  ) =>
    fetchJson<VerificationRequestItem>(
      `/api/incidents/${incidentIdOrStr}/verification`,
      {
        method: "POST",
        body: JSON.stringify(payload || {}),
      }
    ),

  getIncidentVerifications: (incidentIdOrStr: string | number) =>
    fetchJson<VerificationRequestItem[]>(
      `/api/incidents/${incidentIdOrStr}/verification`
    ),

  getChallengeDetail: (challengeId: string) =>
    fetchJson<{
      challenge_id: string;
      incident_id: string;
      user_id: string;
      status: string;
      activity_summary: string;
      created_at: string;
      expires_at: string;
      is_expired: boolean;
      question: string;
    }>(`/api/verify/${challengeId}`),

  submitChallengeResponse: (
    challengeId: string,
    response: "CONFIRMED" | "DENIED",
    authPin?: string
  ) =>
    fetchJson<any>(`/api/verify/${challengeId}/respond`, {
      method: "POST",
      body: JSON.stringify({ response, auth_pin: authPin }),
    }),

  getResponseActions: (incidentIdOrStr: string | number) =>
    fetchJson<ResponseActionItem[]>(
      `/api/incidents/${incidentIdOrStr}/responses`
    ),

  proposeResponseAction: (
    incidentIdOrStr: string | number,
    payload: { action: string; reason: string; parameters?: any }
  ) =>
    fetchJson<ResponseActionItem>(
      `/api/incidents/${incidentIdOrStr}/responses`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      }
    ),

  executeResponseAction: (actionId: number, payload?: { notes?: string }) =>
    fetchJson<ResponseActionItem>(`/api/responses/${actionId}/execute`, {
      method: "POST",
      body: JSON.stringify(payload || {}),
    }),

  rejectResponseAction: (actionId: number, payload?: { notes?: string }) =>
    fetchJson<ResponseActionItem>(`/api/responses/${actionId}/reject`, {
      method: "POST",
      body: JSON.stringify(payload || {}),
    }),

  getMitreTechniques: () => fetchJson<MitreTechnique[]>("/api/mitre/techniques"),

  getAnalytics: () => fetchJson<AnalyticsData>("/api/analytics"),

  getAttackGraph: (incidentId?: number) => {
    const qs = incidentId ? `?incident_id=${incidentId}` : "";
    return fetchJson<AttackGraphData>(`/api/attack-graph${qs}`);
  },

  getReports: () => fetchJson<IncidentReport[]>("/api/reports"),
};
