"use client";

import { use, useEffect, useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  ShieldAlert,
  AlertTriangle,
  Clock,
  Server,
  User,
  Globe,
  Bot,
  CheckCircle2,
  BrainCircuit,
  FileCheck,
  ChevronDown,
  ChevronUp,
  Activity,
  Zap,
  ExternalLink,
  Shield,
  XCircle,
  Copy,
  Lock,
  Flame,
  Radio,
  Send,
  Database,
  Terminal,
} from "lucide-react";

import Sidebar from "@/components/Sidebar";
import Topbar from "@/components/Topbar";
import {
  api,
  IncidentDetail,
  InvestigationResult,
  VerificationRequestItem,
  ResponseActionItem,
} from "@/lib/api";

const severityStyles: Record<string, string> = {
  CRITICAL: "text-red-400 bg-red-500/10 border-red-500/20",
  HIGH: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  MEDIUM: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  LOW: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
};

const statusStyles: Record<string, string> = {
  NEW: "text-blue-400 bg-blue-500/10 border-blue-500/20",
  INVESTIGATING: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  Investigating: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  AWAITING_USER_VERIFICATION: "text-purple-400 bg-purple-500/10 border-purple-500/20 animate-pulse",
  USER_CONFIRMED: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
  USER_DENIED: "text-red-400 bg-red-500/10 border-red-500/20 font-bold",
  VERIFICATION_EXPIRED: "text-amber-400 bg-amber-500/10 border-amber-500/20",
  CONTAINMENT_PENDING: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  CONTAINED: "text-teal-400 bg-teal-500/10 border-teal-500/20",
  Contained: "text-teal-400 bg-teal-500/10 border-teal-500/20",
  FALSE_POSITIVE: "text-zinc-400 bg-zinc-500/10 border-zinc-500/20",
  "False Positive": "text-zinc-400 bg-zinc-500/10 border-zinc-500/20",
  CONFIRMED_INCIDENT: "text-red-400 bg-red-500/20 border-red-500/40 font-bold",
  RESOLVED: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
  Resolved: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
};

export default function IncidentDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const resolvedParams = use(params);
  const incidentId = resolvedParams.id;

  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [investigating, setInvestigating] = useState(false);
  const [investigationResult, setInvestigationResult] = useState<InvestigationResult | null>(null);
  const [selectedStatus, setSelectedStatus] = useState<string>("INVESTIGATING");
  const [analystNotes, setAnalystNotes] = useState<string>("");
  const [decisionSubmitting, setDecisionSubmitting] = useState(false);
  const [expandedEventId, setExpandedEventId] = useState<number | null>(null);

  // User Verification state
  const [verifying, setVerifying] = useState(false);
  const [verificationList, setVerificationList] = useState<VerificationRequestItem[]>([]);
  const [copiedChallengeId, setCopiedChallengeId] = useState<string | null>(null);
  const [showHistory, setShowHistory] = useState(false);

  // Response Engine state
  const [responseActions, setResponseActions] = useState<ResponseActionItem[]>([]);
  const [proposingAction, setProposingAction] = useState(false);
  const [actionConfirmTarget, setActionConfirmTarget] = useState<number | null>(null);
  const [executingActionId, setExecutingActionId] = useState<number | null>(null);

  const loadIncident = async () => {
    try {
      setLoading(true);
      const data = await api.getIncidentDetail(incidentId);
      setIncident(data);
      setSelectedStatus(data.status);
      if (data.verification_requests) {
        setVerificationList(data.verification_requests);
      }
      if (data.response_actions) {
        setResponseActions(data.response_actions);
      }
    } catch (e) {
      console.error("Failed to load incident detail:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIncident();
    const interval = setInterval(loadIncident, 10000);
    return () => clearInterval(interval);
  }, [incidentId]);

  const handleRunInvestigation = async () => {
    try {
      setInvestigating(true);
      const res = await api.investigateIncident(incidentId);
      setInvestigationResult(res);
      await loadIncident();
    } catch (e) {
      console.error("Investigation failed:", e);
      alert("AI Analyst investigation failed. Ensure backend server is running.");
    } finally {
      setInvestigating(false);
    }
  };

  const handleCreateVerification = async () => {
    try {
      setVerifying(true);
      const req = await api.createVerificationRequest(incidentId, {
        user_id: incident?.user || "primary_user",
        delivery_method: "DEMO_PORTAL",
        expires_in_minutes: 15,
      });
      alert(`User verification request dispatched! Challenge ID: ${req.challenge_id}`);
      await loadIncident();
    } catch (e: any) {
      console.error("Failed to create verification challenge:", e);
      alert("Failed to create user verification request.");
    } finally {
      setVerifying(false);
    }
  };

  const handleCopyLink = (challengeId: string) => {
    const url = `${window.location.origin}/verify/${challengeId}`;
    navigator.clipboard.writeText(url);
    setCopiedChallengeId(challengeId);
    setTimeout(() => setCopiedChallengeId(null), 2000);
  };

  const handleProposeResponse = async (actionType: string, defaultReason: string) => {
    try {
      setProposingAction(true);
      const targetParams: Record<string, any> = {};
      if (incident?.source_ip) targetParams["target_ip"] = incident.source_ip;
      if (incident?.hostname) targetParams["target_host"] = incident.hostname;
      if (incident?.user) targetParams["target_user"] = incident.user;

      await api.proposeResponseAction(incidentId, {
        action: actionType,
        reason: defaultReason,
        parameters: targetParams,
      });
      await loadIncident();
    } catch (e: any) {
      console.error("Failed to propose response action:", e);
      alert(e.message || "Failed to propose action.");
    } finally {
      setProposingAction(false);
    }
  };

  const handleExecuteResponse = async (actionId: number) => {
    try {
      setExecutingActionId(actionId);
      await api.executeResponseAction(actionId, {
        notes: "Approved and simulated by Lead SOC Analyst in demonstration console.",
      });
      setActionConfirmTarget(null);
      await loadIncident();
    } catch (e: any) {
      console.error("Execution failed:", e);
      alert(e.message || "Failed to execute response action.");
    } finally {
      setExecutingActionId(null);
    }
  };

  const handleRejectResponse = async (actionId: number) => {
    try {
      await api.rejectResponseAction(actionId, { notes: "Cancelled by analyst." });
      setActionConfirmTarget(null);
      await loadIncident();
    } catch (e: any) {
      console.error("Failed to reject response:", e);
    }
  };

  const handleDecisionSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setDecisionSubmitting(true);
      await api.makeDecision(incidentId, {
        status: selectedStatus,
        action_notes: analystNotes,
        actor: "lead_soc_analyst",
      });
      alert(`Incident status updated to: ${selectedStatus}`);
      setAnalystNotes("");
      await loadIncident();
    } catch (e: any) {
      console.error("Decision submission failed:", e);
      alert(`Failed to submit decision: ${e.message || "Invalid state transition"}`);
    } finally {
      setDecisionSubmitting(false);
    }
  };

  const handleDirectAnalystDecision = async (newStatus: string, reason: string) => {
    try {
      setDecisionSubmitting(true);
      await api.makeDecision(incidentId, {
        status: newStatus,
        action_notes: reason,
        actor: "lead_soc_analyst",
      });
      setSelectedStatus(newStatus);
      await loadIncident();
    } catch (e: any) {
      console.error("Direct decision failed:", e);
      alert(`Failed to update status to ${newStatus}: ${e.message || "Invalid state transition"}`);
    } finally {
      setDecisionSubmitting(false);
    }
  };

  if (loading && !incident) {
    return (
      <div className="min-h-screen bg-black text-white">
        <Sidebar />
        <Topbar />
        <main className="ml-64 min-h-screen pt-20 flex items-center justify-center">
          <div className="text-zinc-500 font-mono text-sm animate-pulse">
            Loading Incident #{incidentId} Telemetry & Context...
          </div>
        </main>
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="min-h-screen bg-black text-white">
        <Sidebar />
        <Topbar />
        <main className="ml-64 min-h-screen pt-20 p-8">
          <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-8 text-center">
            <h2 className="text-xl font-bold text-red-400">Incident Not Found</h2>
            <p className="mt-2 text-sm text-zinc-400">
              The requested incident could not be retrieved from the database.
            </p>
            <Link
              href="/incidents"
              className="mt-4 inline-flex items-center gap-2 rounded-lg bg-zinc-900 border border-zinc-700 px-4 py-2 text-xs font-medium text-white hover:bg-zinc-800"
            >
              <ArrowLeft className="h-4 w-4" />
              <span>Back to Incidents List</span>
            </Link>
          </div>
        </main>
      </div>
    );
  }

  const latestVerification = verificationList.length > 0 ? verificationList[0] : null;

  return (
    <div className="min-h-screen bg-black text-white">
      <Sidebar />
      <Topbar />

      <main className="ml-64 min-h-screen pt-20">
        <div className="p-8">
          {/* Breadcrumb & Navigation */}
          <div className="mb-6 flex items-center justify-between">
            <Link
              href="/incidents"
              className="inline-flex items-center gap-2 text-xs font-mono text-zinc-400 hover:text-white transition"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
              <span>INCIDENTS CONSOLE</span>
              <span className="text-zinc-600">/</span>
              <span className="text-emerald-400 font-semibold">{incident.incident_id}</span>
            </Link>

            <div className="flex items-center gap-3">
              <button
                onClick={loadIncident}
                className="rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800 transition"
              >
                Refresh Data
              </button>
            </div>
          </div>

          {/* ============================================================ */}
          {/* SECTION 1 — INCIDENT HEADER & SUMMARY */}
          {/* ============================================================ */}
          <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-6 shadow-xl">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
              <div>
                <div className="flex items-center gap-3">
                  <span className="font-mono text-xs font-bold text-zinc-400 tracking-wider">
                    {incident.incident_id}
                  </span>
                  <span
                    className={`rounded-md border px-2.5 py-0.5 text-xs font-bold ${
                      severityStyles[incident.severity] || severityStyles.MEDIUM
                    }`}
                  >
                    {incident.severity}
                  </span>
                  <span
                    className={`rounded-md border px-2.5 py-0.5 text-xs font-bold font-mono ${
                      statusStyles[incident.status] || "text-zinc-300 bg-zinc-800 border-zinc-700"
                    }`}
                  >
                    STATUS: {incident.status}
                  </span>
                </div>

                <h1 className="mt-2 text-2xl font-bold tracking-tight text-white">
                  {incident.title}
                </h1>

                <p className="mt-2 text-xs text-zinc-400 max-w-4xl leading-relaxed">
                  {incident.summary || "Automated multi-stage correlation incident."}
                </p>
              </div>

              {/* Action Buttons: Investigate & Verify User */}
              <div className="flex flex-wrap items-center gap-2">
                <button
                  onClick={handleRunInvestigation}
                  disabled={investigating}
                  className="flex items-center gap-2 rounded-xl bg-purple-600 hover:bg-purple-500 text-white px-4 py-2.5 text-xs font-semibold shadow-lg shadow-purple-950/40 transition disabled:opacity-50"
                >
                  <BrainCircuit className={`h-4 w-4 ${investigating ? "animate-spin" : ""}`} />
                  <span>{investigating ? "Running RAG + LLM..." : "AI Investigate"}</span>
                </button>

                <button
                  onClick={handleCreateVerification}
                  disabled={verifying}
                  className="flex items-center gap-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2.5 text-xs font-semibold shadow-lg shadow-emerald-950/40 transition disabled:opacity-50"
                >
                  <Send className="h-4 w-4" />
                  <span>{verifying ? "Dispatching..." : "Verify User"}</span>
                </button>
              </div>
            </div>

            {/* Quick Metadata Ribbons */}
            <div className="mt-6 grid grid-cols-2 sm:grid-cols-4 gap-4 border-t border-zinc-800/80 pt-4 text-xs font-mono">
              <div className="flex items-center gap-2 text-zinc-400">
                <Globe className="h-4 w-4 text-red-400" />
                <span>Source IP: <strong className="text-white">{incident.source_ip || "Unknown"}</strong></span>
              </div>
              <div className="flex items-center gap-2 text-zinc-400">
                <User className="h-4 w-4 text-blue-400" />
                <span>Target User: <strong className="text-white">{incident.user || "N/A"}</strong></span>
              </div>
              <div className="flex items-center gap-2 text-zinc-400">
                <Server className="h-4 w-4 text-emerald-400" />
                <span>Target Host: <strong className="text-white">{incident.hostname || "Internal Asset"}</strong></span>
              </div>
              <div className="flex items-center gap-2 text-zinc-400">
                <Clock className="h-4 w-4 text-yellow-400" />
                <span>Updated: <strong className="text-white">{new Date(incident.updated_at).toLocaleTimeString()}</strong></span>
              </div>
            </div>
          </div>

          {/* ============================================================ */}
          {/* SECTION 2 — COMPOSITE RISK SCORE */}
          {/* ============================================================ */}
          <div className="mt-6 grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-5 flex items-center justify-between">
              <div>
                <p className="text-[11px] font-mono uppercase text-zinc-400">Composite Risk Score</p>
                <p className="text-3xl font-extrabold text-white mt-1">
                  {incident.risk_score} <span className="text-xs font-normal text-zinc-500">/ 100</span>
                </p>
                <p className="text-[10px] text-zinc-500 mt-1">Multi-stage probability weighting</p>
              </div>
              <div
                className={`h-12 w-12 rounded-xl flex items-center justify-center font-bold text-sm ${
                  incident.risk_score >= 80
                    ? "bg-red-500/20 text-red-400 border border-red-500/30"
                    : incident.risk_score >= 50
                    ? "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30"
                    : "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                }`}
              >
                {Math.round(incident.risk_score)}%
              </div>
            </div>

            <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-5">
              <p className="text-[11px] font-mono uppercase text-zinc-400">XGBoost ML Classification</p>
              <p className="text-lg font-bold text-white mt-1">
                {incident.events?.[0]?.detections?.[0]?.predicted_class || "Attack Detected"}
              </p>
              <p className="text-[10px] text-zinc-500 mt-1 font-mono">
                Development Evaluation: 99.89%
              </p>
            </div>

            <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-5">
              <p className="text-[11px] font-mono uppercase text-zinc-400">Isolation Forest Anomalies</p>
              <p className="text-lg font-bold text-yellow-400 mt-1">
                {incident.events?.filter((e) => e.anomalies?.some((a) => a.is_anomalous)).length || 0} Flagged
              </p>
              <p className="text-[10px] text-zinc-500 mt-1">Behavioral outlier detection</p>
            </div>

            <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-5">
              <p className="text-[11px] font-mono uppercase text-zinc-400">MITRE ATT&CK Matrix</p>
              <p className="text-lg font-bold text-purple-400 mt-1">
                {incident.mitre_techniques?.length || 0} Techniques
              </p>
              <p className="text-[10px] text-zinc-500 mt-1 font-mono">
                {incident.mitre_techniques?.join(", ") || "None"}
              </p>
            </div>
          </div>

          {/* ============================================================ */}
          {/* SECTION 8 — USER VERIFICATION (MANDATORY HITL FLOW) */}
          {/* ============================================================ */}
          <div className="mt-6 rounded-2xl border border-zinc-800 bg-zinc-950 p-6">
            <div className="flex items-center justify-between border-b border-zinc-800 pb-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  <User className="h-5 w-5" />
                </div>
                <div>
                  <h2 className="text-base font-bold text-white">USER VERIFICATION (Human-in-the-Loop)</h2>
                  <p className="text-xs text-zinc-400">
                    Verify account authenticity with user before executing disruptive response actions
                  </p>
                </div>
              </div>

              <button
                onClick={handleCreateVerification}
                disabled={verifying}
                className="flex items-center gap-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs font-semibold text-emerald-400 hover:bg-emerald-500/20 transition disabled:opacity-50"
              >
                <Send className="h-3.5 w-3.5" />
                <span>{verifying ? "Creating..." : "Dispatch Challenge"}</span>
              </button>
            </div>

            {/* Verification Outcomes / Active Challenges */}
            <div className="mt-4">
              {verificationList.length === 0 ? (
                <div className="rounded-xl border border-dashed border-zinc-800 p-6 text-center">
                  <p className="text-xs text-zinc-400">No user verification challenge active for this incident.</p>
                  <p className="text-[11px] text-zinc-600 mt-1">
                    Click &apos;Dispatch Challenge&apos; to generate a human-in-the-loop verification challenge for {incident.user || "the account"}.
                  </p>
                </div>
              ) : (
                (() => {
                  const activeVr = verificationList[0];
                  const previousVrs = verificationList.slice(1);
                  const isConfirmed = activeVr.status === "CONFIRMED";
                  const isDenied = activeVr.status === "DENIED";
                  const isPending = activeVr.status === "PENDING";
                  const isExpired = activeVr.status === "EXPIRED";

                  return (
                    <div className="space-y-4">
                      {/* Active Challenge Card */}
                      <div
                        className={`rounded-xl border p-4 transition ${
                          isConfirmed
                            ? "border-emerald-500/30 bg-emerald-950/20"
                            : isDenied
                            ? "border-red-500/30 bg-red-950/20"
                            : isExpired
                            ? "border-zinc-800 bg-zinc-900/40 opacity-80"
                            : "border-purple-500/30 bg-purple-950/20"
                        }`}
                      >
                        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                          <div className="flex items-center gap-3">
                            <span
                              className={`rounded px-2.5 py-0.5 text-xs font-bold font-mono ${
                                isConfirmed
                                  ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                                  : isDenied
                                  ? "bg-red-500/20 text-red-400 border border-red-500/30"
                                  : isExpired
                                  ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                                  : "bg-purple-500/20 text-purple-400 border border-purple-500/30 animate-pulse"
                              }`}
                            >
                              CHALLENGE: {activeVr.status}
                            </span>
                            <span className="text-xs text-zinc-300 font-mono">
                              Target User: <strong>{activeVr.user_id}</strong> • Token: {activeVr.challenge_id}
                            </span>
                          </div>

                          {/* Quick Link & Verification Portal Actions */}
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => handleCopyLink(activeVr.challenge_id)}
                              className="flex items-center gap-1 rounded bg-zinc-900 border border-zinc-700 px-2 py-1 text-[11px] text-zinc-300 hover:text-white"
                            >
                              <Copy className="h-3 w-3" />
                              <span>{copiedChallengeId === activeVr.challenge_id ? "Copied!" : "Copy Link"}</span>
                            </button>

                            <Link
                              href={`/verify/${activeVr.challenge_id}`}
                              target="_blank"
                              className="flex items-center gap-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white px-2.5 py-1 text-[11px] font-semibold transition"
                            >
                              <ExternalLink className="h-3 w-3" />
                              <span>Open Verification Portal</span>
                            </Link>
                          </div>
                        </div>

                        <p className="mt-2 text-xs text-zinc-300 bg-zinc-950/60 p-2.5 rounded-lg border border-zinc-800/80">
                          <strong>Activity Presented:</strong> {activeVr.activity_summary}
                        </p>

                        {/* Outcomes & Decision Pathway for Analyst */}
                        {isConfirmed && (
                          <div className="mt-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 p-3.5 rounded-lg bg-emerald-950/40 border border-emerald-500/30">
                            <div>
                              <p className="text-xs font-bold text-emerald-400 flex items-center gap-1.5">
                                <CheckCircle2 className="h-4 w-4" />
                                <span>USER CONFIRMED ACTIVITY</span>
                              </p>
                              <p className="text-[11px] text-zinc-300 mt-0.5">
                                User verified activity was legitimate. Incident status: <span className="font-mono text-emerald-400 font-semibold">USER_CONFIRMED</span> (remains open for analyst review).
                              </p>
                            </div>
                            <div className="flex items-center gap-2">
                              <button
                                onClick={() => handleDirectAnalystDecision("FALSE_POSITIVE", "User attested activity was legitimate business operation.")}
                                disabled={decisionSubmitting}
                                className="rounded bg-emerald-600 hover:bg-emerald-500 px-3 py-1.5 text-xs font-bold text-white transition shadow disabled:opacity-50"
                              >
                                {decisionSubmitting ? "Updating..." : "MARK AS LEGITIMATE"}
                              </button>
                              <button
                                onClick={() => handleDirectAnalystDecision("INVESTIGATING", "User confirmed activity; analyst continuing in-depth investigation.")}
                                disabled={decisionSubmitting}
                                className="rounded bg-zinc-800 hover:bg-zinc-700 px-3 py-1.5 text-xs font-medium text-white transition border border-zinc-700 disabled:opacity-50"
                              >
                                {decisionSubmitting ? "Updating..." : "CONTINUE INVESTIGATION"}
                              </button>
                            </div>
                          </div>
                        )}

                        {isDenied && (
                          <div className="mt-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 p-3.5 rounded-lg bg-red-950/40 border border-red-500/30">
                            <div>
                              <p className="text-xs font-bold text-red-400 flex items-center gap-1.5">
                                <XCircle className="h-4 w-4" />
                                <span>USER DENIED ACTIVITY — COMPROMISE CONFIRMED</span>
                              </p>
                              <p className="text-[11px] text-red-200 mt-0.5">
                                User indicated account was compromised. Incident status: <span className="font-mono text-red-400 font-semibold">USER_DENIED</span>. Severity elevated to CRITICAL.
                              </p>
                            </div>
                            <div className="flex items-center gap-2">
                              <button
                                onClick={() => handleProposeResponse("ISOLATE_HOST", "User confirmed compromise via verification denial.")}
                                disabled={proposingAction}
                                className="rounded bg-red-600 hover:bg-red-500 px-3 py-1.5 text-xs font-bold text-white transition shadow disabled:opacity-50"
                              >
                                Propose Host Isolation
                              </button>
                              <button
                                onClick={() => handleProposeResponse("REVOKE_USER_SESSION", "Compromised credentials reported by user.")}
                                disabled={proposingAction}
                                className="rounded bg-orange-600 hover:bg-orange-500 px-3 py-1.5 text-xs font-bold text-white transition shadow disabled:opacity-50"
                              >
                                Revoke Session
                              </button>
                            </div>
                          </div>
                        )}

                        {isPending && (
                          <div className="mt-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 p-3.5 rounded-lg bg-purple-950/30 border border-purple-500/30">
                            <div>
                              <p className="text-xs font-bold text-purple-300 flex items-center gap-1.5">
                                <Clock className="h-4 w-4 animate-spin" />
                                <span>AWAITING USER VERIFICATION RESPONSE</span>
                              </p>
                              <p className="text-[11px] text-zinc-300 mt-0.5">
                                Verification challenge dispatched to user. Incident status: <span className="font-mono text-purple-300 font-semibold">AWAITING_USER_VERIFICATION</span>.
                              </p>
                            </div>
                            <div className="flex items-center gap-2">
                              <Link
                                href={`/verify/${activeVr.challenge_id}`}
                                target="_blank"
                                className="flex items-center gap-1 rounded bg-purple-600 hover:bg-purple-500 text-white px-3 py-1.5 text-xs font-bold transition shadow"
                              >
                                <ExternalLink className="h-3.5 w-3.5" />
                                <span>Open User Portal</span>
                              </Link>
                            </div>
                          </div>
                        )}

                        {isExpired && (
                          <div className="mt-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 p-3.5 rounded-lg bg-zinc-900 border border-zinc-700">
                            <div>
                              <p className="text-xs font-bold text-amber-400 flex items-center gap-1.5">
                                <AlertTriangle className="h-4 w-4" />
                                <span>VERIFICATION CHALLENGE EXPIRED</span>
                              </p>
                              <p className="text-[11px] text-zinc-400 mt-0.5">
                                User did not respond within the 15-minute challenge window. Incident status: <span className="font-mono text-amber-300 font-semibold">VERIFICATION_EXPIRED</span>.
                              </p>
                            </div>
                            <div className="flex items-center gap-2">
                              <button
                                onClick={handleCreateVerification}
                                disabled={verifying}
                                className="rounded bg-purple-600 hover:bg-purple-500 px-3 py-1.5 text-xs font-semibold text-white transition disabled:opacity-50"
                              >
                                {verifying ? "Creating..." : "Re-Dispatch Challenge"}
                              </button>
                              <button
                                onClick={() => handleDirectAnalystDecision("INVESTIGATING", "Challenge expired; continuing investigation.")}
                                disabled={decisionSubmitting}
                                className="rounded bg-zinc-800 hover:bg-zinc-700 px-3 py-1.5 text-xs font-medium text-white transition border border-zinc-700 disabled:opacity-50"
                              >
                                Continue Investigation
                              </button>
                            </div>
                          </div>
                        )}
                      </div>

                      {/* Collapsible History for Previous Challenges */}
                      {previousVrs.length > 0 && (
                        <div className="border-t border-zinc-800/80 pt-3">
                          <button
                            type="button"
                            onClick={() => setShowHistory(!showHistory)}
                            className="flex items-center gap-1.5 text-xs text-zinc-400 hover:text-white font-mono transition"
                          >
                            {showHistory ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                            <span>Previous Verification History ({previousVrs.length})</span>
                          </button>
                          {showHistory && (
                            <div className="mt-2 space-y-2">
                              {previousVrs.map((pvr) => (
                                <div
                                  key={pvr.id}
                                  className="flex items-center justify-between p-2.5 rounded-lg bg-zinc-900/50 border border-zinc-800 text-xs font-mono text-zinc-400"
                                >
                                  <span>Token: {pvr.challenge_id}</span>
                                  <span className="rounded px-2 py-0.5 bg-zinc-800 text-zinc-200 text-[10px] font-bold">
                                    {pvr.status}
                                  </span>
                                  <span className="text-[11px] text-zinc-500">
                                    {new Date(pvr.created_at).toLocaleTimeString()}
                                  </span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })()
              )}
            </div>
          </div>

          {/* ============================================================ */}
          {/* SECTION 9 — CONTROLLED RESPONSE ENGINE */}
          {/* ============================================================ */}
          <div className="mt-6 rounded-2xl border border-zinc-800 bg-zinc-950 p-6">
            <div className="flex items-center justify-between border-b border-zinc-800 pb-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-orange-500/10 text-orange-400 border border-orange-500/20">
                  <Shield className="h-5 w-5" />
                </div>
                <div>
                  <h2 className="text-base font-bold text-white">CONTROLLED RESPONSE ENGINE (Simulated)</h2>
                  <p className="text-xs text-zinc-400">
                    Analyst-governed containment actions. Executed safely in simulation mode for academic demo.
                  </p>
                </div>
              </div>
            </div>

            {/* Quick Propose Buttons */}
            <div className="mt-4 flex flex-wrap gap-2">
              <button
                onClick={() => handleProposeResponse("ISOLATE_HOST", `Containment for host ${incident.hostname || 'endpoint'}`)}
                disabled={proposingAction}
                className="rounded-lg bg-zinc-900 border border-zinc-700 hover:border-red-500 hover:bg-zinc-800 px-3 py-1.5 text-xs text-zinc-200 transition"
              >
                + ISOLATE_HOST
              </button>

              <button
                onClick={() => handleProposeResponse("BLOCK_SOURCE_IP", `Perimeter block for attacker ${incident.source_ip || 'IP'}`)}
                disabled={proposingAction}
                className="rounded-lg bg-zinc-900 border border-zinc-700 hover:border-orange-500 hover:bg-zinc-800 px-3 py-1.5 text-xs text-zinc-200 transition"
              >
                + BLOCK_SOURCE_IP
              </button>

              <button
                onClick={() => handleProposeResponse("REVOKE_USER_SESSION", `Invalidate active tokens for ${incident.user || 'user'}`)}
                disabled={proposingAction}
                className="rounded-lg bg-zinc-900 border border-zinc-700 hover:border-yellow-500 hover:bg-zinc-800 px-3 py-1.5 text-xs text-zinc-200 transition"
              >
                + REVOKE_USER_SESSION
              </button>

              <button
                onClick={() => handleProposeResponse("FORENSIC_SNAPSHOT", `RAM and disk capture on ${incident.hostname || 'host'}`)}
                disabled={proposingAction}
                className="rounded-lg bg-zinc-900 border border-zinc-700 hover:border-blue-500 hover:bg-zinc-800 px-3 py-1.5 text-xs text-zinc-200 transition"
              >
                + FORENSIC_SNAPSHOT
              </button>

              <button
                onClick={() => handleProposeResponse("DISABLE_ACCOUNT", `Lock account credentials for ${incident.user || 'user'}`)}
                disabled={proposingAction}
                className="rounded-lg bg-zinc-900 border border-zinc-700 hover:border-purple-500 hover:bg-zinc-800 px-3 py-1.5 text-xs text-zinc-200 transition"
              >
                + DISABLE_ACCOUNT
              </button>
            </div>

            {/* List of Proposed / Executed Response Actions */}
            <div className="mt-4 space-y-3">
              {responseActions.length === 0 ? (
                <p className="text-xs text-zinc-500 italic p-3 bg-zinc-900/30 rounded-lg">
                  No response actions recorded. Click an action above to propose controlled containment.
                </p>
              ) : (
                responseActions.map((act) => {
                  const isPending = act.status === "PENDING";
                  const isExecuted = act.status === "EXECUTED";
                  const isRejected = act.status === "REJECTED";

                  return (
                    <div
                      key={act.id}
                      className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4"
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                        <div className="flex items-center gap-3">
                          <span
                            className={`rounded px-2.5 py-0.5 text-xs font-bold font-mono ${
                              isExecuted
                                ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                                : isPending
                                ? "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30"
                                : "bg-zinc-800 text-zinc-500"
                            }`}
                          >
                            {act.status}
                          </span>
                          <span className="font-mono text-xs font-bold text-white">
                            {act.action}
                          </span>
                          <span className="text-xs text-zinc-400">
                            Reason: {act.reason}
                          </span>
                        </div>

                        {/* Analyst Confirmation Controls */}
                        {isPending && (
                          <div className="flex items-center gap-2">
                            {actionConfirmTarget === act.id ? (
                              <>
                                <button
                                  onClick={() => handleExecuteResponse(act.id)}
                                  disabled={executingActionId === act.id}
                                  className="rounded bg-emerald-600 hover:bg-emerald-500 px-3 py-1 text-xs font-bold text-white transition"
                                >
                                  {executingActionId === act.id ? "Executing..." : "CONFIRM ACTION"}
                                </button>
                                <button
                                  onClick={() => setActionConfirmTarget(null)}
                                  className="rounded bg-zinc-800 hover:bg-zinc-700 px-3 py-1 text-xs text-zinc-300 transition"
                                >
                                  CANCEL
                                </button>
                              </>
                            ) : (
                              <>
                                <button
                                  onClick={() => setActionConfirmTarget(act.id)}
                                  className="rounded bg-orange-600 hover:bg-orange-500 px-3 py-1 text-xs font-semibold text-white transition"
                                >
                                  Approve & Execute
                                </button>
                                <button
                                  onClick={() => handleRejectResponse(act.id)}
                                  className="rounded bg-zinc-800 hover:bg-zinc-700 px-3 py-1 text-xs text-zinc-400 transition"
                                >
                                  Reject
                                </button>
                              </>
                            )}
                          </div>
                        )}
                      </div>

                      {/* Execution simulation log */}
                      {act.execution_log && (
                        <div className="mt-2.5 rounded bg-zinc-950 p-2.5 border border-zinc-800/80 font-mono text-[11px] text-emerald-400">
                          {act.execution_log}
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Main 2-Column Grid */}
          <div className="mt-6 grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* LEFT COLUMN: Timeline, Detection Evidence */}
            <div className="lg:col-span-7 space-y-6">
              {/* ============================================================ */}
              {/* SECTION 4 — TIMELINE */}
              {/* ============================================================ */}
              <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-6">
                <div className="flex items-center justify-between border-b border-zinc-800 pb-4">
                  <div className="flex items-center gap-2">
                    <Clock className="h-5 w-5 text-emerald-400" />
                    <h3 className="text-base font-bold text-white">Attack Progression Timeline</h3>
                  </div>
                  <span className="text-xs text-zinc-500 font-mono">
                    {incident.timeline?.length || 0} Chronological Events
                  </span>
                </div>

                <div className="mt-5 space-y-4">
                  {incident.timeline?.map((item, idx) => (
                    <div key={idx} className="relative pl-6 pb-4 border-l border-zinc-800 last:border-l-0 last:pb-0">
                      <div className="absolute -left-1.5 top-0.5 h-3 w-3 rounded-full bg-emerald-500 border-2 border-black" />
                      <div className="flex items-center justify-between text-xs font-mono text-zinc-500">
                        <span>{new Date(item.timestamp).toLocaleTimeString()}</span>
                        <span className="text-zinc-400">{item.event_type}</span>
                      </div>
                      <p className="mt-1 text-xs font-medium text-white">
                        {item.description}
                      </p>
                      <p className="mt-0.5 text-[11px] text-zinc-400 font-mono">
                        {item.source_ip} ➔ {item.destination_ip}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              {/* ============================================================ */}
              {/* SECTION 3 — DETECTION EVIDENCE (TELEMETRY) */}
              {/* ============================================================ */}
              <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-6">
                <div className="flex items-center justify-between border-b border-zinc-800 pb-4">
                  <div className="flex items-center gap-2">
                    <Activity className="h-5 w-5 text-red-400" />
                    <h3 className="text-base font-bold text-white">Security Events & ML Detections</h3>
                  </div>
                  <span className="text-xs text-zinc-500 font-mono">
                    {incident.events?.length || 0} Total Flows
                  </span>
                </div>

                <div className="mt-4 divide-y divide-zinc-800">
                  {incident.events?.map((ev) => {
                    const isExpanded = expandedEventId === ev.id;
                    const topDet = ev.detections?.[0];
                    const topAnom = ev.anomalies?.[0];

                    return (
                      <div key={ev.id} className="py-3">
                        <div
                          onClick={() => setExpandedEventId(isExpanded ? null : ev.id)}
                          className="flex items-center justify-between cursor-pointer hover:bg-zinc-900/40 p-2 rounded-lg transition"
                        >
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-xs text-zinc-400 font-bold">
                                {ev.event_type}
                              </span>
                              <span
                                className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${
                                  severityStyles[ev.severity.toUpperCase()] || "text-zinc-400"
                                }`}
                              >
                                {ev.severity.toUpperCase()}
                              </span>
                              {topDet && topDet.predicted_class !== "BENIGN" && (
                                <span className="rounded bg-red-500/10 border border-red-500/20 text-red-400 px-1.5 py-0.5 text-[10px] font-mono">
                                  {topDet.predicted_class} ({Math.round(topDet.confidence * 100)}%)
                                </span>
                              )}
                              {topAnom?.is_anomalous && (
                                <span className="rounded bg-yellow-500/10 border border-yellow-500/20 text-yellow-400 px-1.5 py-0.5 text-[10px] font-mono">
                                  Anomaly: {topAnom.anomaly_score.toFixed(2)}
                                </span>
                              )}
                            </div>
                            <p className="mt-1 text-[11px] text-zinc-400 font-mono">
                              {ev.source_ip}:{ev.source_port} ➔ {ev.destination_ip}:{ev.destination_port} ({ev.protocol})
                            </p>
                          </div>

                          <div className="flex items-center gap-2 text-zinc-500">
                            <span className="text-[10px] font-mono">
                              {new Date(ev.timestamp).toLocaleTimeString()}
                            </span>
                            {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                          </div>
                        </div>

                        {/* Expanded details */}
                        {isExpanded && (
                          <div className="mt-2 p-3 rounded-lg bg-zinc-950 border border-zinc-800 text-[11px] font-mono text-zinc-300 space-y-1">
                            <p><strong>Event ID:</strong> {ev.id} | <strong>User:</strong> {ev.user || "N/A"} | <strong>Host:</strong> {ev.hostname || "N/A"}</p>
                            <p><strong>Raw Telemetry / Payload:</strong></p>
                            <pre className="bg-black/60 p-2 rounded text-[10px] text-emerald-400 overflow-x-auto">
                              {JSON.stringify(ev.raw_data, null, 2)}
                            </pre>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* RIGHT COLUMN: AI Investigation, RAG Evidence, MITRE, Audit Trail, Decision */}
            <div className="lg:col-span-5 space-y-6">
              {/* ============================================================ */}
              {/* SECTION 6 & 7 — AI INVESTIGATION & RAG EVIDENCE */}
              {/* ============================================================ */}
              <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-6">
                <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
                  <div className="flex items-center gap-2">
                    <BrainCircuit className="h-5 w-5 text-purple-400" />
                    <h3 className="text-base font-bold text-white">AI Analyst Investigation</h3>
                  </div>

                  {investigationResult && (
                    <span
                      className={`rounded px-2.5 py-0.5 text-xs font-bold font-mono ${
                        investigationResult.analysis_mode === "LLM_RAG"
                          ? "bg-purple-500/20 text-purple-300 border border-purple-500/30"
                          : investigationResult.analysis_mode === "LLM"
                          ? "bg-blue-500/20 text-blue-300 border border-blue-500/30"
                          : "bg-yellow-500/20 text-yellow-300 border border-yellow-500/30"
                      }`}
                    >
                      MODE: {investigationResult.analysis_mode}
                    </span>
                  )}
                </div>

                {!investigationResult ? (
                  <div className="mt-5 text-center py-8">
                    <Bot className="h-10 w-10 text-zinc-600 mx-auto mb-3" />
                    <p className="text-xs text-zinc-400">AI Investigation not yet generated for this incident.</p>
                    <button
                      onClick={handleRunInvestigation}
                      disabled={investigating}
                      className="mt-4 rounded-xl bg-purple-600 hover:bg-purple-500 text-white px-4 py-2 text-xs font-semibold shadow-lg shadow-purple-950/40 transition disabled:opacity-50"
                    >
                      {investigating ? "Querying pgvector & Ollama..." : "Run AI Investigation"}
                    </button>
                  </div>
                ) : (
                  <div className="mt-4 space-y-4">
                    {/* Summary */}
                    <div>
                      <p className="text-[10px] uppercase font-mono text-zinc-500 tracking-wider">
                        Incident Summary
                      </p>
                      <p className="mt-1 text-xs text-zinc-200 leading-relaxed bg-zinc-900/50 p-3 rounded-lg border border-zinc-800">
                        {investigationResult.incident_summary}
                      </p>
                    </div>

                    {/* Likely Attack Pattern & Root Cause */}
                    {investigationResult.likely_attack_pattern && (
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                        <div className="p-2.5 bg-zinc-900/40 rounded-lg border border-zinc-800">
                          <p className="text-[10px] font-mono text-zinc-500 uppercase">Likely Attack Pattern</p>
                          <p className="mt-1 font-semibold text-white">{investigationResult.likely_attack_pattern}</p>
                        </div>
                        <div className="p-2.5 bg-zinc-900/40 rounded-lg border border-zinc-800">
                          <p className="text-[10px] font-mono text-zinc-500 uppercase">Confidence Score</p>
                          <p className="mt-1 font-semibold text-emerald-400">
                            {Math.round((investigationResult.confidence || 0.85) * 100)}%
                          </p>
                        </div>
                      </div>
                    )}

                    {investigationResult.root_cause_hypothesis && (
                      <div>
                        <p className="text-[10px] uppercase font-mono text-zinc-500 tracking-wider">
                          Root Cause Hypothesis
                        </p>
                        <p className="mt-1 text-xs text-zinc-300 italic bg-zinc-900/40 p-2.5 rounded-lg border border-zinc-800">
                          &ldquo;{investigationResult.root_cause_hypothesis}&rdquo;
                        </p>
                      </div>
                    )}

                    {/* Prioritized Recommendations */}
                    {investigationResult.prioritized_recommendations && investigationResult.prioritized_recommendations.length > 0 && (
                      <div>
                        <p className="text-[10px] uppercase font-mono text-zinc-500 tracking-wider">
                          Prioritized Recommendations
                        </p>
                        <div className="mt-1.5 space-y-1.5">
                          {investigationResult.prioritized_recommendations.map((rec, i) => (
                            <div key={i} className="text-xs text-zinc-300 bg-zinc-900/60 p-2 rounded-lg border border-zinc-800/80">
                              {rec}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* RAG Evidence References */}
                    {investigationResult.evidence_references && investigationResult.evidence_references.length > 0 && (
                      <div className="border-t border-zinc-800 pt-3">
                        <p className="text-[10px] uppercase font-mono text-emerald-400 tracking-wider flex items-center gap-1.5">
                          <Database className="h-3.5 w-3.5" />
                          <span>Retrieved pgvector Knowledge Base Evidence</span>
                        </p>
                        <div className="mt-2 space-y-2">
                          {investigationResult.evidence_references.map((ev, i) => (
                            <div key={i} className="rounded bg-zinc-900/40 p-2 text-[11px] border border-zinc-800">
                              <span className="font-mono text-purple-400 font-bold">[{ev.document_id}]</span>{" "}
                              <span className="text-white font-medium">{ev.title}</span>
                              {ev.technique_id && (
                                <span className="ml-2 text-zinc-500 font-mono">({ev.technique_id})</span>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Analyst Warning */}
                    {investigationResult.analyst_warning && (
                      <div className="p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/20 text-yellow-300 text-xs">
                        <strong>Analyst Note:</strong> {investigationResult.analyst_warning}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* ============================================================ */}
              {/* SECTION 5 — MITRE ATT&CK */}
              {/* ============================================================ */}
              <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-6">
                <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
                  <h3 className="text-base font-bold text-white">MITRE ATT&CK Techniques</h3>
                  <span className="text-xs text-zinc-500 font-mono">
                    {incident.mitre_details?.length || 0} Mapped
                  </span>
                </div>

                <div className="mt-4 space-y-3">
                  {incident.mitre_details?.map((t) => (
                    <div key={t.technique_id} className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-3">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-xs font-bold text-purple-400">{t.technique_id}</span>
                        <span className="rounded bg-zinc-800 px-2 py-0.5 text-[10px] text-zinc-400 font-mono">{t.tactic}</span>
                      </div>
                      <p className="mt-1 text-xs font-semibold text-white">{t.name}</p>
                      <p className="mt-1 text-[11px] text-zinc-400 leading-snug line-clamp-2">{t.description}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* ============================================================ */}
              {/* SECTION 11 — ANALYST DECISION & STATE MACHINE */}
              {/* ============================================================ */}
              <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-6">
                <div className="flex items-center gap-2 border-b border-zinc-800 pb-3">
                  <FileCheck className="h-5 w-5 text-blue-400" />
                  <h3 className="text-base font-bold text-white">Analyst Decision & Triage</h3>
                </div>

                <form onSubmit={handleDecisionSubmit} className="mt-4 space-y-4">
                  <div>
                    <label className="block text-xs font-medium text-zinc-400 mb-1.5">
                      Lifecycle State Transition
                    </label>
                    <select
                      value={selectedStatus}
                      onChange={(e) => setSelectedStatus(e.target.value)}
                      className="w-full rounded-xl border border-zinc-800 bg-zinc-900 px-3 py-2.5 text-xs text-white focus:border-emerald-500 focus:outline-none"
                    >
                      <option value="INVESTIGATING">INVESTIGATING</option>
                      <option value="AWAITING_USER_VERIFICATION">AWAITING_USER_VERIFICATION</option>
                      <option value="USER_CONFIRMED">USER_CONFIRMED</option>
                      <option value="USER_DENIED">USER_DENIED</option>
                      <option value="CONTAINMENT_PENDING">CONTAINMENT_PENDING</option>
                      <option value="CONTAINED">CONTAINED</option>
                      <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
                      <option value="CONFIRMED_INCIDENT">CONFIRMED_INCIDENT</option>
                      <option value="RESOLVED">RESOLVED</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-zinc-400 mb-1.5">
                      Analyst Action Notes & Rationale
                    </label>
                    <textarea
                      rows={3}
                      value={analystNotes}
                      onChange={(e) => setAnalystNotes(e.target.value)}
                      placeholder="e.g. Activity confirmed with user, host quarantined, firewall rule applied..."
                      className="w-full rounded-xl border border-zinc-800 bg-zinc-900 p-2.5 text-xs text-white placeholder-zinc-500 focus:border-emerald-500 focus:outline-none"
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={decisionSubmitting}
                    className="w-full rounded-xl bg-zinc-900 border border-zinc-700 hover:border-emerald-500 hover:bg-zinc-800 py-2.5 text-xs font-semibold text-white transition disabled:opacity-50"
                  >
                    {decisionSubmitting ? "Submitting Decision..." : "Submit Incident Decision"}
                  </button>
                </form>
              </div>

              {/* ============================================================ */}
              {/* SECTION 10 — AUDIT TRAIL */}
              {/* ============================================================ */}
              <div className="rounded-2xl border border-zinc-800 bg-zinc-950 p-6">
                <div className="flex items-center gap-2 border-b border-zinc-800 pb-3">
                  <Terminal className="h-5 w-5 text-emerald-400" />
                  <h3 className="text-base font-bold text-white">Immutable SOC Audit Trail</h3>
                </div>

                <div className="mt-4 space-y-2.5 max-h-80 overflow-y-auto pr-1">
                  {!incident.audit_logs || incident.audit_logs.length === 0 ? (
                    <p className="text-xs text-zinc-500">No audit logs recorded yet.</p>
                  ) : (
                    incident.audit_logs.map((log) => (
                      <div key={log.id} className="rounded-lg bg-zinc-900/60 p-2.5 border border-zinc-800/80 text-[11px]">
                        <div className="flex justify-between font-mono text-[10px] text-zinc-500">
                          <span className="text-emerald-400 font-semibold">{log.action}</span>
                          <span>{new Date(log.created_at).toLocaleTimeString()}</span>
                        </div>
                        <p className="mt-1 text-zinc-300">
                          Actor: <strong>{log.actor}</strong>
                        </p>
                        {log.details && (
                          <pre className="mt-1 bg-black/40 p-1.5 rounded text-[10px] text-zinc-400 overflow-x-auto">
                            {JSON.stringify(log.details, null, 2)}
                          </pre>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
