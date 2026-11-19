"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  BrainCircuit,
  Zap,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  Database,
  Cpu,
  FileCode,
  ExternalLink,
  ShieldAlert,
  BookOpen,
  Timer,
  Layers,
} from "lucide-react";

import Sidebar from "@/components/Sidebar";
import Topbar from "@/components/Topbar";
import { api, IncidentSummary, InvestigationResult } from "@/lib/api";

export default function AIAnalystPage() {
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>("");
  const [investigating, setInvestigating] = useState(false);
  const [result, setResult] = useState<InvestigationResult | null>(null);

  useEffect(() => {
    api.getIncidents().then((data) => {
      setIncidents(data);
      if (data.length > 0) {
        setSelectedIncidentId(data[0].incident_id);
      }
    });
  }, []);

  const handleIncidentChange = (newIncidentId: string) => {
    setSelectedIncidentId(newIncidentId);
    // Prevent displaying stale results from another incident
    setResult(null);
  };

  const handleRunInvestigation = async () => {
    if (!selectedIncidentId) return;
    try {
      setInvestigating(true);
      const res = await api.investigateIncident(selectedIncidentId);
      setResult(res);
    } catch (e: any) {
      console.error("Investigation error:", e);
      alert(e.message || "Investigation failed.");
    } finally {
      setInvestigating(false);
    }
  };

  const currentIncident = incidents.find((i) => i.incident_id === selectedIncidentId);

  return (
    <div className="min-h-screen bg-black text-white">
      <Sidebar />
      <Topbar />

      <main className="ml-64 min-h-screen pt-20">
        <div className="p-8">
          {/* Header */}
          <div className="mb-8">
            <p className="text-xs uppercase tracking-widest text-emerald-400 font-mono">
              Automated Investigation & Synthesis
            </p>
            <h1 className="mt-2 text-3xl font-bold tracking-tight text-white">
              AI Security Analyst
            </h1>
            <p className="mt-2 text-sm text-zinc-400">
              Interactive SOC copilot synthesizing telemetry, pgvector RAG playbooks, MITRE tactics, and prioritized response steps
            </p>
          </div>

          {/* Architecture Status Banner */}
          <div className="mb-8 rounded-xl border border-zinc-800 bg-zinc-950 p-5">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
                  <Cpu className="h-5 w-5" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-white">
                    Investigation Pipeline: pgvector RAG + Local Ollama LLM
                  </h3>
                  <p className="text-xs text-zinc-400">
                    Dual Architecture: Real pgvector semantic vector retrieval paired with local llama3 inference and transparent rule-based fallback
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-4 text-xs font-mono">
                <span className="flex items-center gap-1.5 rounded-full border border-purple-500/30 bg-purple-500/10 px-3 py-1 text-purple-300">
                  <Database className="h-3.5 w-3.5 text-purple-400" />
                  pgvector (all-MiniLM-L6-v2)
                </span>
                <span className="flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-emerald-400">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  MITRE STIX Connected
                </span>
              </div>
            </div>
          </div>

          {/* Investigation Workspace */}
          <div className="grid grid-cols-1 gap-8 lg:grid-cols-3">
            {/* LEFT COLUMN: Incident Selector & Metadata */}
            <div className="space-y-6">
              <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-5">
                <label className="block text-xs font-semibold uppercase tracking-wider text-zinc-400 mb-2">
                  Select Incident for Analysis
                </label>
                <select
                  value={selectedIncidentId}
                  onChange={(e) => handleIncidentChange(e.target.value)}
                  className="w-full rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 text-xs text-white focus:border-emerald-500 focus:outline-none"
                >
                  {incidents.map((inc) => (
                    <option key={inc.incident_id} value={inc.incident_id}>
                      {inc.incident_id} — {inc.title.slice(0, 36)}...
                    </option>
                  ))}
                </select>

                {currentIncident && (
                  <div className="mt-5 space-y-3 border-t border-zinc-850 pt-4 text-xs">
                    <div>
                      <span className="text-zinc-500">Severity:</span>{" "}
                      <strong className="text-red-400 uppercase font-mono">{currentIncident.severity}</strong>
                    </div>
                    <div>
                      <span className="text-zinc-500">Risk Score:</span>{" "}
                      <strong className="font-mono text-emerald-400">{currentIncident.risk_score}/100</strong>
                    </div>
                    <div>
                      <span className="text-zinc-500">Source Attacker:</span>{" "}
                      <span className="font-mono text-zinc-300">{currentIncident.source_ip || "Unknown"}</span>
                    </div>
                    <div>
                      <span className="text-zinc-500">Target Asset:</span>{" "}
                      <span className="text-zinc-300">{currentIncident.hostname || currentIncident.user || "N/A"}</span>
                    </div>
                    <div>
                      <span className="text-zinc-500">Telemetry Events:</span>{" "}
                      <span className="text-zinc-300">{currentIncident.event_count} Security Events</span>
                    </div>

                    <Link
                      href={`/incidents/${currentIncident.incident_id}`}
                      className="mt-3 flex items-center gap-1.5 text-emerald-400 hover:text-emerald-300 transition"
                    >
                      <span>View Full Incident Timeline</span>
                      <ArrowRight className="h-3 w-3" />
                    </Link>
                  </div>
                )}

                <button
                  onClick={handleRunInvestigation}
                  disabled={investigating || !selectedIncidentId}
                  className="mt-6 flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-500 py-3 text-xs font-semibold text-black transition hover:bg-emerald-400 disabled:opacity-50"
                >
                  <BrainCircuit className={`h-4 w-4 ${investigating ? "animate-spin" : ""}`} />
                  <span>{investigating ? "Running RAG & Inference..." : "Generate AI Investigation"}</span>
                </button>
              </div>

              {/* RAG Knowledge Base Indicator */}
              <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-5">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 mb-2 flex items-center gap-1.5">
                  <Database className="h-4 w-4 text-purple-400" />
                  <span>Knowledge Base Playbooks</span>
                </h4>
                <p className="text-xs text-zinc-400 leading-relaxed">
                  pgvector indexes standardized Incident Response Playbooks (NIST SP 800-61 / MITRE D3FEND). Semantic queries match incident telemetry vectors against response actions.
                </p>
              </div>
            </div>

            {/* RIGHT COLUMN: Analysis Output & Findings */}
            <div className="lg:col-span-2 space-y-6">
              {result ? (
                <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-6 space-y-6">
                  {/* Top Bar with Mode, Model, Status & Latency */}
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-zinc-800 pb-4">
                    <div>
                      <h2 className="text-base font-semibold text-white flex items-center gap-2">
                        <span>AI Analyst Findings:</span>
                        <span className="font-mono text-emerald-400">{result.incident_id}</span>
                      </h2>
                      <p className="mt-1 text-xs text-zinc-500 font-mono">
                        Model Confidence: {Math.round(result.confidence * 100)}% • Status: {result.status.toUpperCase()}
                      </p>
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`rounded px-2.5 py-1 font-mono text-xs font-semibold border ${
                          result.analysis_mode === "LLM_RAG"
                            ? "bg-purple-500/10 border-purple-500/30 text-purple-300"
                            : result.analysis_mode === "LLM"
                            ? "bg-blue-500/10 border-blue-500/30 text-blue-300"
                            : "bg-amber-500/10 border-amber-500/30 text-amber-300"
                        }`}
                      >
                        MODE: {result.analysis_mode}
                      </span>
                      <span
                        className={`rounded px-2.5 py-1 font-mono text-xs font-semibold border ${
                          result.llm_status === "LLM_UNAVAILABLE"
                            ? "bg-red-500/10 border-red-500/30 text-red-400"
                            : "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                        }`}
                      >
                        LLM: {result.llm_status || (result.analysis_mode === "RULE_BASED" ? "LLM_UNAVAILABLE" : "ACTIVE")}
                      </span>
                      {result.llm_model && (
                        <span className="rounded bg-zinc-900 border border-zinc-800 px-2.5 py-1 font-mono text-xs text-zinc-300">
                          {result.llm_model}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Real-time Diagnostics (Latency / Tok/s) */}
                  {result.llm_metrics && (
                    <div className="flex flex-wrap items-center gap-4 rounded-lg bg-zinc-900/60 border border-zinc-800 px-3.5 py-2 text-xs font-mono text-zinc-400">
                      <div className="flex items-center gap-1.5 text-zinc-300">
                        <Timer className="h-3.5 w-3.5 text-emerald-400" />
                        <span>Latency: <strong className="text-white">{result.llm_metrics.total_duration_sec}s</strong></span>
                      </div>
                      {result.llm_metrics.tokens_per_second !== undefined && (
                        <div>
                          Tokens/sec: <strong className="text-white">{result.llm_metrics.tokens_per_second}</strong>
                        </div>
                      )}
                      {result.llm_metrics.eval_count !== undefined && (
                        <div>
                          Output Tokens: <strong className="text-white">{result.llm_metrics.eval_count}</strong>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Fallback Warning Banner if LLM_UNAVAILABLE */}
                  {(result.analysis_mode === "RULE_BASED" || result.llm_status === "LLM_UNAVAILABLE") && (
                    <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3.5 flex items-start gap-3 text-xs text-amber-300">
                      <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
                      <div>
                        <strong className="font-semibold text-amber-200">Deterministic Rule-Based Fallback Active:</strong>{" "}
                        Local Ollama LLM was unavailable ({result.llm_error || "connection refused or timed out"}). Telemetry was synthesized using deterministic SOC playbooks and rule-based attack graph correlation. No hallucinated content was injected.
                      </div>
                    </div>
                  )}

                  {/* Analyst Verification Advisory */}
                  {result.analyst_warning && (
                    <div className="rounded-lg border border-yellow-500/20 bg-yellow-500/5 p-3 text-xs text-yellow-300 flex items-start gap-2">
                      <AlertTriangle className="h-4 w-4 text-yellow-400 shrink-0 mt-0.5" />
                      <div>
                        <strong className="font-semibold text-yellow-200">Analyst Verification Advisory:</strong>{" "}
                        {result.analyst_warning}
                      </div>
                    </div>
                  )}

                  {/* Section 1: Telemetry & Attack Story Synthesis */}
                  <div>
                    <h3 className="text-xs font-bold uppercase tracking-wider text-emerald-400 mb-2">
                      Telemetry & Attack Story Synthesis
                    </h3>
                    <div className="rounded-lg border border-zinc-850 bg-zinc-900/50 p-4 text-xs text-zinc-300 leading-relaxed whitespace-pre-line">
                      {result.incident_summary || result.investigation_summary}
                    </div>
                  </div>

                  {/* Section 2: Observed Telemetry Evidence */}
                  {result.observed_evidence && result.observed_evidence.length > 0 && (
                    <div>
                      <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-400 mb-2">
                        Observed Evidence & Correlation Signals
                      </h3>
                      <div className="space-y-1.5">
                        {result.observed_evidence.map((ev, i) => (
                          <div
                            key={i}
                            className="rounded-lg border border-zinc-850 bg-zinc-900/30 px-3 py-2 text-xs text-zinc-300 flex items-start gap-2"
                          >
                            <span className="font-mono text-emerald-400 font-bold">•</span>
                            <span>{ev}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Section 3: Root Cause Hypothesis */}
                  {result.root_cause_hypothesis && (
                    <div>
                      <h3 className="text-xs font-bold uppercase tracking-wider text-purple-400 mb-2">
                        Root Cause Hypothesis
                      </h3>
                      <div className="rounded-lg border border-purple-500/20 bg-purple-500/5 p-3.5 text-xs text-purple-200 italic leading-relaxed">
                        &ldquo;{result.root_cause_hypothesis}&rdquo;
                      </div>
                    </div>
                  )}

                  {/* Section 4: Mapped MITRE ATT&CK Techniques */}
                  <div>
                    <h3 className="text-xs font-bold uppercase tracking-wider text-purple-400 mb-2 flex items-center justify-between">
                      <span>Mapped MITRE ATT&CK Techniques</span>
                      <span className="text-[10px] font-normal font-mono text-zinc-500">
                        {result.mitre_techniques?.length || 0} mapped
                      </span>
                    </h3>

                    {result.mitre_techniques && result.mitre_techniques.length > 0 ? (
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                        {result.mitre_techniques.map((t, i) => (
                          <div
                            key={i}
                            className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-3 flex flex-col justify-between"
                          >
                            <div>
                              <div className="flex items-center justify-between">
                                <span className="font-mono text-xs font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded">
                                  {t.technique_id}
                                </span>
                                {t.tactic && (
                                  <span className="text-[10px] font-mono text-purple-300 bg-purple-500/10 px-1.5 py-0.5 rounded">
                                    {t.tactic}
                                  </span>
                                )}
                              </div>
                              <p className="mt-2 text-xs font-medium text-white">{t.name}</p>
                            </div>

                            <div className="mt-2.5 pt-2 border-t border-zinc-800/80 flex items-center justify-end">
                              <a
                                href={`https://attack.mitre.org/techniques/${t.technique_id.replace(".", "/")}/`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-[11px] text-zinc-400 hover:text-emerald-400 flex items-center gap-1 transition"
                              >
                                <span>ATT&CK Spec</span>
                                <ExternalLink className="h-3 w-3" />
                              </a>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="rounded-lg border border-zinc-850 bg-zinc-900/30 p-3 text-xs text-zinc-500 italic">
                        No specific MITRE techniques mapped for this incident.
                      </div>
                    )}
                  </div>

                  {/* Section 5: Retrieved pgvector RAG Evidence & Playbook References */}
                  <div>
                    <h3 className="text-xs font-bold uppercase tracking-wider text-emerald-400 mb-2 flex items-center justify-between">
                      <span className="flex items-center gap-1.5">
                        <Database className="h-3.5 w-3.5 text-purple-400" />
                        <span>Retrieved pgvector Knowledge Base Evidence</span>
                      </span>
                      <span className="text-[10px] font-normal font-mono text-zinc-500">
                        {result.evidence_references?.length || 0} retrieved
                      </span>
                    </h3>

                    {result.evidence_references && result.evidence_references.length > 0 ? (
                      <div className="space-y-2.5">
                        {result.evidence_references.map((ev, i) => (
                          <div
                            key={i}
                            className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3 text-xs"
                          >
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <span className="font-mono text-[11px] font-bold text-purple-300 bg-purple-500/10 border border-purple-500/20 px-2 py-0.5 rounded">
                                  {ev.document_id}
                                </span>
                                <span className="font-semibold text-white">{ev.title}</span>
                              </div>
                              {ev.similarity_score !== undefined && ev.similarity_score !== null && (
                                <span className="font-mono text-[10px] text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-1.5 py-0.5 rounded">
                                  Similarity: {Math.round(ev.similarity_score * 100)}%
                                </span>
                              )}
                            </div>

                            {ev.content_snippet && (
                              <p className="mt-2 text-zinc-400 leading-relaxed text-[11px] bg-zinc-950/60 p-2.5 rounded border border-zinc-800/60">
                                {ev.content_snippet}
                              </p>
                            )}

                            {ev.technique_id && (
                              <p className="mt-2 text-[10px] text-zinc-500 font-mono">
                                Aligned Technique: <span className="text-purple-300 font-semibold">{ev.technique_id}</span>
                              </p>
                            )}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="rounded-lg border border-zinc-850 bg-zinc-900/30 p-3 text-xs text-zinc-500 italic">
                        No semantic RAG playbooks retrieved for this incident telemetry.
                      </div>
                    )}
                  </div>

                  {/* Section 6: Prioritized Recommendations */}
                  <div>
                    <h3 className="text-xs font-bold uppercase tracking-wider text-amber-400 mb-2">
                      Prioritized Response Steps & Playbook Recommendations
                    </h3>
                    <div className="space-y-2">
                      {(result.prioritized_recommendations?.length
                        ? result.prioritized_recommendations
                        : result.recommended_steps || result.investigation_steps || []
                      ).map((rec, i) => (
                        <div
                          key={i}
                          className="rounded-lg border border-zinc-850 bg-zinc-900/40 p-3 text-xs text-zinc-300 flex items-start gap-2.5"
                        >
                          <span className="font-mono text-emerald-400 font-bold shrink-0">{i + 1}.</span>
                          <span className="leading-relaxed">{rec}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Section 7: Rapid Containment Actions (Simulated) */}
                  <div>
                    <h3 className="text-xs font-bold uppercase tracking-wider text-blue-400 mb-2 flex items-center justify-between">
                      <span>Available Containment Actions (Simulated)</span>
                      <span className="text-[10px] font-mono text-zinc-500 uppercase">
                        Simulation Mode Active
                      </span>
                    </h3>
                    <div className="flex flex-wrap gap-2">
                      {(result.recommended_actions || [
                        "Verify User Authenticity",
                        "Block Attacker IP (Simulated)",
                        "Isolate Endpoint Host (Simulated)",
                        "Revoke User Session (Simulated)",
                        "Capture Forensic Snapshot (Simulated)"
                      ]).map((act, i) => (
                        <span
                          key={i}
                          className="rounded-lg border border-blue-500/30 bg-blue-500/10 px-3 py-1.5 text-xs font-medium text-blue-300"
                        >
                          {act}
                        </span>
                      ))}
                    </div>
                    <p className="text-[11px] text-zinc-500 mt-2">
                      To govern and execute these containment actions, open the{" "}
                      <Link
                        href={`/incidents/${result.incident_id}`}
                        className="text-emerald-400 hover:text-emerald-300 underline font-medium"
                      >
                        Incident Details Console
                      </Link>
                      .
                    </p>
                  </div>
                </div>
              ) : (
                <div className="flex h-96 flex-col items-center justify-center rounded-xl border border-dashed border-zinc-800 bg-zinc-950 p-8 text-center">
                  <BrainCircuit className="h-12 w-12 text-zinc-700 mb-3" />
                  <h3 className="text-base font-semibold text-white">
                    Select an incident to run AI Investigation
                  </h3>
                  <p className="mt-1 text-xs text-zinc-500 max-w-sm">
                    The AI Analyst correlates security telemetry, ML flow detections, Isolation Forest anomalies, pgvector playbooks, and MITRE tactics into actionable containment guidance.
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
