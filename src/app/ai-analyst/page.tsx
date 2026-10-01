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

  const handleRunInvestigation = async () => {
    if (!selectedIncidentId) return;
    try {
      setInvestigating(true);
      const res = await api.investigateIncident(selectedIncidentId);
      setResult(res);
    } catch (e) {
      console.error("Investigation error:", e);
      alert("Investigation failed.");
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
              Interactive incident copilot providing telemetry synthesis, ATT&CK mapping, and recommended response playbooks
            </p>
          </div>

          {/* Architecture Status Banner */}
          <div className="mb-8 rounded-xl border border-zinc-800 bg-zinc-950 p-5">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-500/10 text-emerald-400">
                  <Cpu className="h-5 w-5" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-white">
                    Investigation Pipeline Architecture
                  </h3>
                  <p className="text-xs text-zinc-400">
                    Phase 1: Deterministic telemetry synthesis & playbooks • Phase 2: RAG + Open-Source LLM
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-4 text-xs font-mono">
                <span className="flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-emerald-400">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  pgvector ready
                </span>
                <span className="flex items-center gap-1.5 rounded-full border border-zinc-800 bg-zinc-900 px-3 py-1 text-zinc-300">
                  <Database className="h-3.5 w-3.5 text-blue-400" />
                  MITRE STIX Connected
                </span>
              </div>
            </div>
          </div>

          {/* Investigation Workspace */}
          <div className="grid grid-cols-1 gap-8 lg:grid-cols-3">
            {/* Incident Selector & Metadata */}
            <div className="space-y-6">
              <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-5">
                <label className="block text-xs font-semibold uppercase tracking-wider text-zinc-400 mb-2">
                  Select Incident for Analysis
                </label>
                <select
                  value={selectedIncidentId}
                  onChange={(e) => setSelectedIncidentId(e.target.value)}
                  className="w-full rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 text-xs text-white focus:border-emerald-500 focus:outline-none"
                >
                  {incidents.map((inc) => (
                    <option key={inc.incident_id} value={inc.incident_id}>
                      {inc.incident_id} — {inc.title.slice(0, 38)}...
                    </option>
                  ))}
                </select>

                {currentIncident && (
                  <div className="mt-5 space-y-3 border-t border-zinc-850 pt-4 text-xs">
                    <div>
                      <span className="text-zinc-500">Severity:</span>{" "}
                      <strong className="text-red-400">{currentIncident.severity}</strong>
                    </div>
                    <div>
                      <span className="text-zinc-500">Risk Score:</span>{" "}
                      <strong className="font-mono text-emerald-400">{currentIncident.risk_score}/100</strong>
                    </div>
                    <div>
                      <span className="text-zinc-500">Source Attacker:</span>{" "}
                      <span className="font-mono text-zinc-300">{currentIncident.source_ip || "N/A"}</span>
                    </div>
                    <div>
                      <span className="text-zinc-500">Target Asset:</span>{" "}
                      <span className="text-zinc-300">{currentIncident.hostname || currentIncident.user || "N/A"}</span>
                    </div>
                    <div>
                      <span className="text-zinc-500">Telemetry Events:</span>{" "}
                      <span className="text-zinc-300">{currentIncident.event_count}</span>
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
                  <span>{investigating ? "Analyzing Attack Chain..." : "Generate AI Investigation"}</span>
                </button>
              </div>
            </div>

            {/* Analysis Output & Response Recommendations */}
            <div className="lg:col-span-2 space-y-6">
              {result ? (
                <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-6 space-y-6">
                  <div className="flex items-center justify-between border-b border-zinc-800 pb-4">
                    <div>
                      <h2 className="text-base font-semibold text-white">
                        AI Analyst Investigation Findings: {result.incident_id}
                      </h2>
                      <p className="mt-1 text-xs text-zinc-500 font-mono">
                        Model Confidence: {Math.round(result.confidence * 100)}% • Status: {result.status.toUpperCase()}
                      </p>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="rounded bg-purple-500/10 border border-purple-500/20 px-2.5 py-1 font-mono text-xs text-purple-400">
                        {result.analysis_mode || "LLM_RAG"}
                      </span>
                      <span className="rounded bg-emerald-500/10 border border-emerald-500/20 px-3 py-1 font-mono text-xs text-emerald-400">
                        Analysis Complete
                      </span>
                    </div>
                  </div>

                  <div>
                    <h3 className="text-xs font-bold uppercase tracking-wider text-emerald-400 mb-2">
                      Telemetry & Attack Story Synthesis
                    </h3>
                    <div className="rounded-lg border border-zinc-850 bg-zinc-900/50 p-4 text-xs text-zinc-300 leading-relaxed whitespace-pre-line">
                      {result.incident_summary || result.investigation_summary}
                    </div>
                  </div>

                  <div>
                    <h3 className="text-xs font-bold uppercase tracking-wider text-amber-400 mb-2">
                      Prioritized Response Steps
                    </h3>
                    <div className="space-y-2">
                      {(result.recommended_steps || result.investigation_steps || []).map((st, i) => (
                        <div
                          key={i}
                          className="rounded-lg border border-zinc-850 bg-zinc-900/40 p-3 text-xs text-zinc-300 flex items-start gap-2"
                        >
                          <span className="font-mono text-emerald-400 font-bold">{i + 1}.</span>
                          <span>{st}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div>
                    <h3 className="text-xs font-bold uppercase tracking-wider text-blue-400 mb-2">
                      Rapid Containment Actions
                    </h3>
                    <div className="flex flex-wrap gap-2">
                      {(result.recommended_actions || result.prioritized_recommendations || []).map((act, i) => (
                        <span
                          key={i}
                          className="rounded-lg border border-blue-500/30 bg-blue-500/10 px-3 py-1.5 text-xs font-medium text-blue-300"
                        >
                          {act}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="flex h-96 flex-col items-center justify-center rounded-xl border border-dashed border-zinc-800 bg-zinc-950 p-8 text-center">
                  <BrainCircuit className="h-12 w-12 text-zinc-700 mb-3" />
                  <h3 className="text-base font-semibold text-white">
                    Select an incident to run AI Investigation
                  </h3>
                  <p className="mt-1 text-xs text-zinc-500 max-w-sm">
                    The AI Analyst correlates security telemetry, ML flow detections, Isolation Forest anomalies, and MITRE tactics into actionable containment guidance.
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
