"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  AlertTriangle,
  ShieldCheck,
  ChevronRight,
  Filter,
  RefreshCw,
  Search,
  ExternalLink,
} from "lucide-react";

import Sidebar from "@/components/Sidebar";
import Topbar from "@/components/Topbar";
import { api, IncidentSummary } from "@/lib/api";

const severityStyles: Record<string, string> = {
  CRITICAL: "text-red-400 bg-red-500/10 border-red-500/20",
  HIGH: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  MEDIUM: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  LOW: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
};

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState<string>("");

  const loadIncidents = async () => {
    try {
      setLoading(true);
      const data = await api.getIncidents({
        severity: severityFilter || undefined,
        status: statusFilter || undefined,
      });
      setIncidents(data);
    } catch (e) {
      console.error("Failed to load incidents:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIncidents();
  }, [severityFilter, statusFilter]);

  const filteredIncidents = incidents.filter((inc) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      inc.incident_id.toLowerCase().includes(q) ||
      inc.title.toLowerCase().includes(q) ||
      (inc.source_ip && inc.source_ip.toLowerCase().includes(q)) ||
      (inc.hostname && inc.hostname.toLowerCase().includes(q)) ||
      (inc.user && inc.user.toLowerCase().includes(q))
    );
  });

  return (
    <div className="min-h-screen bg-black text-white">
      <Sidebar />
      <Topbar />

      <main className="ml-64 min-h-screen pt-20">
        <div className="p-8">
          {/* Header */}
          <div className="mb-8 flex items-end justify-between">
            <div>
              <p className="text-xs uppercase tracking-widest text-emerald-400 font-mono">
                Incident Triage & Correlation
              </p>
              <h1 className="mt-2 text-3xl font-bold tracking-tight text-white">
                Correlated Incidents
              </h1>
              <p className="mt-2 text-sm text-zinc-400">
                Multi-stage attack chains grouped deterministically by host, IP, and temporal windows
              </p>
            </div>

            <button
              onClick={loadIncidents}
              disabled={loading}
              className="flex items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900 px-3.5 py-2 text-xs font-medium text-zinc-300 transition hover:bg-zinc-800 hover:text-white"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
              <span>Refresh</span>
            </button>
          </div>

          {/* Filter Toolbar */}
          <div className="mb-6 flex flex-wrap items-center justify-between gap-4 rounded-xl border border-zinc-800 bg-zinc-950 p-4">
            <div className="flex flex-1 items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900/60 px-3 py-2 text-sm max-w-md">
              <Search className="h-4 w-4 text-zinc-500" />
              <input
                type="text"
                placeholder="Search by ID, Hostname, Source IP, or User..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-transparent text-xs text-white placeholder-zinc-500 focus:outline-none"
              />
            </div>

            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2 text-xs text-zinc-400">
                <Filter className="h-3.5 w-3.5" />
                <span>Severity:</span>
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="rounded border border-zinc-800 bg-zinc-900 px-2 py-1 text-xs text-zinc-200 focus:outline-none"
                >
                  <option value="">All Severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>

              <div className="flex items-center gap-2 text-xs text-zinc-400">
                <span>Status:</span>
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="rounded border border-zinc-800 bg-zinc-900 px-2 py-1 text-xs text-zinc-200 focus:outline-none"
                >
                  <option value="">All Statuses</option>
                  <option value="Investigating">Investigating</option>
                  <option value="Contained">Contained</option>
                  <option value="Resolved">Resolved</option>
                  <option value="False Positive">False Positive</option>
                </select>
              </div>
            </div>
          </div>

          {/* Incidents List Table */}
          <div className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950">
            <div className="border-b border-zinc-800 px-6 py-4 flex items-center justify-between">
              <h2 className="text-sm font-semibold text-white">
                Active Incidents ({filteredIncidents.length})
              </h2>
              <p className="text-xs text-zinc-500">
                Showing incidents detected by real-time correlation
              </p>
            </div>

            {loading ? (
              <div className="p-12 text-center text-sm text-zinc-500">
                Loading incidents from PostgreSQL...
              </div>
            ) : filteredIncidents.length === 0 ? (
              <div className="p-12 text-center text-sm text-zinc-500">
                No incidents match the active filters.
              </div>
            ) : (
              <div className="divide-y divide-zinc-800">
                {filteredIncidents.map((incident) => {
                  const isResolved = incident.status === "Resolved";
                  return (
                    <div
                      key={incident.incident_id}
                      className="flex items-center justify-between px-6 py-4.5 transition hover:bg-zinc-900/50"
                    >
                      <div className="flex items-start gap-4">
                        <div
                          className={`mt-1 flex h-10 w-10 items-center justify-center rounded-lg ${
                            incident.severity === "CRITICAL"
                              ? "bg-red-500/10 text-red-400"
                              : incident.severity === "HIGH"
                              ? "bg-orange-500/10 text-orange-400"
                              : "bg-yellow-500/10 text-yellow-400"
                          }`}
                        >
                          {isResolved ? (
                            <ShieldCheck className="h-5 w-5 text-emerald-400" />
                          ) : (
                            <AlertTriangle className="h-5 w-5" />
                          )}
                        </div>

                        <div>
                          <div className="flex items-center gap-3">
                            <span className="font-mono text-xs font-semibold text-emerald-400">
                              {incident.incident_id}
                            </span>
                            <span
                              className={`rounded border px-2 py-0.5 text-[10px] font-bold ${
                                severityStyles[incident.severity] || severityStyles.MEDIUM
                              }`}
                            >
                              {incident.severity}
                            </span>
                            <span className="rounded bg-zinc-800 px-2 py-0.5 text-[10px] text-zinc-300 font-mono">
                              Risk {incident.risk_score}/100
                            </span>
                          </div>

                          <h3 className="mt-1.5 text-base font-semibold text-white hover:text-emerald-400 transition">
                            <Link href={`/incidents/${incident.incident_id}`}>
                              {incident.title}
                            </Link>
                          </h3>

                          <p className="mt-1 text-xs text-zinc-400">
                            {incident.summary}
                          </p>

                          <div className="mt-2.5 flex flex-wrap items-center gap-3 text-xs text-zinc-500">
                            <span>
                              Attacker: <strong className="text-zinc-300 font-mono">{incident.source_ip || "N/A"}</strong>
                            </span>
                            <span>•</span>
                            <span>
                              Target: <strong className="text-zinc-300">{incident.hostname || incident.user || "N/A"}</strong>
                            </span>
                            <span>•</span>
                            <span>
                              Telemetry Events: <strong className="text-zinc-300">{incident.event_count}</strong>
                            </span>

                            {incident.mitre_techniques.length > 0 && (
                              <>
                                <span>•</span>
                                <div className="flex items-center gap-1.5">
                                  {incident.mitre_techniques.map((tid) => (
                                    <span
                                      key={tid}
                                      className="rounded bg-zinc-800/90 px-1.5 py-0.5 font-mono text-[10px] text-zinc-300"
                                    >
                                      {tid}
                                    </span>
                                  ))}
                                </div>
                              </>
                            )}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-4">
                        <div className="text-right">
                          <span
                            className={`inline-block rounded-full px-2.5 py-1 text-[10px] font-medium ${
                              incident.status === "Resolved"
                                ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                                : incident.status === "Contained"
                                ? "bg-blue-500/10 text-blue-400 border border-blue-500/20"
                                : "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20"
                            }`}
                          >
                            {incident.status}
                          </span>
                          <p className="mt-1 text-[10px] text-zinc-500 font-mono">
                            {new Date(incident.updated_at).toLocaleTimeString([], {
                              hour: "2-digit",
                              minute: "2-digit",
                            })}
                          </p>
                        </div>

                        <Link
                          href={`/incidents/${incident.incident_id}`}
                          className="flex items-center gap-1 rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-1.5 text-xs font-medium text-zinc-300 transition hover:border-emerald-500/40 hover:text-white"
                        >
                          <span>Investigate</span>
                          <ChevronRight className="h-3.5 w-3.5" />
                        </Link>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
