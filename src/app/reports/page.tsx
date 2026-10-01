"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  FileText,
  Printer,
  Download,
  ShieldAlert,
  ChevronRight,
  Calendar,
  User,
  Server,
  Globe,
} from "lucide-react";

import Sidebar from "@/components/Sidebar";
import Topbar from "@/components/Topbar";
import { api, IncidentReport } from "@/lib/api";

export default function ReportsPage() {
  const [reports, setReports] = useState<IncidentReport[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .getReports()
      .then((data) => setReports(data))
      .catch((e) => console.error("Error loading reports:", e))
      .finally(() => setLoading(false));
  }, []);

  const handlePrint = () => {
    window.print();
  };

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
                Post-Incident Documentation & Compliance
              </p>
              <h1 className="mt-2 text-3xl font-bold tracking-tight text-white">
                Incident Reports
              </h1>
              <p className="mt-2 text-sm text-zinc-400">
                Structured forensic incident reports generated directly from database telemetry and correlation results
              </p>
            </div>

            <button
              onClick={handlePrint}
              className="flex items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900 px-3.5 py-2 text-xs font-medium text-zinc-300 transition hover:bg-zinc-800 hover:text-white"
            >
              <Printer className="h-3.5 w-3.5 text-emerald-400" />
              <span>Export / Print Reports</span>
            </button>
          </div>

          {/* Reports List */}
          {loading ? (
            <div className="p-12 text-center text-sm text-zinc-500">
              Generating structured reports from PostgreSQL incident records...
            </div>
          ) : reports.length === 0 ? (
            <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-12 text-center text-sm text-zinc-500">
              No incident records found. Seed synthetic scenarios from the top bar to generate reports.
            </div>
          ) : (
            <div className="space-y-6">
              {reports.map((rep) => (
                <div
                  key={rep.report_id}
                  className="rounded-xl border border-zinc-800 bg-zinc-950 p-6 transition hover:border-zinc-700"
                >
                  <div className="flex flex-wrap items-start justify-between gap-4 border-b border-zinc-850 pb-4">
                    <div>
                      <div className="flex items-center gap-3">
                        <span className="font-mono text-xs font-bold text-emerald-400">
                          {rep.report_id}
                        </span>
                        <span
                          className={`rounded border px-2 py-0.5 text-[10px] font-bold ${
                            rep.severity === "CRITICAL"
                              ? "text-red-400 bg-red-500/10 border-red-500/20"
                              : rep.severity === "HIGH"
                              ? "text-orange-400 bg-orange-500/10 border-orange-500/20"
                              : "text-yellow-400 bg-yellow-500/10 border-yellow-500/20"
                          }`}
                        >
                          {rep.severity}
                        </span>
                        <span className="rounded bg-zinc-800 px-2 py-0.5 text-[10px] text-zinc-300 font-mono">
                          Risk Score: {rep.risk_score}/100
                        </span>
                      </div>

                      <h2 className="mt-2 text-lg font-bold text-white">
                        {rep.title}
                      </h2>

                      <p className="mt-1 text-xs text-zinc-400 max-w-3xl">
                        {rep.summary}
                      </p>
                    </div>

                    <div className="flex items-center gap-3">
                      <Link
                        href={`/incidents/${rep.incident_id}`}
                        className="flex items-center gap-1.5 rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-1.5 text-xs font-medium text-emerald-400 hover:bg-zinc-800 transition"
                      >
                        <span>Investigate Incident</span>
                        <ChevronRight className="h-3.5 w-3.5" />
                      </Link>
                    </div>
                  </div>

                  {/* Forensic Key Evidence Points */}
                  <div className="mt-4 grid grid-cols-2 gap-4 text-xs sm:grid-cols-4">
                    <div>
                      <span className="text-[10px] uppercase text-zinc-500 font-medium">
                        Adversary Origin
                      </span>
                      <p className="font-mono text-zinc-200 mt-0.5">{rep.source_ip || "Unknown"}</p>
                    </div>

                    <div>
                      <span className="text-[10px] uppercase text-zinc-500 font-medium">
                        Target Host / Asset
                      </span>
                      <p className="text-zinc-200 mt-0.5">{rep.hostname || "Internal Asset"}</p>
                    </div>

                    <div>
                      <span className="text-[10px] uppercase text-zinc-500 font-medium">
                        Abused Account
                      </span>
                      <p className="text-zinc-200 mt-0.5">{rep.user || "N/A"}</p>
                    </div>

                    <div>
                      <span className="text-[10px] uppercase text-zinc-500 font-medium">
                        Telemetry Evidence Count
                      </span>
                      <p className="text-zinc-200 mt-0.5 font-mono">{rep.event_count} Security Events</p>
                    </div>
                  </div>

                  {/* Mapped MITRE Techniques */}
                  {rep.mitre_techniques && rep.mitre_techniques.length > 0 && (
                    <div className="mt-4 border-t border-zinc-850 pt-3">
                      <span className="text-[10px] uppercase font-semibold text-zinc-500">
                        Associated MITRE ATT&CK Techniques:
                      </span>
                      <div className="mt-2 flex flex-wrap gap-2">
                        {rep.mitre_techniques.map((t, idx) => (
                          <span
                            key={idx}
                            className="rounded-md border border-zinc-800 bg-zinc-900 px-2.5 py-1 font-mono text-[11px] text-purple-300"
                          >
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="mt-4 flex items-center justify-between text-[11px] text-zinc-500 border-t border-zinc-850/60 pt-3">
                    <span>
                      Generated At:{" "}
                      <strong className="text-zinc-400 font-mono">
                        {new Date(rep.generated_at).toLocaleString()}
                      </strong>
                    </span>
                    <span>Status: <strong className="text-zinc-300">{rep.status}</strong></span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
