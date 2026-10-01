"use client";

import { useEffect, useState } from "react";
import {
  ShieldAlert,
  AlertOctagon,
  Flame,
  Server,
  Activity,
  RefreshCw,
  Cpu,
} from "lucide-react";

import Sidebar from "@/components/Sidebar";
import Topbar from "@/components/Topbar";
import StatCard from "@/components/StatCard";
import IncidentTable from "@/components/IncidentTable";
import ThreatChart from "@/components/ThreatChart";
import { api, DashboardStats } from "@/lib/api";

export default function Home() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadStats = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getDashboardStats();
      setStats(data);
    } catch (err: any) {
      console.warn("Could not fetch dashboard stats:", err);
      setError("Backend connection offline or initializing");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadStats();
    // Auto-refresh stats every 30 seconds
    const timer = setInterval(loadStats, 30000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="min-h-screen bg-black text-white">
      <Sidebar />
      <Topbar />

      <main className="ml-64 min-h-screen pt-20">
        <div className="p-8">
          {/* Page heading */}
          <div className="mb-8 flex items-end justify-between">
            <div>
              <p className="text-xs uppercase tracking-widest text-emerald-400 font-mono">
                Real-Time SOC Ingestion & Analysis
              </p>
              <h1 className="mt-2 text-3xl font-bold tracking-tight text-white">
                Security Operations
              </h1>
              <p className="mt-2 text-sm text-zinc-400">
                XGBoost ML Classification • Isolation Forest Anomaly Detection • Automated MITRE Correlation
              </p>
            </div>

            <button
              onClick={loadStats}
              disabled={loading}
              className="flex items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900 px-3.5 py-2 text-xs font-medium text-zinc-300 transition hover:bg-zinc-800 hover:text-white disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
              <span>Refresh Metrics</span>
            </button>
          </div>

          {/* Statistics Grid */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard
              title="Threat Events Detected"
              value={stats ? stats.threats_today.toString() : "—"}
              description={stats ? `${stats.total_security_events} total telemetry flows in DB` : "Awaiting database telemetry..."}
              icon={ShieldAlert}
              severity="critical"
            />

            <StatCard
              title="Critical Incidents"
              value={stats ? stats.critical_incidents.toString() : "—"}
              description={stats ? `${stats.active_incidents} active investigations in progress` : "Awaiting incident correlation..."}
              icon={AlertOctagon}
              severity="critical"
            />

            <StatCard
              title="Anomalies Flagged"
              value={stats ? stats.anomalies_detected.toString() : "—"}
              description="Unsupervised Isolation Forest baseline"
              icon={Flame}
              severity="high"
            />

            <StatCard
              title="Assets Monitored"
              value={stats ? stats.assets_monitored.toString() : "—"}
              description="Active hosts and network endpoints"
              icon={Server}
              severity="normal"
            />
          </div>

          {/* Threat Activity Visualization */}
          <div className="mt-6 rounded-xl border border-zinc-800 bg-zinc-950 p-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="font-semibold text-white">Threat Activity Timeline</h2>
                <p className="mt-1 text-xs text-zinc-500">
                  Real-time security telemetry & anomaly detections across 24 hours
                </p>
              </div>

              <div className="flex items-center gap-4 text-xs font-mono">
                <div className="flex items-center gap-1.5 text-zinc-400">
                  <Cpu className="h-3.5 w-3.5 text-emerald-400" />
                  <span>XGBoost — Development: 99.89%</span>
                </div>
                <div className="flex items-center gap-1.5 text-emerald-400">
                  <Activity className="h-4 w-4" />
                  <span>Live Telemetry</span>
                </div>
              </div>
            </div>

            <div className="mt-6">
              <ThreatChart data={stats?.threat_activity} />
            </div>
          </div>

          {/* Correlated Incidents Table */}
          <div className="mt-6">
            <IncidentTable incidents={stats?.recent_incidents} />
          </div>
        </div>
      </main>
    </div>
  );
}