"use client";

import { useEffect, useState } from "react";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Legend,
  LineChart,
  Line,
} from "recharts";
import { BarChart3, RefreshCw, PieChart as PieIcon, ShieldAlert } from "lucide-react";

import Sidebar from "@/components/Sidebar";
import Topbar from "@/components/Topbar";
import { api, AnalyticsData } from "@/lib/api";

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#10b981",
};

const ATTACK_COLORS = [
  "#ef4444",
  "#3b82f6",
  "#10b981",
  "#a855f7",
  "#f97316",
  "#ec4899",
  "#06b6d4",
];

export default function AnalyticsPage() {
  const [data, setData] = useState<AnalyticsData | null>(null);
  const [loading, setLoading] = useState(true);

  const loadAnalytics = async () => {
    try {
      setLoading(true);
      const res = await api.getAnalytics();
      setData(res);
    } catch (e) {
      console.error("Failed to load analytics:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAnalytics();
  }, []);

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
                Threat Intelligence & Detection Analytics
              </p>
              <h1 className="mt-2 text-3xl font-bold tracking-tight text-white">
                SOC Analytics
              </h1>
              <p className="mt-2 text-sm text-zinc-400">
                Database-grounded distributions of ML classifications, anomaly scores, and incident severities
              </p>
            </div>

            <button
              onClick={loadAnalytics}
              disabled={loading}
              className="flex items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900 px-3.5 py-2 text-xs font-medium text-zinc-300 transition hover:bg-zinc-800 hover:text-white"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
              <span>Refresh Metrics</span>
            </button>
          </div>

          {/* Quick Stats Banner */}
          <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-5">
              <span className="text-xs uppercase font-medium tracking-wider text-zinc-500">
                Total Correlated Incidents
              </span>
              <p className="mt-2 text-3xl font-bold font-mono text-white">
                {data?.total_incidents || 0}
              </p>
              <p className="mt-1 text-xs text-zinc-500">
                Active & resolved multi-stage investigations
              </p>
            </div>

            <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-5">
              <span className="text-xs uppercase font-medium tracking-wider text-zinc-500">
                Total Normalized Security Events
              </span>
              <p className="mt-2 text-3xl font-bold font-mono text-white">
                {data?.total_events || 0}
              </p>
              <p className="mt-1 text-xs text-zinc-500">
                Ingested telemetry evaluated through XGBoost & Isolation Forest
              </p>
            </div>
          </div>

          {/* Charts 2x2 Grid */}
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            {/* Chart 1: Attacks by Type */}
            <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-6">
              <div className="mb-4">
                <h3 className="font-semibold text-white">Attacks by ML Classification</h3>
                <p className="mt-1 text-xs text-zinc-500">
                  Distribution of supervised XGBoost predicted threat classes
                </p>
              </div>

              <div className="h-64 w-full">
                {data?.attacks_by_type && data.attacks_by_type.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={data.attacks_by_type}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                      <XAxis dataKey="name" stroke="#71717a" fontSize={11} />
                      <YAxis stroke="#71717a" fontSize={11} allowDecimals={false} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: "#09090b",
                          borderColor: "#27272a",
                          color: "#fff",
                          fontSize: "12px",
                        }}
                      />
                      <Bar dataKey="count" fill="#10b981" radius={[4, 4, 0, 0]}>
                        {data.attacks_by_type.map((entry, index) => (
                          <Cell
                            key={`cell-${index}`}
                            fill={ATTACK_COLORS[index % ATTACK_COLORS.length]}
                          />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-xs text-zinc-500">
                    No detections recorded yet.
                  </div>
                )}
              </div>
            </div>

            {/* Chart 2: Severity Distribution */}
            <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-6">
              <div className="mb-4">
                <h3 className="font-semibold text-white">Incident Severity Distribution</h3>
                <p className="mt-1 text-xs text-zinc-500">
                  Breakdown by deterministic risk tier (Critical, High, Medium, Low)
                </p>
              </div>

              <div className="h-64 w-full">
                {data?.severity_distribution && data.severity_distribution.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={data.severity_distribution}
                        dataKey="count"
                        nameKey="severity"
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={80}
                        paddingAngle={5}
                      >
                        {data.severity_distribution.map((entry) => (
                          <Cell
                            key={`sev-${entry.severity}`}
                            fill={SEVERITY_COLORS[entry.severity] || "#71717a"}
                          />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: "#09090b",
                          borderColor: "#27272a",
                          color: "#fff",
                          fontSize: "12px",
                        }}
                      />
                      <Legend wrapperStyle={{ fontSize: "11px" }} />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-xs text-zinc-500">
                    No incidents recorded yet.
                  </div>
                )}
              </div>
            </div>

            {/* Chart 3: Detection Confidence Distribution */}
            <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-6">
              <div className="mb-4">
                <h3 className="font-semibold text-white">Detection Confidence Distribution</h3>
                <p className="mt-1 text-xs text-zinc-500">
                  Model certainty levels across telemetry classifications
                </p>
              </div>

              <div className="h-64 w-full">
                {data?.confidence_distribution ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={data.confidence_distribution}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                      <XAxis dataKey="range" stroke="#71717a" fontSize={11} />
                      <YAxis stroke="#71717a" fontSize={11} allowDecimals={false} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: "#09090b",
                          borderColor: "#27272a",
                          color: "#fff",
                          fontSize: "12px",
                        }}
                      />
                      <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-xs text-zinc-500">
                    No confidence telemetry available.
                  </div>
                )}
              </div>
            </div>

            {/* Chart 4: Anomalies Over Time */}
            <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-6">
              <div className="mb-4">
                <h3 className="font-semibold text-white">Anomalies Over Time</h3>
                <p className="mt-1 text-xs text-zinc-500">
                  Events flagged as anomalous by unsupervised Isolation Forest
                </p>
              </div>

              <div className="h-64 w-full">
                {data?.anomalies_timeline ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={data.anomalies_timeline}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                      <XAxis dataKey="time" stroke="#71717a" fontSize={11} />
                      <YAxis stroke="#71717a" fontSize={11} allowDecimals={false} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: "#09090b",
                          borderColor: "#27272a",
                          color: "#fff",
                          fontSize: "12px",
                        }}
                      />
                      <Line
                        type="monotone"
                        dataKey="anomalies"
                        stroke="#eab308"
                        strokeWidth={2}
                        dot={{ r: 3, fill: "#eab308" }}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-xs text-zinc-500">
                    No anomaly timeline recorded.
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
