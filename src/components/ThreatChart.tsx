"use client";

import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Legend,
} from "recharts";

interface ThreatActivityItem {
  time: string;
  threats: number;
  anomalies: number;
}

interface ThreatChartProps {
  data?: ThreatActivityItem[];
}

export default function ThreatChart({ data = [] }: ThreatChartProps) {
  if (!data || data.length === 0) {
    return (
      <div className="h-64 w-full flex flex-col items-center justify-center rounded-lg border border-dashed border-zinc-800 bg-zinc-950/40 p-4 text-center">
        <p className="text-xs text-zinc-400 font-medium">No live telemetry time-series recorded</p>
        <p className="text-[11px] text-zinc-500 mt-1">Telemetry events will chart dynamically as they are ingested from PostgreSQL</p>
      </div>
    );
  }

  const chartData = data;

  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart
          data={chartData}
          margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
        >
          <defs>
            <linearGradient id="threatGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
            </linearGradient>
            <linearGradient id="anomalyGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#eab308" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#eab308" stopOpacity={0.0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
          <XAxis
            dataKey="time"
            stroke="#71717a"
            fontSize={11}
            tickLine={false}
          />
          <YAxis
            stroke="#71717a"
            fontSize={11}
            tickLine={false}
            allowDecimals={false}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: "#09090b",
              borderColor: "#27272a",
              borderRadius: "0.5rem",
              fontSize: "12px",
              color: "#fafafa",
            }}
          />
          <Legend
            wrapperStyle={{ fontSize: "11px", paddingTop: "8px" }}
          />
          <Area
            type="monotone"
            dataKey="threats"
            name="Threat Events"
            stroke="#ef4444"
            strokeWidth={2}
            fillOpacity={1}
            fill="url(#threatGradient)"
          />
          <Area
            type="monotone"
            dataKey="anomalies"
            name="Anomalies"
            stroke="#eab308"
            strokeWidth={2}
            fillOpacity={1}
            fill="url(#anomalyGradient)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
