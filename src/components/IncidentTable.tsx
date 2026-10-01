import Link from "next/link";
import { AlertTriangle, ShieldCheck, ChevronRight } from "lucide-react";
import { mockIncidents, Incident as MockIncident } from "@/data/mockIncidents";

export interface IncidentDisplayItem {
  id: string;
  db_id?: number;
  attack: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  confidence: number;
  sourceIp: string;
  target?: string;
  technique?: string;
  timestamp: string;
  status: string;
}

const severityStyles = {
  CRITICAL: "text-red-400 bg-red-500/10 border-red-500/20",
  HIGH: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  MEDIUM: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  LOW: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
};

interface IncidentTableProps {
  incidents?: IncidentDisplayItem[];
}

export default function IncidentTable({ incidents = [] }: IncidentTableProps) {
  const displayItems = incidents;

  return (
    <div className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950">
      <div className="border-b border-zinc-800 px-5 py-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="font-semibold text-white">
              Recent Security Incidents
            </h3>
            <p className="mt-1 text-xs text-zinc-500">
              Correlated multi-stage security incidents
            </p>
          </div>

          <Link
            href="/incidents"
            className="flex items-center gap-1 text-xs font-medium text-emerald-400 hover:text-emerald-300 transition"
          >
            <span>View All</span>
            <ChevronRight className="h-3 w-3" />
          </Link>
        </div>
      </div>

      <div className="divide-y divide-zinc-800">
        {displayItems.length === 0 ? (
          <div className="p-8 text-center">
            <p className="text-sm text-zinc-400">No active security incidents recorded</p>
            <p className="mt-1 text-xs text-zinc-600">Click &apos;Simulate SOC Attack&apos; above to generate live multi-stage telemetry</p>
          </div>
        ) : (
          displayItems.map((incident) => {
            const href = `/incidents/${incident.id}`;
            const isResolved = incident.status.toLowerCase() === "resolved";

            return (
              <Link
                key={incident.id}
                href={href}
                className="flex items-center justify-between px-5 py-4 transition hover:bg-zinc-900/60 block"
              >
              <div className="flex items-center gap-4">
                <div
                  className={`flex h-9 w-9 items-center justify-center rounded-lg ${
                    incident.severity === "CRITICAL" ||
                    incident.severity === "HIGH"
                      ? "bg-red-500/10"
                      : "bg-yellow-500/10"
                  }`}
                >
                  {isResolved ? (
                    <ShieldCheck className="h-4 w-4 text-emerald-400" />
                  ) : (
                    <AlertTriangle className="h-4 w-4 text-red-400" />
                  )}
                </div>

                <div>
                  <p className="text-sm font-medium text-white hover:text-emerald-400 transition">
                    {incident.attack}
                  </p>

                  <p className="mt-1 text-xs text-zinc-500">
                    <span className="font-mono text-zinc-400">{incident.id}</span> • {incident.sourceIp}
                    {incident.target && ` ➔ ${incident.target}`}
                    {incident.technique && (
                      <span className="ml-2 rounded bg-zinc-800/80 px-1.5 py-0.5 font-mono text-[10px] text-zinc-300">
                        {incident.technique}
                      </span>
                    )}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-6">
                <span
                  className={`rounded-md border px-2.5 py-1 text-[10px] font-bold ${
                    severityStyles[incident.severity] || severityStyles.MEDIUM
                  }`}
                >
                  {incident.severity}
                </span>

                <div className="w-16 text-right">
                  <p className="text-sm font-semibold text-white">
                    {incident.confidence}%
                  </p>
                  <p className="text-[10px] text-zinc-600">confidence</p>
                </div>

                <p className="w-20 text-right text-xs text-zinc-500 font-mono">
                  {incident.timestamp}
                </p>

                <ChevronRight className="h-4 w-4 text-zinc-600" />
              </div>
            </Link>
          );
        }))}
      </div>
    </div>
  );
}