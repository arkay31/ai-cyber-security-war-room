"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  Node,
  Edge,
  useNodesState,
  useEdgesState,
} from "reactflow";
import "reactflow/dist/style.css";
import {
  Network,
  RefreshCw,
  Info,
  Layers,
  ExternalLink,
  ShieldAlert,
  Server,
  User,
  Radio,
  X,
  ArrowRight,
  Maximize2,
} from "lucide-react";

import Sidebar from "@/components/Sidebar";
import Topbar from "@/components/Topbar";
import { api, AttackGraphData, IncidentSummary } from "@/lib/api";

export default function AttackGraphPage() {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [loading, setLoading] = useState(true);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [selectedIncidentFilter, setSelectedIncidentFilter] = useState<string>("");
  const [selectedNodeData, setSelectedNodeData] = useState<any | null>(null);

  useEffect(() => {
    api.getIncidents().then((data) => setIncidents(data)).catch(() => {});
  }, []);

  const loadGraph = useCallback(async (filterIncId?: string) => {
    try {
      setLoading(true);
      const incParam = filterIncId ? parseInt(filterIncId, 10) : undefined;
      const data: AttackGraphData = await api.getAttackGraph(isNaN(incParam as number) ? undefined : incParam);

      // Style nodes according to cyber defense aesthetics
      const styledNodes: Node[] = data.nodes.map((n) => {
        const type = n.data.type || "default";
        let bg = "#18181b";
        let border = "#3f3f46";
        let color = "#fafafa";

        if (type === "incident") {
          bg = "#450a0a";
          border = "#ef4444";
          color = "#fca5a5";
        } else if (type === "source_ip") {
          bg = "#27272a";
          border = "#f97316";
          color = "#fdba74";
        } else if (type === "target_host") {
          bg = "#172554";
          border = "#3b82f6";
          color = "#93c5fd";
        } else if (type === "user") {
          bg = "#3b0764";
          border = "#a855f7";
          color = "#d8b4fe";
        } else if (type === "mitre") {
          bg = "#064e3b";
          border = "#10b981";
          color = "#6ee7b7";
        }

        return {
          id: n.id,
          position: n.position,
          data: {
            ...n.data,
            label: (
              <div className="px-3 py-2 text-center min-w-[140px]">
                <div className="font-mono text-[11px] font-bold">{n.data.label}</div>
                {n.data.title && (
                  <div className="text-[10px] text-zinc-300 mt-0.5 max-w-[150px] truncate">
                    {n.data.title}
                  </div>
                )}
                {n.data.risk_score !== undefined && (
                  <div className="text-[10px] font-mono text-red-400 mt-0.5 font-bold">
                    Risk: {n.data.risk_score}/100
                  </div>
                )}
                {n.data.tactic && (
                  <div className="text-[9px] font-mono text-emerald-300 mt-0.5 uppercase">
                    {n.data.tactic}
                  </div>
                )}
              </div>
            ),
          },
          style: {
            background: bg,
            border: `1.5px solid ${border}`,
            borderRadius: "0.5rem",
            color: color,
            boxShadow: "0 4px 6px -1px rgba(0, 0, 0, 0.5)",
            cursor: "pointer",
          },
        };
      });

      const styledEdges: Edge[] = data.edges.map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        label: e.label,
        animated: e.animated ?? true,
        style: { stroke: "#71717a", strokeWidth: 1.5 },
        labelStyle: { fill: "#d4d4d8", fontSize: 10, fontFamily: "monospace", fontWeight: 600 },
        labelBgStyle: { fill: "#09090b", fillOpacity: 0.9 },
        labelBgPadding: [4, 2] as [number, number],
      }));

      setNodes(styledNodes);
      setEdges(styledEdges);
    } catch (e) {
      console.error("Failed to load attack graph:", e);
    } finally {
      setLoading(false);
    }
  }, [setNodes, setEdges]);

  useEffect(() => {
    loadGraph(selectedIncidentFilter);
  }, [selectedIncidentFilter, loadGraph]);

  const onNodeClick = (_: React.MouseEvent, node: Node) => {
    setSelectedNodeData(node.data);
  };

  return (
    <div className="min-h-screen bg-black text-white">
      <Sidebar />
      <Topbar />

      <main className="ml-64 min-h-screen pt-20">
        <div className="p-8">
          {/* Header */}
          <div className="mb-6 flex flex-col md:flex-row md:items-end md:justify-between gap-4">
            <div>
              <p className="text-xs uppercase tracking-widest text-emerald-400 font-mono">
                Adversary Topology & Entity Link Analysis
              </p>
              <h1 className="mt-2 text-3xl font-bold tracking-tight text-white">
                Attack Graph
              </h1>
              <p className="mt-2 text-sm text-zinc-400">
                4-Column Correlated Entity Topology: Adversary IP (Col 1) ➔ Incident (Col 2) ➔ Target Host / User (Col 3) ➔ MITRE Technique (Col 4)
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              {/* Incident Filter Dropdown */}
              <select
                value={selectedIncidentFilter}
                onChange={(e) => setSelectedIncidentFilter(e.target.value)}
                className="rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 text-xs text-zinc-300 focus:outline-none focus:border-emerald-500"
              >
                <option value="">All Correlated Incidents</option>
                {incidents.map((inc) => (
                  <option key={inc.id} value={inc.id.toString()}>
                    {inc.incident_id} — {inc.title.slice(0, 28)}...
                  </option>
                ))}
              </select>

              <button
                onClick={() => loadGraph(selectedIncidentFilter)}
                disabled={loading}
                className="flex items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900 px-3.5 py-2 text-xs font-medium text-zinc-300 transition hover:bg-zinc-800 hover:text-white"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
                <span>Refresh Graph</span>
              </button>
            </div>
          </div>

          {/* Legend */}
          <div className="mb-4 flex flex-wrap items-center gap-4 rounded-xl border border-zinc-800 bg-zinc-950 px-5 py-3 text-xs">
            <span className="text-zinc-500 uppercase font-mono font-bold text-[10px]">Topology Legend:</span>
            <div className="flex items-center gap-1.5">
              <span className="h-3 w-3 rounded bg-zinc-700 border border-orange-500" />
              <span className="text-zinc-300">Col 1: Adversary Source IP</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="h-3 w-3 rounded bg-red-600 border border-red-400" />
              <span className="text-zinc-300">Col 2: Correlated Incident</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="h-3 w-3 rounded bg-blue-900 border border-blue-500" />
              <span className="text-zinc-300">Col 3: Target Endpoint</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="h-3 w-3 rounded bg-purple-900 border border-purple-500" />
              <span className="text-zinc-300">Col 3: Abused User</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="h-3 w-3 rounded bg-emerald-950 border border-emerald-500" />
              <span className="text-zinc-300">Col 4: MITRE Technique</span>
            </div>
          </div>

          {/* Graph Canvas & Side Drawer */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            <div className={`${selectedNodeData ? "lg:col-span-8" : "lg:col-span-12"} transition-all`}>
              <div className="h-[640px] w-full rounded-xl border border-zinc-800 bg-zinc-950 overflow-hidden relative">
                {loading ? (
                  <div className="flex h-full items-center justify-center text-sm text-zinc-500 font-mono">
                    Calculating graph layout and spacing...
                  </div>
                ) : nodes.length === 0 ? (
                  <div className="flex h-full items-center justify-center text-sm text-zinc-500 font-mono">
                    No active incident nodes found. Seed synthetic events from the Top Bar to visualize.
                  </div>
                ) : (
                  <ReactFlow
                    nodes={nodes}
                    edges={edges}
                    onNodesChange={onNodesChange}
                    onEdgesChange={onEdgesChange}
                    onNodeClick={onNodeClick}
                    fitView
                    minZoom={0.2}
                    maxZoom={2.0}
                  >
                    <Background color="#27272a" gap={24} size={1} />
                    <Controls className="!bg-zinc-900 !border-zinc-800 !text-white" />
                    <MiniMap
                      nodeColor={(n) => {
                        if (n.style?.background) return n.style.background as string;
                        return "#3f3f46";
                      }}
                      className="!bg-zinc-900 !border-zinc-800 rounded-lg overflow-hidden"
                    />
                  </ReactFlow>
                )}
              </div>
            </div>

            {/* Entity Inspector Side Panel */}
            {selectedNodeData && (
              <div className="lg:col-span-4 rounded-xl border border-zinc-800 bg-zinc-950 p-6 flex flex-col justify-between">
                <div className="space-y-4">
                  <div className="flex items-center justify-between border-b border-zinc-850 pb-3">
                    <div className="flex items-center gap-2">
                      <span
                        className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase font-mono ${
                          selectedNodeData.type === "incident"
                            ? "bg-red-500/20 text-red-300 border border-red-500/30"
                            : selectedNodeData.type === "source_ip"
                            ? "bg-orange-500/20 text-orange-300 border border-orange-500/30"
                            : selectedNodeData.type === "target_host"
                            ? "bg-blue-500/20 text-blue-300 border border-blue-500/30"
                            : selectedNodeData.type === "user"
                            ? "bg-purple-500/20 text-purple-300 border border-purple-500/30"
                            : "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                        }`}
                      >
                        {selectedNodeData.type}
                      </span>
                      <h3 className="text-sm font-bold text-white font-mono truncate max-w-[180px]">
                        {typeof selectedNodeData.label === "string" ? selectedNodeData.label : selectedNodeData.technique_id || selectedNodeData.type}
                      </h3>
                    </div>
                    <button
                      onClick={() => setSelectedNodeData(null)}
                      className="text-zinc-500 hover:text-white text-xs font-mono p-1 rounded hover:bg-zinc-900"
                    >
                      <X className="h-4 w-4" />
                    </button>
                  </div>

                  {/* Incident Node Details */}
                  {selectedNodeData.type === "incident" && (
                    <div className="space-y-3 text-xs">
                      <div>
                        <span className="text-zinc-500">Incident Title:</span>
                        <p className="text-white font-semibold mt-0.5">{selectedNodeData.title}</p>
                      </div>
                      <div className="grid grid-cols-2 gap-2 pt-1">
                        <div className="bg-zinc-900 p-2.5 rounded-lg border border-zinc-800">
                          <span className="text-[10px] text-zinc-500 uppercase font-mono">Severity</span>
                          <p className="font-bold text-red-400 mt-0.5">{selectedNodeData.severity}</p>
                        </div>
                        <div className="bg-zinc-900 p-2.5 rounded-lg border border-zinc-800">
                          <span className="text-[10px] text-zinc-500 uppercase font-mono">Risk Score</span>
                          <p className="font-bold text-emerald-400 mt-0.5">{selectedNodeData.risk_score}/100</p>
                        </div>
                      </div>
                      <div>
                        <span className="text-zinc-500">Current Status:</span>
                        <p className="font-mono text-zinc-300 font-bold mt-0.5">{selectedNodeData.status}</p>
                      </div>
                      {selectedNodeData.summary && (
                        <div>
                          <span className="text-zinc-500">Incident Narrative:</span>
                          <p className="text-zinc-400 mt-0.5 leading-relaxed bg-zinc-900/50 p-2.5 rounded border border-zinc-850">
                            {selectedNodeData.summary}
                          </p>
                        </div>
                      )}
                      <div>
                        <span className="text-zinc-500">Correlated Telemetry:</span>
                        <p className="text-zinc-300 mt-0.5">{selectedNodeData.event_count || 0} Security Events</p>
                      </div>
                    </div>
                  )}

                  {/* MITRE Technique Details */}
                  {selectedNodeData.type === "mitre" && (
                    <div className="space-y-3 text-xs">
                      <div>
                        <span className="text-zinc-500">Technique ID:</span>
                        <p className="text-emerald-400 font-mono font-bold mt-0.5">{selectedNodeData.technique_id}</p>
                      </div>
                      <div>
                        <span className="text-zinc-500">Technique Name:</span>
                        <p className="text-white font-semibold mt-0.5">{selectedNodeData.name}</p>
                      </div>
                      <div>
                        <span className="text-zinc-500">Tactic:</span>
                        <p className="text-purple-300 font-mono mt-0.5">{selectedNodeData.tactic}</p>
                      </div>
                      {selectedNodeData.description && (
                        <div>
                          <span className="text-zinc-500">Adversary TTP Description:</span>
                          <p className="text-zinc-400 mt-0.5 leading-relaxed bg-zinc-900/50 p-2.5 rounded border border-zinc-850 line-clamp-6">
                            {selectedNodeData.description}
                          </p>
                        </div>
                      )}
                      {selectedNodeData.url && (
                        <div className="pt-2">
                          <a
                            href={selectedNodeData.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1.5 text-xs text-emerald-400 hover:text-emerald-300 transition"
                          >
                            <span>Open MITRE ATT&CK Documentation</span>
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Target Host Details */}
                  {selectedNodeData.type === "target_host" && (
                    <div className="space-y-3 text-xs">
                      <div>
                        <span className="text-zinc-500">Asset Hostname:</span>
                        <p className="text-white font-mono font-semibold mt-0.5">{selectedNodeData.title || selectedNodeData.label}</p>
                      </div>
                      <div>
                        <span className="text-zinc-500">Network Segment:</span>
                        <p className="text-zinc-300 mt-0.5">Corporate Internal Subnet (RFC-1918)</p>
                      </div>
                      <div>
                        <span className="text-zinc-500">Containment Readiness:</span>
                        <p className="text-blue-400 font-mono mt-0.5 font-semibold">EDR Agent Active • Isolation Supported</p>
                      </div>
                    </div>
                  )}

                  {/* Source IP Details */}
                  {selectedNodeData.type === "source_ip" && (
                    <div className="space-y-3 text-xs">
                      <div>
                        <span className="text-zinc-500">Adversary Source IP:</span>
                        <p className="text-orange-400 font-mono font-bold mt-0.5">{selectedNodeData.label}</p>
                      </div>
                      <div>
                        <span className="text-zinc-500">Reputation Assessment:</span>
                        <p className="text-zinc-300 mt-0.5">External Untrusted Ingress Traffic</p>
                      </div>
                      <div>
                        <span className="text-zinc-500">Firewall Response:</span>
                        <p className="text-orange-300 font-mono mt-0.5 font-semibold">Perimeter ACL Block Available</p>
                      </div>
                    </div>
                  )}

                  {/* User Details */}
                  {selectedNodeData.type === "user" && (
                    <div className="space-y-3 text-xs">
                      <div>
                        <span className="text-zinc-500">Abused Username:</span>
                        <p className="text-purple-300 font-mono font-bold mt-0.5">{selectedNodeData.username || selectedNodeData.label}</p>
                      </div>
                      <div>
                        <span className="text-zinc-500">Identity Realm:</span>
                        <p className="text-zinc-300 mt-0.5">Enterprise Active Directory / SSO</p>
                      </div>
                      <div>
                        <span className="text-zinc-500">Verification Capability:</span>
                        <p className="text-purple-400 font-mono mt-0.5 font-semibold">Human-in-the-Loop Challenge Supported</p>
                      </div>
                    </div>
                  )}
                </div>

                {/* Footer Link if Incident Node */}
                {selectedNodeData.type === "incident" && (
                  <div className="pt-4 border-t border-zinc-850">
                    <Link
                      href={`/incidents/${typeof selectedNodeData.label === "string" ? selectedNodeData.label : selectedNodeData.incident_id || ""}`}
                      className="flex items-center justify-center gap-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-black py-2.5 text-xs font-bold transition shadow"
                    >
                      <span>Open Incident Investigation</span>
                      <ArrowRight className="h-3.5 w-3.5" />
                    </Link>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
