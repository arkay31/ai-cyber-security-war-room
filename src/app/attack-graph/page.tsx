"use client";

import { useEffect, useState, useMemo } from "react";
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
import { Network, RefreshCw, Info, Layers } from "lucide-react";

import Sidebar from "@/components/Sidebar";
import Topbar from "@/components/Topbar";
import { api, AttackGraphData } from "@/lib/api";

export default function AttackGraphPage() {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [loading, setLoading] = useState(true);

  const loadGraph = async () => {
    try {
      setLoading(true);
      const data: AttackGraphData = await api.getAttackGraph();

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
            label: (
              <div className="px-3 py-1.5 text-center">
                <div className="font-mono text-[11px] font-bold">{n.data.label}</div>
                {n.data.title && (
                  <div className="text-[9px] text-zinc-400 mt-0.5 max-w-[140px] truncate">
                    {n.data.title}
                  </div>
                )}
                {n.data.risk_score !== undefined && (
                  <div className="text-[9px] font-mono text-red-400 mt-0.5">
                    Risk: {n.data.risk_score}/100
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
          },
        };
      });

      const styledEdges: Edge[] = data.edges.map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        label: e.label,
        animated: e.animated ?? true,
        style: { stroke: "#52525b", strokeWidth: 1.5 },
        labelStyle: { fill: "#a1a1aa", fontSize: 10, fontFamily: "monospace" },
        labelBgStyle: { fill: "#09090b", fillOpacity: 0.8 },
      }));

      setNodes(styledNodes);
      setEdges(styledEdges);
    } catch (e) {
      console.error("Failed to load attack graph:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadGraph();
  }, []);

  return (
    <div className="min-h-screen bg-black text-white">
      <Sidebar />
      <Topbar />

      <main className="ml-64 min-h-screen pt-20">
        <div className="p-8">
          {/* Header */}
          <div className="mb-6 flex items-end justify-between">
            <div>
              <p className="text-xs uppercase tracking-widest text-emerald-400 font-mono">
                Adversary Topology & Entity Link Analysis
              </p>
              <h1 className="mt-2 text-3xl font-bold tracking-tight text-white">
                Attack Graph
              </h1>
              <p className="mt-2 text-sm text-zinc-400">
                Visualizing correlated entity relationships: Attacker IP ➔ Incident ➔ Target Host / User ➔ MITRE Technique
              </p>
            </div>

            <button
              onClick={loadGraph}
              disabled={loading}
              className="flex items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900 px-3.5 py-2 text-xs font-medium text-zinc-300 transition hover:bg-zinc-800 hover:text-white"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
              <span>Refresh Graph</span>
            </button>
          </div>

          {/* Legend */}
          <div className="mb-4 flex flex-wrap items-center gap-4 rounded-xl border border-zinc-800 bg-zinc-950 px-5 py-3 text-xs">
            <div className="flex items-center gap-1.5">
              <span className="h-3 w-3 rounded bg-red-600 border border-red-400" />
              <span className="text-zinc-300">Incident</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="h-3 w-3 rounded bg-zinc-700 border border-orange-500" />
              <span className="text-zinc-300">Attacker Source IP</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="h-3 w-3 rounded bg-blue-900 border border-blue-500" />
              <span className="text-zinc-300">Target Host</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="h-3 w-3 rounded bg-purple-900 border border-purple-500" />
              <span className="text-zinc-300">Compromised User</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="h-3 w-3 rounded bg-emerald-950 border border-emerald-500" />
              <span className="text-zinc-300">MITRE Technique</span>
            </div>
          </div>

          {/* Graph Canvas Container */}
          <div className="h-[620px] w-full rounded-xl border border-zinc-800 bg-zinc-950 overflow-hidden relative">
            {loading ? (
              <div className="flex h-full items-center justify-center text-sm text-zinc-500 font-mono">
                Rendering attack relationship graph...
              </div>
            ) : nodes.length === 0 ? (
              <div className="flex h-full items-center justify-center text-sm text-zinc-500 font-mono">
                No active incidents found in database. Seed synthetic events to render.
              </div>
            ) : (
              <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                fitView
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
      </main>
    </div>
  );
}
