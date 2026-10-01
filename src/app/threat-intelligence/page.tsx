"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Radar,
  Shield,
  Search,
  ExternalLink,
  Layers,
  AlertCircle,
  Database,
} from "lucide-react";

import Sidebar from "@/components/Sidebar";
import Topbar from "@/components/Topbar";
import { api, MitreTechnique } from "@/lib/api";

export default function ThreatIntelligencePage() {
  const [techniques, setTechniques] = useState<MitreTechnique[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [selectedTactic, setSelectedTactic] = useState("");

  useEffect(() => {
    api
      .getMitreTechniques()
      .then((data) => setTechniques(data))
      .catch((e) => console.error("Error loading MITRE techniques:", e))
      .finally(() => setLoading(false));
  }, []);

  const tactics = Array.from(new Set(techniques.map((t) => t.tactic)));

  const filtered = techniques.filter((t) => {
    const matchesSearch =
      !search ||
      t.technique_id.toLowerCase().includes(search.toLowerCase()) ||
      t.name.toLowerCase().includes(search.toLowerCase()) ||
      t.description.toLowerCase().includes(search.toLowerCase());

    const matchesTactic = !selectedTactic || t.tactic === selectedTactic;
    return matchesSearch && matchesTactic;
  });

  return (
    <div className="min-h-screen bg-black text-white">
      <Sidebar />
      <Topbar />

      <main className="ml-64 min-h-screen pt-20">
        <div className="p-8">
          {/* Header */}
          <div className="mb-8">
            <p className="text-xs uppercase tracking-widest text-emerald-400 font-mono">
              Knowledge Base & MITRE ATT&CK Matrix
            </p>
            <h1 className="mt-2 text-3xl font-bold tracking-tight text-white">
              Threat Intelligence
            </h1>
            <p className="mt-2 text-sm text-zinc-400">
              Enterprise security tactics, adversary techniques, and associated live incidents in the War Room
            </p>
          </div>

          {/* Search and Filters */}
          <div className="mb-6 flex flex-wrap items-center justify-between gap-4 rounded-xl border border-zinc-800 bg-zinc-950 p-4">
            <div className="flex flex-1 items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900/60 px-3 py-2 text-sm max-w-md">
              <Search className="h-4 w-4 text-zinc-500" />
              <input
                type="text"
                placeholder="Search technique ID (e.g. T1110), name, or keyword..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full bg-transparent text-xs text-white placeholder-zinc-500 focus:outline-none"
              />
            </div>

            <div className="flex items-center gap-2">
              <span className="text-xs text-zinc-400">Tactic Filter:</span>
              <select
                value={selectedTactic}
                onChange={(e) => setSelectedTactic(e.target.value)}
                className="rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-1.5 text-xs text-zinc-300 focus:outline-none"
              >
                <option value="">All Tactics ({tactics.length})</option>
                {tactics.map((tac) => (
                  <option key={tac} value={tac}>
                    {tac}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Techniques Grid */}
          {loading ? (
            <div className="p-12 text-center text-sm text-zinc-500">
              Loading MITRE ATT&CK techniques from PostgreSQL...
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-3">
              {filtered.map((t) => (
                <div
                  key={t.technique_id}
                  className="rounded-xl border border-zinc-800 bg-zinc-950 p-5 transition hover:border-zinc-700 hover:bg-zinc-900/30 flex flex-col justify-between"
                >
                  <div>
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded">
                        {t.technique_id}
                      </span>
                      <span className="rounded bg-purple-500/10 border border-purple-500/20 px-2 py-0.5 text-[10px] font-medium text-purple-300">
                        {t.tactic}
                      </span>
                    </div>

                    <h3 className="mt-3 text-base font-semibold text-white">
                      {t.name}
                    </h3>

                    <p className="mt-2 text-xs text-zinc-400 line-clamp-4 leading-relaxed">
                      {t.description}
                    </p>
                  </div>

                  <div className="mt-4 border-t border-zinc-850 pt-3 flex items-center justify-between text-xs">
                    <span className="text-zinc-500 font-mono">
                      Mapped Incidents:{" "}
                      <strong className="text-emerald-400">{t.incident_count || 0}</strong>
                    </span>

                    <a
                      href={`https://attack.mitre.org/techniques/${t.technique_id}/`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-[11px] text-zinc-400 hover:text-emerald-400 transition"
                    >
                      <span>MITRE Docs</span>
                      <ExternalLink className="h-3 w-3" />
                    </a>
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
