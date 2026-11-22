"use client";

import { useEffect, useState, useRef } from "react";
import {
  Bell,
  Search,
  Circle,
  Play,
  CheckCircle2,
  AlertCircle,
  ChevronDown,
  Sparkles,
  ShieldAlert,
  Terminal,
  Activity,
  Layers,
  Zap,
} from "lucide-react";
import { api, HealthStatus } from "@/lib/api";

const DEMO_SCENARIOS = [
  {
    id: "account_takeover",
    name: "Account Takeover & Exfil (Faculty Demo)",
    badge: "Recommended",
    badgeColor: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
    desc: "7-step kill chain: SSH brute force -> sudo abuse -> shadow read -> C2 egress.",
  },
  {
    id: "port_scan",
    name: "SYN Stealth Port Reconnaissance",
    badge: "Discovery",
    badgeColor: "text-blue-400 bg-blue-500/10 border-blue-500/20",
    desc: "Rapid TCP SYN probe sweep across ports 21, 22, 80, 443, 3306, 8080.",
  },
  {
    id: "brute_force",
    name: "SSH Credential Brute Force",
    badge: "Credential Access",
    badgeColor: "text-orange-400 bg-orange-500/10 border-orange-500/20",
    desc: "Distributed password guessing attempts targeting administrative port 22.",
  },
  {
    id: "ddos",
    name: "Volumetric SYN Flood DDoS",
    badge: "Impact",
    badgeColor: "text-red-400 bg-red-500/10 border-red-500/20",
    desc: "High flow packet rate TCP SYN flood overwhelming ingress HTTPS gateway.",
  },
  {
    id: "privilege_escalation",
    name: "Local Sudo Privilege Escalation",
    badge: "PrivEsc",
    badgeColor: "text-purple-400 bg-purple-500/10 border-purple-500/20",
    desc: "Unauthorized sudo binary execution to spawn root shell and read shadow file.",
  },
];

export default function Topbar() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [seeding, setSeeding] = useState(false);
  const [seedSuccess, setSeedSuccess] = useState<string | null>(null);
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let isMounted = true;

    const checkHealth = () => {
      api
        .getHealth()
        .then((data) => {
          if (isMounted) setHealth(data);
        })
        .catch(() => {
          if (isMounted) setHealth(null);
        });
    };

    checkHealth();
    const interval = setInterval(checkHealth, 5000);

    const handleClickOutside = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);

    return () => {
      isMounted = false;
      clearInterval(interval);
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, []);

  const handleTriggerScenario = async (scenarioId: string) => {
    if (seeding) return;
    try {
      setSeeding(true);
      setMenuOpen(false);
      const res = await api.simulateScenario(scenarioId);
      const scName = DEMO_SCENARIOS.find((s) => s.id === scenarioId)?.name || "Scenario";
      setSeedSuccess(scName);

      setTimeout(() => {
        setSeedSuccess(null);
        if (res?.incident_id) {
          window.location.href = `/incidents/${res.incident_id}`;
        } else {
          window.location.reload();
        }
      }, 1200);
    } catch (e) {
      console.error("Failed to simulate scenario:", e);
      alert("Failed to simulate scenario. Ensure backend server is running.");
    } finally {
      setSeeding(false);
    }
  };

  const isOnline = health?.status === "healthy";

  return (
    <header className="fixed left-64 right-0 top-0 z-30 flex h-20 items-center justify-between border-b border-zinc-800 bg-zinc-950/95 px-8 backdrop-blur">
      <div>
        <p className="text-xs uppercase tracking-widest text-zinc-500">
          Security Operations Center
        </p>

        <h2 className="mt-1 text-lg font-semibold text-white">
          AI Cyber Security War Room
        </h2>
      </div>

      <div className="flex items-center gap-4">
        {/* Interactive Interview Demo Scenarios Dropdown */}
        <div className="relative" ref={menuRef}>
          <button
            onClick={() => setMenuOpen(!menuOpen)}
            disabled={seeding}
            className="flex items-center gap-2 rounded-lg border border-red-500/40 bg-gradient-to-r from-red-500/20 to-orange-500/20 px-3.5 py-1.5 text-xs font-semibold text-white shadow-lg shadow-red-950/30 transition hover:from-red-500/30 hover:to-orange-500/30 disabled:opacity-50"
            title="Inject curated attack scenarios for interview demonstrations"
          >
            {seedSuccess ? (
              <>
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                <span className="text-emerald-300">
                  {seedSuccess} Ingested!
                </span>
              </>
            ) : (
              <>
                <Sparkles className="h-3.5 w-3.5 text-orange-400" />
                <span>
                  {seeding ? "Executing Scenario..." : "Interview Demo Scenarios"}
                </span>
                <ChevronDown className={`h-3 w-3 text-zinc-400 transition-transform ${menuOpen ? "rotate-180" : ""}`} />
              </>
            )}
          </button>

          {menuOpen && (
            <div className="absolute right-0 mt-2 w-96 rounded-xl border border-zinc-800 bg-zinc-900/95 p-2 shadow-2xl backdrop-blur z-50">
              <div className="px-3 py-2 border-b border-zinc-800/80">
                <p className="text-xs font-semibold text-white flex items-center gap-1.5">
                  <Terminal className="h-3.5 w-3.5 text-red-400" />
                  Interviewer Live Injection Scenarios
                </p>
                <p className="text-[11px] text-zinc-400 mt-0.5">
                  Select an attack pattern to stream through the full ML (TreeSHAP) $\to$ RAG $\to$ LLM SOC lifecycle.
                </p>
              </div>

              <div className="mt-1 divide-y divide-zinc-800/40">
                {DEMO_SCENARIOS.map((sc) => (
                  <button
                    key={sc.id}
                    onClick={() => handleTriggerScenario(sc.id)}
                    className="w-full text-left p-2.5 rounded-lg hover:bg-zinc-800/70 transition group flex flex-col gap-1"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-zinc-100 group-hover:text-red-300 transition">
                        {sc.name}
                      </span>
                      <span
                        className={`text-[10px] px-1.5 py-0.5 rounded border font-medium ${sc.badgeColor}`}
                      >
                        {sc.badge}
                      </span>
                    </div>
                    <p className="text-[11px] text-zinc-400 leading-relaxed">
                      {sc.desc}
                    </p>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* System status */}
        <div
          className={`flex items-center gap-2 rounded-full border px-4 py-2 ${
            isOnline
              ? "border-emerald-500/20 bg-emerald-500/5 text-emerald-400"
              : "border-yellow-500/20 bg-yellow-500/5 text-yellow-400"
          }`}
        >
          <Circle
            className={`h-2.5 w-2.5 fill-current ${
              isOnline ? "text-emerald-400" : "text-yellow-400"
            }`}
          />
          <span className="text-xs font-medium">
            {isOnline ? "SOC War Room Online" : "Connecting..."}
          </span>
        </div>

        {/* Notifications */}
        <button className="relative text-zinc-400 transition hover:text-white">
          <Bell className="h-5 w-5" />
          <span className="absolute -right-1 -top-1 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-[9px] font-bold text-white">
            3
          </span>
        </button>
      </div>
    </header>
  );
}