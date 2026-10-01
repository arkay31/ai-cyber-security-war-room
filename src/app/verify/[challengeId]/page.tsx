"use client";

import { use, useEffect, useState } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Clock,
  User,
  CheckCircle2,
  XCircle,
  Lock,
} from "lucide-react";
import { api } from "@/lib/api";

interface ChallengeData {
  challenge_id: string;
  incident_id: string;
  user_id: string;
  status: string;
  activity_summary: string;
  created_at: string;
  expires_at: string;
  is_expired: boolean;
  question: string;
}

export default function UserVerificationPage({
  params,
}: {
  params: Promise<{ challengeId: string }>;
}) {
  const resolvedParams = use(params);
  const challengeId = resolvedParams.challengeId;

  const [challenge, setChallenge] = useState<ChallengeData | null>(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [outcome, setOutcome] = useState<"CONFIRMED" | "DENIED" | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [authPin, setAuthPin] = useState("4829");

  const loadChallenge = async () => {
    try {
      setLoading(true);
      setErrorMsg(null);
      const data = await api.getChallengeDetail(challengeId);
      setChallenge(data);
      if (data.status === "CONFIRMED" || data.status === "DENIED") {
        setOutcome(data.status as "CONFIRMED" | "DENIED");
      }
    } catch (e: any) {
      console.error("Failed to load verification challenge:", e);
      setErrorMsg("This verification challenge is invalid or has expired.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadChallenge();
  }, [challengeId]);

  const handleRespond = async (responseType: "CONFIRMED" | "DENIED") => {
    try {
      setSubmitting(true);
      setErrorMsg(null);
      const res = await api.submitChallengeResponse(challengeId, responseType, authPin);
      setOutcome(responseType);
      setChallenge((prev) => (prev ? { ...prev, status: responseType } : null));
    } catch (e: any) {
      console.error("Submission failed:", e);
      setErrorMsg(e.message || "Failed to submit verification response.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-center items-center p-4">
      {/* Brand Header */}
      <div className="w-full max-w-md mb-6 text-center">
        <div className="inline-flex items-center justify-center p-3 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 mb-3">
          <ShieldAlert className="h-8 w-8" />
        </div>
        <h1 className="text-xl font-bold tracking-tight text-white">
          SECURITY VERIFICATION
        </h1>
        <p className="text-xs text-slate-400 mt-1 font-mono uppercase tracking-widest">
          Autonomous SOC Identity Challenge
        </p>
      </div>

      {/* Main Challenge Card */}
      <div className="w-full max-w-md bg-zinc-900/90 border border-zinc-800 rounded-2xl p-6 shadow-2xl backdrop-blur">
        {loading ? (
          <div className="py-12 text-center text-sm text-zinc-400 animate-pulse">
            Verifying challenge cryptographic token...
          </div>
        ) : errorMsg ? (
          <div className="py-8 text-center">
            <div className="inline-flex p-3 rounded-full bg-red-500/10 text-red-400 mb-3">
              <AlertTriangle className="h-6 w-6" />
            </div>
            <h3 className="text-sm font-semibold text-white">Challenge Unavailable</h3>
            <p className="text-xs text-zinc-400 mt-2">{errorMsg}</p>
          </div>
        ) : outcome ? (
          /* Completed Response State */
          <div className="py-6 text-center">
            {outcome === "CONFIRMED" ? (
              <>
                <div className="inline-flex p-3 rounded-full bg-emerald-500/10 text-emerald-400 mb-3 border border-emerald-500/20">
                  <CheckCircle2 className="h-8 w-8" />
                </div>
                <h3 className="text-lg font-bold text-emerald-400">
                  USER CONFIRMED ACTIVITY
                </h3>
                <p className="text-xs text-zinc-300 mt-2 leading-relaxed">
                  Thank you, <span className="font-semibold text-white">{challenge?.user_id}</span>. You verified this activity was legitimate.
                </p>
                <div className="mt-4 p-3 rounded-lg bg-zinc-950/60 border border-zinc-800 text-[11px] text-zinc-400 text-left">
                  <span className="font-semibold text-zinc-300">SOC War Room Status:</span> The incident remains open for SOC analyst review under status <span className="font-mono text-emerald-400">USER_CONFIRMED</span>.
                </div>
              </>
            ) : (
              <>
                <div className="inline-flex p-3 rounded-full bg-red-500/10 text-red-400 mb-3 border border-red-500/20">
                  <XCircle className="h-8 w-8" />
                </div>
                <h3 className="text-lg font-bold text-red-400">
                  USER DENIED ACTIVITY
                </h3>
                <p className="text-xs text-red-200 mt-2 leading-relaxed">
                  You indicated that you did not authorize this activity.
                </p>
                <div className="mt-4 p-3 rounded-lg bg-red-950/20 border border-red-800/40 text-[11px] text-red-300 text-left">
                  <span className="font-semibold text-red-200">Immediate Containment Action:</span> Incident severity escalated to <span className="font-bold">CRITICAL</span>. Active sessions are queued for revocation by SOC analysts.
                </div>
              </>
            )}
          </div>
        ) : challenge?.is_expired ? (
          /* Expired State */
          <div className="py-6 text-center">
            <div className="inline-flex p-3 rounded-full bg-yellow-500/10 text-yellow-400 mb-3 border border-yellow-500/20">
              <Clock className="h-8 w-8" />
            </div>
            <h3 className="text-base font-bold text-yellow-400">Challenge Expired</h3>
            <p className="text-xs text-zinc-400 mt-2">
              The verification time window for this security incident has lapsed. The SOC War Room has recorded this challenge as <span className="font-mono text-yellow-300">EXPIRED</span>.
            </p>
          </div>
        ) : (
          /* Active Question & Action State */
          <div>
            <div className="flex items-center justify-between pb-4 border-b border-zinc-800">
              <div className="flex items-center gap-2 text-xs text-zinc-400 font-mono">
                <User className="h-3.5 w-3.5 text-emerald-400" />
                <span>Account: <strong className="text-white">{challenge?.user_id}</strong></span>
              </div>
              <span className="rounded bg-yellow-500/10 border border-yellow-500/20 text-yellow-400 px-2 py-0.5 text-[10px] font-bold">
                PENDING VERIFICATION
              </span>
            </div>

            <div className="my-5 space-y-3">
              <div>
                <label className="text-[10px] uppercase font-mono text-zinc-500 tracking-wider">
                  Suspicious Activity Detected
                </label>
                <p className="mt-1 text-sm text-zinc-200 bg-zinc-950/60 border border-zinc-800/80 rounded-xl p-3 leading-relaxed">
                  {challenge?.activity_summary}
                </p>
              </div>

              <div className="flex items-center justify-between text-xs text-zinc-400 font-mono pt-1">
                <span>Time: {new Date(challenge?.created_at || "").toLocaleTimeString()}</span>
                <span>Ref: {challenge?.incident_id}</span>
              </div>
            </div>

            {/* Verification Prompt Question */}
            <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/30 text-center my-4">
              <p className="text-sm font-semibold text-white">
                {challenge?.question || "Did you perform this activity?"}
              </p>
              <p className="text-[11px] text-zinc-400 mt-1">
                Select your response to confirm or trigger automated containment.
              </p>
            </div>

            {/* Demo Authentication Step */}
            <div className="mb-5 flex items-center justify-between p-2.5 rounded-lg bg-zinc-950 border border-zinc-800 text-xs">
              <div className="flex items-center gap-2 text-zinc-400">
                <Lock className="h-3.5 w-3.5 text-emerald-400" />
                <span>Demo Auth PIN:</span>
              </div>
              <input
                type="text"
                value={authPin}
                onChange={(e) => setAuthPin(e.target.value)}
                maxLength={6}
                className="w-20 bg-zinc-900 border border-zinc-700 rounded px-2 py-1 text-xs text-center font-mono text-emerald-400 focus:outline-none focus:border-emerald-500"
              />
            </div>

            {/* Action Buttons */}
            <div className="grid grid-cols-2 gap-3 pt-2">
              <button
                onClick={() => handleRespond("CONFIRMED")}
                disabled={submitting}
                className="flex items-center justify-center gap-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-semibold py-3 px-4 text-xs transition shadow-lg shadow-emerald-950/50 disabled:opacity-50"
              >
                <CheckCircle2 className="h-4 w-4" />
                <span>YES, IT WAS ME</span>
              </button>

              <button
                onClick={() => handleRespond("DENIED")}
                disabled={submitting}
                className="flex items-center justify-center gap-2 rounded-xl bg-red-600 hover:bg-red-500 text-white font-semibold py-3 px-4 text-xs transition shadow-lg shadow-red-950/50 disabled:opacity-50"
              >
                <XCircle className="h-4 w-4" />
                <span>NO, I DID NOT</span>
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Footer Disclaimer */}
      <p className="text-[10px] text-zinc-600 mt-6 max-w-sm text-center">
        Enterprise SOC War Room Verification Gateway • Responses are cryptographically timestamped and transmitted directly to the lead analyst console.
      </p>
    </div>
  );
}
