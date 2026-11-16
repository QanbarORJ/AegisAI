"use client";

import { useState } from "react";
import { loginUser } from "@/lib/api";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setErrorMessage(null);
    setStatusMessage(null);
    try {
      const result = await loginUser(email, password);
      setStatusMessage(
        `Authenticated as ${result.user.email} (${result.user.role}) in tenant ${result.organization.name}`
      );
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : "Authentication failed");
    }
  }

  return (
    <div className="max-w-md mx-auto mt-10 rounded-xl border border-slate-800 bg-slate-900/60 p-6">
      <h1 className="text-xl font-bold text-slate-100">Tenant Sign In</h1>
      <p className="text-xs text-slate-400 mt-1">
        Authenticate to access your organization&apos;s AI security assessments.
      </p>

      <form onSubmit={handleSubmit} className="mt-6 space-y-4">
        <div>
          <label className="block text-xs font-medium text-slate-300 mb-1">
            Work Email
          </label>
          <input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
            placeholder="engineer@acme.io"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-slate-300 mb-1">
            Password
          </label>
          <input
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100"
          />
        </div>
        {errorMessage && (
          <div className="text-xs text-rose-400 bg-rose-950/40 border border-rose-800 rounded p-2">
            {errorMessage}
          </div>
        )}
        {statusMessage && (
          <div className="text-xs text-emerald-400 bg-emerald-950/40 border border-emerald-800 rounded p-2">
            {statusMessage}
          </div>
        )}
        <button
          type="submit"
          className="w-full py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-sm font-medium text-white transition-colors"
        >
          Sign In
        </button>
      </form>
    </div>
  );
}
