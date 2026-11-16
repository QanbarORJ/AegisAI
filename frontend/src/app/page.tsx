import Link from "next/link";

export default function HomePage() {
  return (
    <div className="space-y-8">
      <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-6">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <span className="text-xs font-mono uppercase tracking-wider text-emerald-400">
              Platform Security Foundation Active
            </span>
            <h1 className="text-2xl font-bold tracking-tight text-slate-100 mt-1">
              AegisAI Security Posture & Assessment Console
            </h1>
            <p className="text-sm text-slate-400 mt-1 max-w-2xl">
              Deterministic and hybrid security assessment for Large Language Models (Module A),
              Retrieval-Augmented Generation Pipelines (Module B), and Autonomous AI Agents (Module C).
            </p>
          </div>
          <div className="flex items-center gap-3">
            <Link
              href="/login"
              className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-sm font-medium text-white transition-colors"
            >
              Tenant Sign In
            </Link>
          </div>
        </div>
      </section>

      <section className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5">
          <div className="text-xs font-mono text-slate-400 uppercase">SSRF Boundary Guard</div>
          <div className="text-lg font-semibold text-slate-100 mt-1">
            Pre-Connect DNS & IP Validation
          </div>
          <p className="text-xs text-slate-400 mt-2">
            Blocks RFC 1918 private networks, loopback, CGNAT, and cloud metadata services
            (169.254.169.254) prior to socket connection.
          </p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5">
          <div className="text-xs font-mono text-slate-400 uppercase">Credential Vault</div>
          <div className="text-lg font-semibold text-slate-100 mt-1">
            AES-256-GCM + HKDF-SHA256
          </div>
          <p className="text-xs text-slate-400 mt-2">
            Target API credentials are encrypted at rest with tenant organization_id bound as
            Associated Authenticated Data (AAD).
          </p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5">
          <div className="text-xs font-mono text-slate-400 uppercase">Multi-Tenant RBAC</div>
          <div className="text-lg font-semibold text-slate-100 mt-1">
            Strict Tenant & Role Isolation
          </div>
          <p className="text-xs text-slate-400 mt-2">
            Enforces ORG_ADMIN, SECURITY_ENGINEER, and VIEWER permissions with immutable,
            secret-redacted audit logging.
          </p>
        </div>
      </section>
    </div>
  );
}
