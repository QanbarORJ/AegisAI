import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "AegisAI — Enterprise AI Application Security Assessment Platform",
  description:
    "Modular security assessment and red teaming platform for LLMs, RAG pipelines, and Autonomous AI Agents.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
        <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur">
          <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="h-8 w-8 rounded bg-emerald-500/10 border border-emerald-500/40 flex items-center justify-center font-mono font-bold text-emerald-400">
                A
              </div>
              <div>
                <Link href="/" className="font-semibold tracking-tight text-slate-100">
                  AegisAI
                </Link>
                <span className="ml-2 text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                  v0.2.0
                </span>
              </div>
            </div>
            <nav className="flex items-center gap-6 text-sm text-slate-300">
              <Link href="/" className="hover:text-emerald-400 transition-colors">
                Posture Dashboard
              </Link>
              <Link href="/login" className="hover:text-emerald-400 transition-colors">
                Tenant Auth
              </Link>
            </nav>
          </div>
        </header>
        <main className="flex-1 max-w-7xl w-full mx-auto px-6 py-8">
          {children}
        </main>
      </body>
    </html>
  );
}
