"use client";

import Nav from "@/components/nav";
import Waitlist from "@/components/waitlist";

const ACCENT = "#EF4444";
const HUB_URL = "https://specialized-model-startups.vercel.app";


function SectionLabel({ label }: { label: string }) {
  return (
    <div className="reveal flex items-center gap-5 mb-12">
      <span className="text-xs font-semibold uppercase tracking-[0.18em] text-gray-400 shrink-0">{label}</span>
      <div className="flex-1 h-px bg-gray-100" />
    </div>
  );
}

export default function Home() {
  return (
    <div className="min-h-screen bg-white text-[#0a0a0a] overflow-x-hidden">
      <Nav />

      {/* Hero */}
      <section className="relative min-h-screen flex flex-col justify-center px-6 pt-14 overflow-hidden">
        <div
          className="absolute inset-0 pointer-events-none"
          style={{
            backgroundImage: `radial-gradient(circle at 20% 30%, ${ACCENT}07 0%, transparent 50%), radial-gradient(circle at 80% 70%, ${ACCENT}05 0%, transparent 50%)`,
          }}
        />

        <div className="relative max-w-5xl mx-auto w-full py-20">
          <div className="fade-up delay-0 mb-8">
            <span
              className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full text-xs font-semibold border"
              style={{ color: ACCENT, borderColor: `${ACCENT}30`, backgroundColor: `${ACCENT}08` }}
            >
              <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ backgroundColor: ACCENT }} />
              Training &middot; 18&times; A6000 &middot; ETA Q3 2026
            </span>
          </div>

          <h1 className="fade-up delay-1 text-[clamp(3.5rem,10vw,7rem)] font-bold leading-[0.92] tracking-tight mb-6">
            <span className="serif font-light italic" style={{ color: ACCENT }}>Seal</span>
            <span>Patch</span>
          </h1>

          <p className="fade-up delay-2 serif text-[clamp(1.25rem,3vw,2rem)] font-light text-gray-500 mb-4 max-w-xl">
            Scanners report. SealPatch removes.
          </p>

          <p className="fade-up delay-3 text-sm text-gray-400 leading-relaxed max-w-lg mb-10">
            First model trained on CVE-fix pairs with CI validation&nbsp;— understands that base image upgrades break app behavior, lockfile pins cascade, and some CVEs in dev layers don&apos;t matter.
          </p>

          <div className="fade-up delay-4">
            <Waitlist />
          </div>
        </div>
      </section>

      {/* The Problem */}
      <section className="px-6 py-24 max-w-5xl mx-auto">
        <SectionLabel label="The Problem" />
        <div className="grid md:grid-cols-2 gap-6">
          <div className="reveal rounded-2xl border border-gray-100 p-8 bg-gray-50/50">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-400 mb-5">What general tools do</p>
            <ul className="space-y-3 text-sm text-gray-500 leading-relaxed">
              <li className="flex gap-3">
                <span className="text-gray-300 mt-0.5">&#8212;</span>
                Scanners (Snyk, Trivy) find CVEs — engineers do the work
              </li>
              <li className="flex gap-3">
                <span className="text-gray-300 mt-0.5">&#8212;</span>
                Backlogs grow to 500+ CVEs and never shrink
              </li>
              <li className="flex gap-3">
                <span className="text-gray-300 mt-0.5">&#8212;</span>
                Base image upgrades break app behavior silently
              </li>
              <li className="flex gap-3">
                <span className="text-gray-300 mt-0.5">&#8212;</span>
                No understanding of which CVEs in dev layers actually matter
              </li>
            </ul>
          </div>

          <div
            className="reveal rounded-2xl border p-8"
            style={{ borderColor: `${ACCENT}25`, backgroundColor: `${ACCENT}05` }}
          >
            <p className="text-xs font-semibold uppercase tracking-widest mb-5" style={{ color: ACCENT }}>What SealPatch does</p>
            <ul className="space-y-3 text-sm leading-relaxed text-gray-700">
              <li className="flex gap-3">
                <svg className="mt-0.5 shrink-0" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={ACCENT} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                Opens minimal PRs pre-validated against your CI pipeline
              </li>
              <li className="flex gap-3">
                <svg className="mt-0.5 shrink-0" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={ACCENT} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                CVEs disappear from your backlog permanently — not deferred
              </li>
              <li className="flex gap-3">
                <svg className="mt-0.5 shrink-0" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={ACCENT} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                Preserves runtime behavior via smoke test validation
              </li>
              <li className="flex gap-3">
                <svg className="mt-0.5 shrink-0" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={ACCENT} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                Understands lockfile cascades and resolves them correctly
              </li>
            </ul>
          </div>
        </div>
      </section>

      {/* How it works */}
      <section className="px-6 py-24 bg-gray-50/50">
        <div className="max-w-5xl mx-auto">
          <SectionLabel label="How it works" />
          <div className="grid md:grid-cols-3 gap-6">
            {[
              {
                step: "01",
                title: "Supervised Fine-Tuning",
                desc: "300k (Dockerfile, CVE scan, remediation PR) triples from real open source repositories. Each triple is verified: CVEs eliminated, CI green, smoke tests unchanged. SealPatch learns what makes a patch safe.",
              },
              {
                step: "02",
                title: "RL with Verifiable Reward",
                desc: "Triple reward: CVEs eliminated from scan + test suite passes + smoke tests unchanged. All three are automatic. SealPatch is penalized for breaking tests even if CVE count drops — safety is non-negotiable.",
              },
              {
                step: "03",
                title: "DPO Alignment",
                desc: "Direct Preference Optimization on (safe patch, breaking patch) pairs. SealPatch learns to prefer stage-pinned base images over full upgrades, and targeted lockfile pins over dep removal.",
              },
            ].map(({ step, title, desc }) => {
              return (
                <div key={step} className="reveal-scale rounded-2xl border border-gray-100 bg-white p-8">
                  <div className="text-xs font-bold uppercase tracking-widest mb-4" style={{ color: ACCENT }}>{step}</div>
                  <h3 className="serif font-semibold text-lg mb-3 text-gray-900">{title}</h3>
                  <p className="text-sm text-gray-500 leading-relaxed">{desc}</p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Capabilities */}
      <section className="px-6 py-24 max-w-5xl mx-auto">
        <SectionLabel label="Capabilities" />
        <div className="grid sm:grid-cols-2 gap-5">
          {[
            {
              icon: (
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke={ACCENT} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07A19.5 19.5 0 0 1 4.69 12 19.79 19.79 0 0 1 1.61 3.38 2 2 0 0 1 3.6 1.18h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L7.91 8.8a16 16 0 0 0 6.29 6.29l.9-.9a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/>
                </svg>
              ),
              title: "Multi-stage Dockerfile optimization",
              desc: "Reduces images from 2GB to 45MB and 240 CVEs to 0 through multi-stage builds, minimal base selection, and layer consolidation — while keeping the app running.",
            },
            {
              icon: (
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke={ACCENT} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/>
                </svg>
              ),
              title: "Lockfile remediation",
              desc: "Resolves CVEs in package lockfiles without breaking the dependency graph. SealPatch understands which transitive dependencies block resolution and pins them precisely.",
            },
            {
              icon: (
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke={ACCENT} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
                </svg>
              ),
              title: "Runtime behavior preservation",
              desc: "Every patch is validated against smoke tests before the PR opens. SealPatch won&apos;t merge a fix that breaks app startup, health checks, or core request paths.",
            },
            {
              icon: (
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke={ACCENT} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="18" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><path d="M13 6h3a2 2 0 0 1 2 2v7"/><line x1="6" y1="9" x2="6" y2="21"/>
                </svg>
              ),
              title: "PR-based audit workflow",
              desc: "Audit &rarr; Patch &rarr; Verify &rarr; Open PR. SealPatch integrates with your existing GitHub workflow — no new tools, no agent sidecars, just a PR you can review and merge.",
            },
          ].map(({ icon, title, desc }) => {
            return (
              <div
                key={title}
               
                className="reveal rounded-2xl border border-gray-100 p-7 flex gap-5 hover:border-gray-200 transition-colors"
              >
                <div
                  className="shrink-0 w-10 h-10 rounded-xl flex items-center justify-center"
                  style={{ backgroundColor: `${ACCENT}10` }}
                >
                  {icon}
                </div>
                <div>
                  <h3 className="font-semibold text-sm text-gray-900 mb-1.5">{title}</h3>
                  <p className="text-sm text-gray-500 leading-relaxed">{desc}</p>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* The numbers */}
      <section className="px-6 py-24 bg-gray-50/50">
        <div className="max-w-5xl mx-auto">
          <SectionLabel label="The numbers" />
          <div className="grid sm:grid-cols-3 gap-6">
            {[
              { stat: "300k", label: "Training triples", sub: "Dockerfile + CVE scan + fix PR" },
              { stat: "Qwen2.5-7B", label: "Base model", sub: "Coder-Instruct" },
              { stat: "CVEs + Tests", label: "Reward signal", sub: "Eliminated + CI pass + smoke stable" },
            ].map(({ stat, label, sub }) => {
              return (
                <div
                  key={label}
                 
                  className="reveal rounded-2xl border p-8"
                  style={{ borderColor: `${ACCENT}20` }}
                >
                  <div className="text-3xl font-bold tracking-tight mb-2" style={{ color: ACCENT }}>{stat}</div>
                  <div className="text-sm font-semibold text-gray-800 mb-1">{label}</div>
                  <div className="text-xs text-gray-400">{sub}</div>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="px-6 py-12 border-t border-gray-100">
        <div className="max-w-5xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 text-sm text-gray-400">
          <p>
            Part of the{" "}
            <a href={HUB_URL} className="underline underline-offset-2 hover:text-gray-600 transition-colors">
              Specialist AI
            </a>{" "}
            portfolio by{" "}
            <a
              href="https://github.com/calebnewtonusc"
              target="_blank"
              rel="noopener noreferrer"
              className="underline underline-offset-2 hover:text-gray-600 transition-colors"
            >
              Caleb Newton &middot; calebnewtonusc
            </a>{" "}
            &middot; 2026
          </p>
        </div>
      </footer>
    </div>
  );
}
