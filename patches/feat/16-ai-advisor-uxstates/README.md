# FEAT-17 — AI Advisor Panel UX States (Sprint 13 — Quick Win batch)

AI-powered remediation advisor panel. No mock — UX upgrade.

Wires VSPUXState into getAdvice() (user-triggered AI advice request):
- #result loading: VSPUXState.skeleton (was inline spinner div)
- #result error: VSPUXState.error + retry (was inline red div)

loadMode + loadStats unchanged (KPI text updates, skeleton not applicable).

Defensive: typeof VSPUXState guard with else fallback to original divs.
