# FEAT-12 — Software Risk Panel UX States (Sprint 8 — Phase B continued)

## What
Seventh panel using FEAT-04 shared VSPUXState module.

No mock data to strip. STATIC_EOL is legitimate End-of-Life reference data
(19 entries: Windows XP, Office 2010, Internet Explorer, Adobe Flash,
PHP 7.4, Node.js 16, Python 2, MySQL 5.7, OpenSSL 1.1, plus VN-specific
MISA SME.NET / Fast Accounting / BKAV) from endoflife.date and manual
sources. Same pattern as DEFAULT_ROLES (Users), MITRE (Threat Intel),
CHECKS (UEBA) — config not mock.

## Changes
loadData() rewritten:
- Skeleton on entry across 4 query selectors (defensive — only set if element exists)
- Empty state if _assets.length === 0 ("No software assets discovered")
- Error state in catch (was silent console.error)
- Defensive: typeof VSPUXState guard via hasUX var
- console.error preserved for debugging visibility

## Why
Original loadData() catch was `console.error(e)` only — user saw nothing on
network failure. Fetch errors silently swallowed.

## Apply
bash patches/feat/11-software-risk-uxstates/apply.sh

## Rollback
bash patches/feat/11-software-risk-uxstates/rollback.sh

## Verified
- 1111 -> ~1130 lines
- 1 patch step success
- STATIC_EOL preserved (legitimate reference)
- 5 VSPUXState integration points
