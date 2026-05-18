# FEAT-19 — DEFERRED

Sprint 15 sw_inventory deferred from Phase Quick Win.

## Why
sw_inventory uses MOCK_* arrays as PRIMARY data source (not fallback):
- 7 MOCK_* arrays (INVENTORY, WHITELIST, BLACKLIST, WARNING, CRACKS, LICENSE, SCAN_HISTORY)
- 6 used as client-side state, mutated by removeFromList() and addToList()
- Backend endpoints exist (/api/v1/sw/*) but not called by frontend yet

Strip-mock + UX-states pattern (used FEAT-01..18) doesn't apply — would
break panel functionality.

## Required for full L2
- Wire 6 backend endpoints: whitelist/blacklist/warning/cracks/license/scan_history
- Convert client-side mutations to API POST/DELETE
- Then apply VSPUXState pattern to all 7 loaders

Estimated effort: 1-2 days (backend integration + UX states).
Recommend: Phase B+ scope, dedicated sprint.

## Status
Sprint 15 closed without code change.
sw_inventory remains at L1 (works, mock data).
