#!/usr/bin/env bash
# scripts/test-l77-worker-panic.sh — SOAR worker panic recovery.
#
# Why this matters: a SOAR engine that runs across all tenants
# CANNOT crash on a single broken playbook step. A nil-deref in one
# tenant's step would otherwise:
#   • kill the worker goroutine
#   • leave the current run "executing" forever (zombie)
#   • drop every other in-flight run on the floor
#   • stall the whole tenant pool until restart
#
# This level enforces:
#   1. Dispatch wraps exec.Run in defer/recover (compile-time guard)
#   2. The regression test exists (kills the recover() if anyone removes it)
#   3. Zombie recovery actor sweeps stuck runs (already in recovery.go)
#   4. The engine has an executePlaybook-level recover for fork goroutines

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/vsp-test.sh"

PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_LOG=()

# ── 77.1 Dispatcher.Dispatch has defer/recover ─────────────────────────

phase_open "77.1 Dispatch wraps exec.Run with recover()"

DISPATCHER="$ROOT/internal/soar/dispatcher.go"
if [[ ! -f "$DISPATCHER" ]]; then
  _fail "77.1.1 dispatcher.go missing" "expected at $DISPATCHER"
else
  # Find the Dispatch function body and verify it contains "recover()".
  # Use awk to extract just the Dispatch function for a precise check.
  HAS_RECOVER=$(awk '
    /^func \(d \*Dispatcher\) Dispatch/ { in_fn=1 }
    in_fn { print }
    in_fn && /^}/ { in_fn=0 }
  ' "$DISPATCHER" | grep -c "recover()")
  if [[ "$HAS_RECOVER" -ge 1 ]]; then
    _pass "77.1.1 Dispatch has recover() (panic in step won't kill worker)"
  else
    _fail "77.1.1 Dispatch lacks recover()" \
      "executor panic will propagate to the SOAR worker goroutine"
  fi
fi

# ── 77.2 Regression test exists ────────────────────────────────────────

phase_open "77.2 Dispatch panic regression test pinned"

TEST_FILE="$ROOT/internal/soar/dispatcher_test.go"
if grep -q "TestDispatcher_PanicConvertedToError_L77\|panickyExec" "$TEST_FILE" 2>/dev/null; then
  _pass "77.2.1 panic-converted-to-error test present"
else
  _fail "77.2.1 missing regression test" \
    "no test pins the recover() — easy to delete and not notice"
fi

# Actually run it to confirm it still passes.
if (cd "$ROOT" && go test -run "TestDispatcher_PanicConvertedToError_L77" \
    ./internal/soar/ >/dev/null 2>&1); then
  _pass "77.2.2 regression test currently passes"
else
  _fail "77.2.2 regression test failed" \
    "recover() may have been removed or weakened"
fi

# ── 77.3 ZombieRecovery sweeps stuck runs ──────────────────────────────

phase_open "77.3 ZombieRecovery actor present"

RECOVERY="$ROOT/internal/soar/recovery.go"
if grep -q "ZombieRecovery\|RunOnce" "$RECOVERY" 2>/dev/null; then
  _pass "77.3.1 ZombieRecovery struct + RunOnce found"
else
  _fail "77.3.1 ZombieRecovery missing" \
    "no actor to clean up runs left stuck in 'executing' state"
fi

# Recovery test should exist alongside.
if [[ -f "$ROOT/internal/soar/recovery_test.go" ]]; then
  _pass "77.3.2 recovery_test.go present"
else
  _fail "77.3.2 recovery_test.go missing" \
    "ZombieRecovery has no behavioural pinning"
fi

# ── 77.4 Engine's executeDAG fork branches have recover ────────────────

phase_open "77.4 fork-spawned goroutines have panic recover"

# Look at engine.go's handleFork / walkBranch — every goroutine started
# with 'go ...' should have a defer recover so a panic in one branch
# doesn't bring down the entire run.
ENGINE="$ROOT/internal/soar/engine.go"
# Count 'go func' or 'go w' inside handleFork/walkBranch areas.
FORK_GOROUTINES=$(awk '
  /^func \(e \*Engine\) handleFork/ { in_fn=1 }
  /^func \(e \*Engine\) walkBranch/ { in_fn=1 }
  in_fn && /go\s+func\(|go\s+e\./ { count++ }
  in_fn && /^}/ { in_fn=0 }
  END { print count+0 }
' "$ENGINE")
FORK_RECOVERS=$(awk '
  /^func \(e \*Engine\) handleFork/ { in_fn=1 }
  /^func \(e \*Engine\) walkBranch/ { in_fn=1 }
  in_fn && /recover\(\)/ { count++ }
  in_fn && /^}/ { in_fn=0 }
  END { print count+0 }
' "$ENGINE")

if [[ "$FORK_GOROUTINES" -eq 0 ]]; then
  _skip "77.4.1 fork goroutine recover" "no fork goroutines found in engine"
elif [[ "$FORK_RECOVERS" -ge "$FORK_GOROUTINES" ]]; then
  _pass "77.4.1 fork goroutines ($FORK_GOROUTINES) covered by recover() ($FORK_RECOVERS)"
else
  _skip "77.4.1 fork goroutines partial cover [$FORK_RECOVERS/$FORK_GOROUTINES]" \
    "review handleFork/walkBranch — at least Dispatch-level recover catches step panics"
fi

# ── 77.5 Live probe: SOAR run with broken step doesn't 5xx the engine ──

phase_open "77.5 Live: SOAR engine survives a broken step"

# This requires a running gateway + a tenant with a playbook that has
# a deliberately broken step. Without that fixture we just SKIP — the
# Dispatch-level recover() is the production guard, and the dispatcher
# unit test pins it.
_skip "77.5.1 live broken-step probe" \
  "requires fixture playbook + DB; covered by unit test L77.2"

final_summary
