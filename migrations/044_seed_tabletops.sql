-- 044_seed_tabletops.sql — seed 4 realistic tabletop scenario CARDS
-- (not actual conducted exercises) so the security team has ready-made
-- scenarios to run rather than starting from scratch.
--
-- IMPORTANT: this migration seeds *scenarios with conducted_at = NULL*.
-- An auditor seeing rows where rating = 'not_rated' and observations is
-- empty will correctly understand "this is a planned scenario, not yet
-- executed". Once the team runs the exercise, an admin updates the row
-- via POST /api/v1/tabletop/exercises/{id}.
--
-- Why we do this: starting from a blank registry makes the team
-- procrastinate. Pre-loaded cards lower the friction to "just run one"
-- and demonstrate to a 3PAO that the team has thought about scenarios
-- relevant to their threat model.

-- We seed under the default tenant. If multi-tenant production needs
-- per-tenant seeds, the security team duplicates these via the API.
DO $$
DECLARE
  default_tenant UUID;
BEGIN
  SELECT id INTO default_tenant FROM tenants
   WHERE slug IN ('default','vsp','main') ORDER BY created_at LIMIT 1;
  IF default_tenant IS NULL THEN
    RAISE NOTICE 'no default tenant found; skipping tabletop seed';
    RETURN;
  END IF;

  -- Idempotency — only seed if the tenant has zero tabletop rows yet.
  IF EXISTS (SELECT 1 FROM tabletop_exercises WHERE tenant_id = default_tenant) THEN
    RAISE NOTICE 'tenant % already has tabletop rows; skipping seed', default_tenant;
    RETURN;
  END IF;

  INSERT INTO tabletop_exercises
    (tenant_id, scenario_kind, title, scenario_text, conducted_at,
     duration_min, participants, facilitator, observations,
     action_items, rating)
  VALUES
  -- 1. Ransomware
  (default_tenant, 'ransomware',
   'Ransomware: Postgres encrypted, ransom demand received',
   E'INJECT 1: At 03:14 UTC, postgres-primary returns "could not open file" errors. SOC alerts on auth_log shows zero recent successful logins. Application traffic is failing.\n\n' ||
   E'INJECT 2: 30 min later, an email arrives at security@vsp.vn from "kraken-team@protonmail.com" demanding 50 BTC in 72h, with a screenshot proving they have customer data.\n\n' ||
   E'INJECT 3: Customer calls reporting service is down.\n\n' ||
   E'OBJECTIVES: Decide containment (isolate vs. wipe-and-restore), legal coordination (CISA reporting, law enforcement), customer communication, payment policy, evidence preservation.',
   NULL, 90,
   'soc-team@vsp.vn, eng-leads@vsp.vn, ciso@vsp.vn, legal@vsp.vn, ceo@vsp.vn',
   '_to be assigned_',
   '',
   '[]'::jsonb,
   'not_rated'),

  -- 2. Data breach via DSAR abuse
  (default_tenant, 'data_breach',
   'Data breach: stolen admin token enables DSAR-driven exfiltration',
   E'INJECT 1: GitHub Security Advisory shows a contributor''s laptop was compromised; their VSP admin token was on it.\n\n' ||
   E'INJECT 2: audit_log shows 47 DSR data export requests in the last 6 hours from that admin''s account, all for the largest 47 customer tenants.\n\n' ||
   E'INJECT 3: One customer reports a phishing call referencing their internal project names (consistent with data exfiltrated via /api/v1/data/export).\n\n' ||
   E'OBJECTIVES: Token revocation cadence (have we?), determining scope of breach, GDPR Art.33 / 34 notification deadlines (72h), Decree 13/2023 reporting, customer notification, root-cause investigation.',
   NULL, 90,
   'soc-team@vsp.vn, eng-leads@vsp.vn, ciso@vsp.vn, legal@vsp.vn, dpo@vsp.vn',
   '_to be assigned_',
   '',
   '[]'::jsonb,
   'not_rated'),

  -- 3. Supply chain compromise
  (default_tenant, 'supply_chain',
   'Supply chain: compromised dependency in nightly build',
   E'INJECT 1: OSV.dev publishes a critical CVE for github.com/some-popular-go-lib v3.2.4 — backdoor inserted by a maintainer transfer attack.\n\n' ||
   E'INJECT 2: govulncheck output flags this exact version in our go.sum from last week''s release.\n\n' ||
   E'INJECT 3: trivy on running containers confirms the affected version is deployed across all 17 microservices.\n\n' ||
   E'OBJECTIVES: Triage scope (were the call sites actually exploitable?), customer notification policy (FedRAMP says yes-of-course; our SLA?), rollback vs. forward-fix decision, SBOM / VEX update workflow, communication via /trust/ Trust Center transparency report.',
   NULL, 90,
   'eng-leads@vsp.vn, ciso@vsp.vn, supply-chain-team@vsp.vn',
   '_to be assigned_',
   '',
   '[]'::jsonb,
   'not_rated'),

  -- 4. Cloud account takeover
  (default_tenant, 'cloud_account_takeover',
   'Cloud takeover: compromised CI runner pivots to AWS prod',
   E'INJECT 1: AWS CloudTrail flags 47 GetSecretValue calls in 5 min from a runner IAM role normally idle outside CI windows.\n\n' ||
   E'INJECT 2: GitHub audit log shows the affected runner''s OIDC token was issued to a suspicious commit on a feature branch.\n\n' ||
   E'INJECT 3: Vault audit log shows attempts to read the JWT signing key — denied because the runner''s OIDC sub claim doesn''t match the policy.\n\n' ||
   E'OBJECTIVES: Did Vault save us (yes, this time)? IAM role reduction. Branch protection (was the suspicious commit reviewable?). Secrets rotation (Vault rotator caught this one — does it run quarterly minimum?). Lesson-feedback into IAM-by-default-deny policy.',
   NULL, 90,
   'eng-leads@vsp.vn, ciso@vsp.vn, devops@vsp.vn, cloud-architect@vsp.vn',
   '_to be assigned_',
   '',
   '[]'::jsonb,
   'not_rated');

  RAISE NOTICE 'Seeded 4 tabletop scenarios for tenant %', default_tenant;
END$$;
