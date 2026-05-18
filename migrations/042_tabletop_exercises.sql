-- 042_tabletop_exercises.sql — incident-response tabletop exercise log.
--
-- DSOMM L4 expects evidence that the IR team practises responding to
-- incidents on a regular cadence, not just that runbooks exist on
-- paper. This table records each tabletop run: what scenario was
-- played, who participated, what the team learned, and what action
-- items came out.
--
-- An auditor can answer "when did you last practise ransomware
-- response?" with one query against this table — the artefact every
-- DSOMM 4.0 / FedRAMP RA-5 review wants.

CREATE TABLE IF NOT EXISTS tabletop_exercises (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  -- Scenario family — keeps reporting groupable. Free text otherwise
  -- so teams can play scenarios specific to their threat model.
  scenario_kind   TEXT NOT NULL CHECK (scenario_kind IN (
    'ransomware','data_breach','insider_threat','ddos','supply_chain',
    'phishing','cloud_account_takeover','third_party_outage','generic'
  )),
  title           TEXT NOT NULL,
  -- One-paragraph injects given to the team. Stored verbatim so a
  -- repeat run can be compared against the same scenario card.
  scenario_text   TEXT NOT NULL,
  -- Conducted_at = when the exercise was held. Decoupled from
  -- created_at so a write-up can be added after the fact.
  conducted_at    TIMESTAMPTZ NOT NULL,
  duration_min    INT NOT NULL DEFAULT 0 CHECK (duration_min >= 0),
  -- Comma-separated email list — keeps cardinality in one row rather
  -- than a junction table; we never query "exercises where alice
  -- participated" so the simpler shape pays off.
  participants    TEXT NOT NULL DEFAULT '',
  facilitator     TEXT NOT NULL DEFAULT '',
  -- Free-text deliverables of the exercise. Auditor reads these as
  -- the proof that practising actually produces improvements.
  observations    TEXT NOT NULL DEFAULT '',
  action_items    JSONB NOT NULL DEFAULT '[]'::jsonb,
  -- Whether the team self-rated the exercise as a pass. Subjective
  -- but useful trend data over time.
  rating          TEXT NOT NULL DEFAULT 'pass'
                    CHECK (rating IN ('pass','partial','fail','not_rated')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tabletop_tenant_when
  ON tabletop_exercises(tenant_id, conducted_at DESC);
CREATE INDEX IF NOT EXISTS idx_tabletop_scenario
  ON tabletop_exercises(tenant_id, scenario_kind, conducted_at DESC);
