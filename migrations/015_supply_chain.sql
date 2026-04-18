-- Migration 015: Supply Chain Integrity (Sigstore/SLSA/VEX)
-- References: NIST SP 800-218 PS, SLSA Framework, CISA Secure by Design

-- ═══ Artifact signatures (Cosign-compatible format) ═══
CREATE TABLE IF NOT EXISTS supply_chain_signatures (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    artifact_name TEXT NOT NULL,           -- e.g. "vsp-gateway:v1.0.0"
    artifact_digest TEXT NOT NULL,          -- sha256:abc...
    signature_bytes BYTEA NOT NULL,          -- raw signature
    signature_b64 TEXT NOT NULL,             -- base64 for transport
    public_key_pem TEXT NOT NULL,            -- signer's public key
    cert_pem TEXT,                            -- X.509 cert (optional)
    bundle_json JSONB NOT NULL,              -- full Cosign-style bundle
    signed_by TEXT NOT NULL,                 -- user/service identity
    signed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    algorithm TEXT NOT NULL DEFAULT 'ECDSA_P256_SHA256',
    verified BOOL NOT NULL DEFAULT false,
    verified_at TIMESTAMPTZ,
    tlog_index BIGINT,                       -- Rekor transparency log index (future)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scs_artifact ON supply_chain_signatures(artifact_name, artifact_digest);
CREATE INDEX IF NOT EXISTS idx_scs_tenant ON supply_chain_signatures(tenant_id);
CREATE INDEX IF NOT EXISTS idx_scs_signed_at ON supply_chain_signatures(signed_at DESC);

-- ═══ SLSA Provenance attestations (in-toto format) ═══
CREATE TABLE IF NOT EXISTS slsa_provenance (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    artifact_name TEXT NOT NULL,
    artifact_digest TEXT NOT NULL,
    slsa_level INT NOT NULL CHECK (slsa_level >= 1 AND slsa_level <= 4),
    builder_id TEXT NOT NULL,                -- e.g. "vsp-gateway-builder"
    build_type TEXT NOT NULL,                -- e.g. "github.com/slsa-framework/slsa-github-generator"
    source_uri TEXT,                          -- git repo URL
    source_commit TEXT,                       -- commit SHA
    invocation_json JSONB NOT NULL,          -- build invocation details
    materials_json JSONB NOT NULL,           -- dependencies
    metadata_json JSONB NOT NULL,            -- timestamps, reproducible flag
    statement_json JSONB NOT NULL,           -- full in-toto statement
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_slsa_artifact ON slsa_provenance(artifact_name, artifact_digest);
CREATE INDEX IF NOT EXISTS idx_slsa_tenant ON slsa_provenance(tenant_id);

-- ═══ VEX statements (CycloneDX VEX format) ═══
CREATE TABLE IF NOT EXISTS vex_statements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    product_name TEXT NOT NULL,               -- e.g. "vsp-gateway"
    product_version TEXT NOT NULL,
    component_name TEXT NOT NULL,             -- e.g. "libexpat"
    component_version TEXT,
    cve_id TEXT,                              -- CVE-2024-XXXXX
    vuln_ref TEXT,                            -- reference URL
    -- CycloneDX VEX status values
    status TEXT NOT NULL CHECK (status IN (
        'affected', 'not_affected', 'fixed', 
        'under_investigation', 'exploitable', 'not_exploitable'
    )),
    justification TEXT CHECK (justification IN (
        'code_not_present', 'code_not_reachable',
        'requires_configuration', 'requires_dependency',
        'requires_environment', 'protected_by_compiler',
        'protected_at_runtime', 'protected_at_perimeter',
        'protected_by_mitigating_control', ''
    ) OR justification IS NULL),
    impact_statement TEXT,
    response_actions TEXT[],                  -- e.g. ['will_not_fix', 'update']
    detail TEXT,
    statement_json JSONB NOT NULL,           -- full CycloneDX VEX JSON
    analysis_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    author TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vex_product ON vex_statements(product_name, product_version);
CREATE INDEX IF NOT EXISTS idx_vex_cve ON vex_statements(cve_id);
CREATE INDEX IF NOT EXISTS idx_vex_status ON vex_statements(status);

-- ═══ Seed initial signing keypair metadata (actual keys generated on first run) ═══
CREATE TABLE IF NOT EXISTS signing_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id TEXT UNIQUE NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'ECDSA_P256',
    public_key_pem TEXT NOT NULL,
    private_key_pem TEXT,                    -- NULL if external key
    usage TEXT NOT NULL DEFAULT 'artifact_signing',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    revoked BOOL NOT NULL DEFAULT false,
    revoked_at TIMESTAMPTZ
);

COMMENT ON TABLE supply_chain_signatures IS 'Artifact signatures in Cosign-compatible format. Ref: Sigstore, NIST SP 800-218 PS';
COMMENT ON TABLE slsa_provenance IS 'SLSA build provenance in in-toto Statement format. Ref: SLSA Level 1-4 Framework';
COMMENT ON TABLE vex_statements IS 'Vulnerability Exploitability eXchange statements. Ref: CycloneDX VEX 1.4, CISA VEX Minimum Requirements';
