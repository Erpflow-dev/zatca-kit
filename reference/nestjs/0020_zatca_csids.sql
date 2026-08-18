-- ============================================================================
-- Migration 0020 — ZATCA CSID onboarding lifecycle (docs/10 onboarding chain).
-- Compliance CSID → compliance checks → production CSID → renewal, per
-- tenant and per environment (the three Fatoora environments are fully
-- independent — a sandbox CSID is useless in simulation/production, so
-- environment is part of every lookup).
--
-- CONTRACT:
--   * zatca_csids is the APPEND-ONLY issuance log: one row per CSID the
--     onboarding flow ever obtained (compliance and production alike,
--     renewals included). "Current" = newest ISSUED row per (environment,
--     kind). No update/delete grants — a renewal or re-onboarding INSERTS.
--   * zatca_credentials (0004) stays the reporting worker's read path
--     (`select cert, secret from zatca_credentials`). The onboarding
--     service mirrors the newest ISSUED PRODUCTION token/secret into it,
--     so the worker keeps working untouched.
--   * disposition is stored verbatim from dispositionMessage ('ISSUED',
--     'NOT_COMPLIANT', …). The NOT_COMPLIANT gate arrives with HTTP 200,
--     so the service branches on this value, never on status codes.
--   * expires_at is parsed from the CSID certificate when possible (the
--     binarySecurityToken decodes to the X509); nullable because parsing
--     a sandbox token may fail — the fleet view treats null as unknown.
-- ============================================================================

create table zatca_csids (
  tenant_id             uuid not null references tenants(id),
  id                    uuid not null default gen_random_uuid(),
  environment           text not null default 'sandbox', -- sandbox|simulation|production
  kind                  text not null check (kind in ('compliance', 'production')),
  binary_security_token text not null,   -- the CSID; Basic username VERBATIM (already base64)
  secret                text not null,
  request_id            text,            -- /compliance requestID = step-2 compliance_request_id
  disposition           text not null,   -- dispositionMessage verbatim
  expires_at            timestamptz,     -- cert notAfter; null = could not parse
  created_at            timestamptz not null default now(),
  primary key (id),
  unique (tenant_id, id)
);

-- "Newest per (environment, kind)" is the only read pattern.
create index zatca_csids_lookup_idx
  on zatca_csids (tenant_id, environment, kind, created_at desc);

alter table zatca_csids enable row level security;
alter table zatca_csids force row level security;
create policy tenant_isolation on zatca_csids
  using (tenant_id = current_tenant_id())
  with check (tenant_id = current_tenant_id());
-- Append-only on purpose: issuance history is audit material, like sales.
grant select, insert on zatca_csids to pos_app;
