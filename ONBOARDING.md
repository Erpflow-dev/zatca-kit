# ZATCA Onboarding Runbook — agent-executable

Written for an AI agent (Claude Code / Codex) driving onboarding WITH a
human who has Fatoora-portal access. Every step names its actor, exact
call, success signal, and the failure modes we hit for real (2026-08-18,
when this exact procedure completed simulation onboarding end to end).

Contract reference: `docs/10-zatca-developer-portal.md`. Reusable code:
the `zatca-kit` repo (CSR, QR, XAdES, API client — all tested).

## The three environments

| env | base URL suffix | template | OTP source |
|---|---|---|---|
| sandbox | `/developer-portal` | `TSTZATCA-Code-Signing` | magic: `123345` valid / `111111` invalid / `222222` expired |
| simulation | `/simulation` | `PREZATCA-Code-Signing` | Fatoora **Simulation** Portal |
| production | `/core` | `ZATCA-Code-Signing` | Fatoora Portal (real) |

Base: `https://gw-fatoora.zatca.gov.sa/e-invoicing` + suffix. CSIDs are
environment-exclusive — never reuse across environments.

## Route A — server-level onboarding (tenant credentials)

Use for: the tenant's reporting credentials, or rehearsal. This is the
exact chain that completed simulation onboarding.

1. **HUMAN**: log into `https://fatoora.zatca.gov.sa` (ERAD credentials)
   → (simulation only: click "Fatoora Simulation Portal", accept the
   test-environment terms) → "Onboard New Solution Unit/Device" →
   solve the reCAPTCHA (agents must NOT) → generate **1** OTP.
   OTP is valid **60 minutes** and is consumed by step 3 only — after
   that there is no time pressure.
2. **AGENT**: generate keypair + CSR with `zatca-kit`:
   `generateCsr(config, '<environment>')` — config needs the real
   15-digit VAT (starts/ends with 3), registered name, branch, address,
   category, and `invoiceType` `'1100'` (tenant-level: standard +
   simplified) or `'0100'` (B2C only). **Store the private key OUTSIDE
   any git repo** (pattern: `a secrets dir outside any repo`).
3. **AGENT**: `POST <base>/compliance` — headers
   `OTP: <otp>`, `Accept-Version: V2`, JSON `{csr: <csrBase64>}`.
   Success: 200, `dispositionMessage: "ISSUED"`, save the FULL body
   (token + secret + requestID). Failures: 400 `invalid-otp` (regenerate,
   move faster), CSR errors name the bad field.
4. **AGENT**: compliance checks — one document per type the CSR's
   invoiceType declares (`1100` ⇒ 6 docs: standard+simplified ×
   invoice/credit/debit; `0100` ⇒ 3 simplified docs).
   Sign with the compliance CSID (ZATCA SDK CLI or zatca-kit xades) and
   `POST <base>/compliance/invoices` per doc with Basic auth
   (`token:secret`, token VERBATIM — never re-encode). Success per doc:
   200/202, `PASS`. Known traps:
   - **Call from a server, never a browser** — this endpoint 403s CORS
     preflights.
   - SDK sample docs violate BR-KSA-EN16931-06 (price-level
     `ChargeIndicator=true`) — strip that block before signing.
   - SDK `fatoora -sign` wants cert AND key files as bare base64,
     no PEM headers. Java 11 only.
   - Seller VAT + name in each doc must match the CSR.
5. **AGENT**: `POST <base>/production/csids` with Basic(compliance
   token:secret), body `{compliance_request_id: "<requestID>"}`.
   Success: 200 ISSUED → production CSID. `Missing-ComplianceSteps`
   names exactly which step-4 documents are still missing.
   **NOT_COMPLIANT arrives with HTTP 200** — always branch on
   `dispositionMessage`, never the status code.
6. **AGENT**: verify — report one signed invoice via
   `POST <base>/invoices/reporting/single` (headers + `Clearance-Status:
   0`) with the production CSID. Success: 200/202 `REPORTED`.
7. **AGENT**: store credentials via the backend
   (`POST /admin/zatca/onboarding/*` drives steps 3-5 server-side and
   persists automatically), set tenant `zatcaPhase: '2'`.

## Route B — terminal onboarding (device CSIDs, the product flow)

The till drives everything itself; the human only types the OTP on the
device. Implemented in `apps/pos_app` (`ZatcaActivationService`) +
`/pos/zatca/*` endpoints:

1. Till generates its keypair + CSR ON DEVICE (`ZatcaCsr`, key never
   leaves; Keystore-wrapped at rest via `ZatcaCredentialsStore`).
2. Owner types the Fatoora OTP on the till →
   `POST /pos/zatca/onboard {csr, otp}` → backend relays to ZATCA →
   compliance cert returned to the device (secret stays server-side).
3. Till signs its own 3 compliance documents (simplified invoice /
   credit / debit — CSR map `0100`) → `POST /pos/zatca/checks`.
4. `POST /pos/zatca/production` → production cert stored on device;
   `ZatcaService` switches to CSID mode; receipts carry the full
   cryptographic stamp.

## Production-day checklist (when the wave letter arrives)

- [ ] Confirm the wave/integration notice in the Fatoora portal.
- [ ] Set `ZATCA_API_BASE=https://gw-fatoora.zatca.gov.sa/e-invoicing/core`.
- [ ] Rehearse once against simulation if >30 days since the last run.
- [ ] Route B per terminal (or Route A for server reporting creds).
- [ ] Verify `GET /admin/zatca/status`: production ISSUED + expiry.
- [ ] Flip `zatcaPhase: '2'`; watch the first live invoices in the
      portal's statistics dashboard (accepted/warnings/rejected + CSV).
- [ ] Diarize CSID expiry (status carries `expiresAt`); renewal =
      `POST /admin/zatca/onboarding/renew` with a fresh CSR + OTP.

## Agent ground rules

- OTPs and CAPTCHA are the human's; certs are public; the private key
  and API secret never enter a chat, a repo, or a log.
- One retry on 5xx/network with the SAME payload is safe everywhere
  (409 = already done = success). 400s are payload bugs — fix, don't
  hammer.
- The gateway once held POSTs open >6 minutes and answered in 0.6s the
  next day: keep 90s timeouts, treat hangs as "try again later", and
  never conclude the contract is wrong from a hang alone.
