# 10 — ZATCA Developer Portal: extracted facts (owner-supplied manual v3)

Source: `User_Manual_Developer_Portal_Manual_Version_3.pdf` (ZATCA, 96 pp).
Read with docs/06 (reference-implementation facts). Where the two disagree,
this file wins — it is ZATCA's own document.

## THE UNBLOCK: registration is self-service
**The Developer Portal is at `https://sandbox.zatca.gov.sa/` and accounts are
created by self-registration** (manual §2.3.1–2.3.2). There is no multi-week
approval queue for sandbox access — earlier planning assumed one. Two tools
sit behind the login:
1. **Compliance & Enablement Toolbox SDK** — an *offline downloadable*
   validator (XML + QR) with a **CLI**. This is exactly what doc 04-B5's
   golden-file CI needs: our generated invoices can be validated in CI
   without any network call to ZATCA.
2. **Integration Sandbox** — a test ZATCA backend with **Swagger docs on the
   Sandbox page** covering onboarding, renewal, reporting, clearance.
   Sandbox CSIDs are test-only and cannot be used in production.
A third, non-technical **portal-based validator** validates pasted XML in the
browser (useful for support: a merchant's accountant can self-serve).

## Auth (manual §3 Security Requirements) — PRECISE
- `Authorization: Basic base64("<CSID>:<secret>")` where **CSID is the
  `binarySecurityToken` returned by the Compliance CSID API** and `secret` is
  issued alongside it.
- **`Accept-Version: V2` is REQUIRED — uppercase `V2`.** The OpenAPI files are
  explicit: HTTP **406** means "accept version header is anything other than
  V2". (The manual's prose says `v2`; the spec wins.)
- Compliance CSID+secret authorize the compliance-check calls; the
  **Production** CSID+secret authorize all reporting/clearance calls.
- The `binarySecurityToken` is **already base64** — it is the username
  verbatim. Base64-encoding it again before building the Basic header
  double-encodes and yields 401.

---

## THE API CONTRACT (from the live OpenAPI files, 2026-08-17)

Pulled from the six spec files the Sandbox page renders, at
`…/developer-portal/users/api/v1/swagger/render?fileId=<ID>` where `<ID>` is
one of `COMPLIANCE_CSID`, `ONBOARDING`, `RENEWAL`, `COMPLIANCE_INVOICE`,
`REPORTING`, `CLEARANCE`. All six declare `info.title` =
*e-Invoicing Sandbox Release (2.1.0)*. Re-pull from that URL when ZATCA bumps
the release — the page itself is public, no login required.

### Base URLs — the old GAZT host is dead
| Environment | Base URL |
|---|---|
| **Sandbox (developer portal)** | `https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal` ← confirmed by the spec's `servers[]` **and** by the portal's own `env-config.js` |
| Simulation | `https://gw-fatoora.zatca.gov.sa/e-invoicing/simulation` |
| Production (core) | `https://gw-fatoora.zatca.gov.sa/e-invoicing/core` |

⚠️ Our client defaulted to `https://gw-apic-gov.gazt.gov.sa/…` — the
pre-rebrand GAZT gateway. Fixed; keep `ZATCA_API_BASE` overridable per env.

### Endpoints

| # | Method + path | Auth | Required headers | Body |
|---|---|---|---|---|
| 1 | `POST /compliance` | **none** | `OTP`, `Accept-Version: V2` | `{ "csr": "<base64 of the PEM CSR>" }` |
| 2 | `POST /production/csids` | Basic (**compliance** CSID) | `Accept-Version: V2` | `{ "compliance_request_id": "1234567890123" }` |
| 3 | `PATCH /production/csids` | Basic (**existing production** CSID) | `OTP`, `Accept-Version: V2`, opt. `accept-language` | `{ "csr": "<base64 CSR>" }` |
| 4 | `POST /compliance/invoices` | Basic (**compliance** CSID) | `Accept-Version: V2`, opt. `Accept-Language` | `{ invoiceHash, uuid, invoice }` |
| 5 | `POST /invoices/reporting/single` | Basic (**production** CSID) | `Accept-Version: V2`, **`Clearance-Status`**, opt. `accept-language` | `{ invoiceHash, uuid, invoice }` |
| 6 | `POST /invoices/clearance/single` | Basic (**production** CSID) | `Accept-Version: V2`, **`Clearance-Status`**, opt. `accept-language` | `{ invoiceHash, uuid, invoice }` |

- `Clearance-Status` is **required**, value `"0"` when clearance is disabled
  and `"1"` when enabled. Our B2C till reports with `"0"`.
- `invoice` is the **base64 of the signed UBL XML**; `invoiceHash` is the
  base64 SHA-256 of the canonicalized XML; `uuid` is our per-invoice UUID.
  Note the `InvoiceRequest` schema names only `invoiceHash` + `invoice`, but
  every worked example sends `uuid` too — send all three.

### CSID issuance response (endpoints 1–3)
```json
{ "requestID": 1234567890123,
  "tokenType": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3",
  "dispositionMessage": "ISSUED",
  "binarySecurityToken": "TUlJ...",
  "secret": "<base64 secret>",
  "errors": null }
```
`binarySecurityToken` becomes the Basic username, verbatim. `requestID` from
step 1 is the `compliance_request_id` for step 2. `dispositionMessage` is
**`ISSUED`** on success and **`NOT_COMPLIANT`** when the compliance checks
have not been passed — that is the gate, and it comes back **200 with a
NOT_COMPLIANT body**, not an HTTP error. Branch on `dispositionMessage`,
never on the status code alone.

### Status codes that change our retry logic
| Code | Reporting | Clearance | What it means for the worker |
|---|---|---|---|
| 200 | ✔ | ✔ | reported/cleared |
| 202 | ✔ | ✔ | accepted **with warnings** — still success, log the warnings |
| 208 | — | ✔ | invoice hash previously submitted → treat as success |
| 303 | — | ✔ | clearance deactivated; resubmit the standard doc via Reporting |
| 400 | ✔ | ✔ | invoice genuinely rejected → `failed`, do not retry |
| 401 | ✔ | ✔ | bad/absent credentials → **config problem, not an invoice problem** |
| 406 | ✔ | ✔ | `Accept-Version` ≠ `V2` → **our bug**, not the invoice's |
| 409 | ✔ | — | **"already reported successfully earlier" → SUCCESS** |
| 500 | ✔ | ✔ | retry |

⚠️ 409 is the one that bites offline-first: a network blip after ZATCA
committed the report means our retry gets 409. Treating "4xx = rejected"
marks a *successfully reported* invoice `failed` forever and raises a false
compliance alert. Same for 401/406 — a credential typo would otherwise burn
the whole pending queue to `failed` on one pass. Fixed in `fatoora.client.ts`.

### Sandbox magic OTPs (from the spec's own examples)
`POST /compliance` in the sandbox accepts fixed OTPs: **`123345` = valid**,
`111111` = invalid, `222222` = expired. Use them to test all three onboarding
branches without a Fatoora portal account.

### Sandbox flakiness (observed live, 2026-08-17)
`GET …/swagger/render` answers instantly, but `POST /compliance` held the
connection >4 minutes without responding (browser-origin, correct headers,
ZATCA's own example CSR — and a no-preflight probe hung identically, so it is
the endpoint, not CORS). The forum documents this mood. Consequence for our
code: every Fatoora call needs an explicit client-side timeout (60–90s) that
returns the invoice to `pending`, or one slow sandbox day stalls the whole
reporting worker on a single invoice.

### Response body (endpoints 4–6)
```json
{ "validationResults": { "infoMessages": [], "warningMessages": [],
                         "erroMessages": [], "status": "" },
  "reportingStatus": "" }
```
Clearance additionally returns `clearedInvoice` (base64 of the ZATCA-stamped
XML) — that is the copy we must archive, not the one we sent.

⚠️ **Spec vs live spelling** (verified live 2026-08-18): the OpenAPI files
say `erroMessages`, but the LIVE sandbox responds `errorMessages`. The DTO
accepts BOTH — trusting either document alone silently reads undefined on
the other. (`erros` in the CSID error schema remains unverified live.)

## ZATCA phase — the tenant tri-state

Tenant setting **`zatcaPhase: 'none' | '1' | '2'`** (config-not-code, rule 6):

| Phase | Meaning | Receipt QR | Reporting |
|---|---|---|---|
| `'none'` | **Signup default.** ZATCA not configured yet | none | never |
| `'1'` | Generation phase — the QR IS the whole obligation | TLV tags 1–5 | never |
| `'2'` | Integration phase — CSID + signing + ≤24h reporting | tags 1–9 | yes |

Written explicitly as `'none'` at signup; absent also reads as `'none'`
(reporting is strictly opt-in — nothing reaches ZATCA until a tenant
explicitly configures phase 2). What honors it:
- **Till**: `ReceiptData.fromSale` prints no QR for `'none'`, the phase-1
  TLV QR for `'1'`/`'2'` (tags 6–9 arrive with the on-device signer).
- **Reporting worker**: reports ONLY `'2'` tenants — `'none'`/`'1'` invoices
  are skipped even when credentials exist.
- **Admin settings UI** (`/admin/settings`): a three-option ZATCA card with
  bilingual explanations; picking `'1'`/`'2'` requires a valid VAT number
  (15 digits, starts+ends with 3) since it prints inside the QR.
- **`GET /admin/zatca/status`**: returns `zatcaPhase` + bilingual
  `nextSteps` guidance ("choose a phase" / "enter the Fatoora OTP" /
  "onboarding complete"), so the UI walks the tenant through onboarding.
- **zatca-kit**: `buildPhase1Qr` / `buildPhase2Qr` in `src/qr.ts`,
  bit-identical to the Dart builder (shared test vectors).

Upgrade path: choose phase 1 in Settings (instant) → when entering an
integration wave, run CSID onboarding (chain above) → flip to phase 2.
Nothing reprints, nothing migrates — the next sale signs and the worker
starts reporting.

## ON-DEVICE SIGNER + FULL VALIDATION GATE (2026-08-18)

The signing story is complete end to end:
- **Dart on-device signer** (`zatca_certificate.dart` + `zatca_xades.dart`
  + CSID mode in `ZatcaService`): full XAdES envelope, QR tags 8–9 from
  the certificate. Vectors cross-verified against the official SDK (cert
  digest) and the reference implementation (SignedProperties digest).
- **zatca-kit `src/xades.ts`**: the TypeScript twin (dependency-free DER
  cert parser + same load-bearing-whitespace templates), locked to the
  SAME vectors so the two implementations cannot drift.
- **Signed golden** `apps/backend/test/golden/simplified-invoice-signed.xml`
  (our builder's fixture signed with the real simulation CSID):
  **GLOBAL VALIDATION RESULT = PASSED** — all six SDK categories
  including QR and SIGNATURE. CI now gates `*-signed.xml` on GLOBAL PASS.
- **B2B clearance primitive**: `FatooraClient.clearStandard()`
  (`/invoices/clearance/single`, `Clearance-Status: 1`) returning the
  ZATCA-stamped `clearedInvoice` — the legal copy to archive. Real-time
  per rule 7; the B2B sale flow plugs into it when built.

Remaining ZATCA engineering: the terminal ACTIVATION flow (on-device CSR
via Dart, key in Keystore-wrapped storage, backend delivery of the CSID
to its terminal) — then production onboarding when the wave arrives.

## SIMULATION ONBOARDING — COMPLETED LIVE (2026-08-18, real company)

The full simulation onboarding ran successfully for the real TIN
(3XXXXXXXXXXXXX3) with a real Fatoora-portal OTP:
1. Portal → Simulation Portal → Onboard device → OTP (1h validity).
2. CSR (zatca-kit generator, `PREZATCA-Code-Signing`) → `POST
   /simulation/compliance` → compliance CSID **ISSUED** (0.6s). The OTP is
   consumed HERE — after this step there is no time pressure.
3. Six compliance checks (SDK-signed samples) → ALL **PASS**
   (standard×3 CLEARED, simplified×3 REPORTED).
4. `POST /simulation/production/csids` → production CSID **ISSUED**
   (request <requestID>).
5. Bonus: `POST /simulation/invoices/reporting/single` with production
   creds → **202 REPORTED** (warning `invalid-signing-certificate` as
   expected — doc was signed with the compliance cert; terminals re-sign
   with the production CSID).

Hard-won operational facts:
- **`/compliance/invoices` rejects browser calls**: its CORS preflight
  (OPTIONS) returns **403** — unlike `/compliance` and `/production/csids`.
  Server-side calls only (our backend is unaffected; it never browsers).
- **SDK cert/key file formats**: `fatoora -sign` wants BOTH files as bare
  base64 — private key WITHOUT `-----BEGIN EC PRIVATE KEY-----` headers,
  cert as the decoded binarySecurityToken text (no PEM wrapper).
- **SDK samples fail current rules**: every Invoice/Debit sample carries a
  price-level `<cac:AllowanceCharge>` with `ChargeIndicator=true` →
  **BR-KSA-EN16931-06** rejection. Strip that block (our builder never
  emits price-level charges; catalogue discounts are document-level).
- SDK needs Java 11 (Temurin 11 zip, no installer, works fine); run from
  `Apps/` with `SDK_CONFIG=Configuration/defaults.json` (CI's trick).
- Simulation ENFORCES the 6-document compliance gate that sandbox skips
  (`Missing-ComplianceSteps` on early production-CSID attempts) — CSR
  invoiceType `1100` demands standard+simplified × invoice/credit/debit.

Credentials/keys live in `a secrets dir outside any repo ` (outside all
repos). Same flow with `ZATCA-Code-Signing` + production base URL is the
real onboarding when a wave assignment arrives.

## LIVE END-TO-END PROOF (2026-08-18, sandbox)
The full chain ran successfully against the live sandbox from the browser:
1. `POST /compliance` (example CSR + OTP `123345`) → **200, ISSUED**,
   compliance CSID + secret + requestID — in 0.9s.
2. `POST /production/csids` (Basic compliance creds,
   `{compliance_request_id}`) → **200, ISSUED**, production CSID — 0.5s.
3. `POST /invoices/reporting/single` (Basic production creds, ZATCA's
   signed sample invoice) → **200, `reportingStatus: "REPORTED"`,
   validation PASS** — 1.0s.
Every documented header/auth/body fact confirmed against the real service.
The endpoint that had held POSTs open for 6+ minutes the previous day
answered in under a second — the flakiness is real but transient; the
90s client timeout stays.

## Onboarding = three API calls, with a gate in the middle
1. **Compliance CSID API** — body: signed **CSR**; requires a valid **OTP**
   (from the taxpayer's Fatoora portal; 1-hour validity per docs/06).
   Returns `binarySecurityToken` (= compliance CSID), `secret`, `requestID`.
2. **Compliance checks** — submit test documents (standard + simplified +
   credit/debit notes) via the compliance-invoices API. The manual is
   explicit: *the Production CSID call returns an invalid response until
   these checks pass* (and the sandbox can simulate that failure).
3. **Production CSID (Onboarding) API** — body: the `requestID` from step 1,
   authorized with the compliance CSID. Returns the production CSID+secret.
- **Production CSID (Renewal) API** — OTP + a fresh CSR; same shape as step 1.
  Certificates expire, so renewal is a first-class flow, not an afterthought:
  the fleet screen should surface CSID expiry per terminal.

## Keys & CSR (manual §5.3, appendix)
- Curve: the manual says "ECDSA … P-256 (secp256k1)" — the two names are
  different curves and the doc conflates them; **secp256k1 is the working
  answer**, matching both reference implementations (docs/06). Keep
  secp256k1 in `zatca_signer.dart`.
- Keys per **FIPS 186**, validated per **NIST SP 800-56A** §5.6.2.3.2/3
  (ECC full or partial public-key validation).
- **"Keys must be marked as non-exportable"** — a software security module is
  acceptable *only if* it meets that bar. Our design (software secp256k1 key
  in app-encrypted storage wrapped by the Android Keystore master key,
  docs/06 amendment) must therefore never expose a key-export path: no
  backup of the private key, no debug dump, wipe on deactivation. Document
  this as a compliance claim we have to be able to defend.
- Public key is the **compressed** form (X only) for the certificate; the
  base64 public key validates standard-invoice signatures.
- CSR is generated with `-sha256`, and carries EGS-specific fields:
  | CSR field | Meaning |
  |---|---|
  | **Functionality Map** | 4-digit binary over "TSCZ", `1` = supported. `1000` = standard only, `0100` = simplified only, `1100` = both. Cannot be all zeros. **Ours: `0100` for a B2C-only till, `1100` once B2B standard invoices ship.** |
  | **Location** | Branch/EGS-unit address (a website address is allowed for e-commerce — our storefront case) |
  | **Organization Name** | Taxpayer name |
  | **Industry** | Sector the unit invoices for |
  Plus the usual common-name/serial/VAT fields per the security standard.
- A **Postman collection** is referenced for testing a generated CSR before
  wiring code.

## What this changes in our plan
1. ~~Do sandbox registration~~ — **not even needed**: the Sandbox page, the
   OpenAPI specs, and the SDK download are all public. **SDK downloaded
   2026-08-17** → `D:\pos\tools\zatca-sdk\zatca-einvoicing-sdk-238-R3.3.8\`
   (Java build, 329MB zip kept alongside). What's inside:
   - `Apps/fatoora` CLI (+ `.bat`): `-csr` (with `-nonprod`/`-sim` env
     flags), `-sign`, `-qr`, `-generateHash`, `-invoiceRequest`,
     **`-validate`** — the offline validator doc 04-B5's golden-file CI
     needs. Needs a JRE (none on this machine yet; CI gets one via
     `actions/setup-java`).
   - `Data/Rules/schematrons/` — the actual EN16931 + ZATCA validation XSLs.
   - `Data/Samples/` — official sample XMLs incl. simplified credit/debit
     notes and error variants → seed material for golden files.
   - `Data/Input/csr-config-*.properties` — the CSR fields, exactly:
     `csr.common.name`, `csr.serial.number` (`1-XXX|2-XXX|3-<uuid>`),
     `csr.organization.identifier` (VAT no.), `csr.organization.unit.name`,
     `csr.organization.name`, `csr.country.name=SA`,
     `csr.invoice.type` (the TSCZ functionality map, e.g. `1100`),
     `csr.location.address`, `csr.industry.business.category`.
   - `Data/Certificates/ec-secp256k1-priv-key.pem` — confirms the curve.

   **⚠️ The SDK requires Java 11.** Verified live (2026-08-18): under a
   Java 17 JRE, `-validate` fails signature checks with *"Curve not
   supported: secp256k1"* — JDK 15+ removed secp256k1 from the SunEC
   provider. Under Temurin 11 (`D:\tools\java\jdk-11.0.32+9-jre`) the full
   run PASSES: XSD, EN, KSA, QR, SIGNATURE, PIH → GLOBAL PASSED on the
   sample simplified invoice and credit note, and the deliberate error
   sample FAILS with exit code 255 — so CI can gate on the exit code.
   Run it with `SDK_CONFIG=<sdk>\Configuration\defaults.json` from the
   SDK's `Apps` dir.

   **CSR ASN.1 ground truth** (SDK-generated reference decoded with
   `openssl req -text -noout`; reference pair kept in the session
   scratchpad `csr-ref/`):
   - Subject order: `C=SA, OU=<unit>, O=<org>, CN=<common name>`; key
     id-ecPublicKey secp256k1; signature ecdsa-with-SHA256; version 1.
   - Extension `1.3.6.1.4.1.311.20.2` (MS certificateTemplateName) =
     `TSTZATCA-Code-Signing` for sandbox (`-nonprod`); simulation/prod use
     the `PREZATCA-`/plain `ZATCA-Code-Signing` variants.
   - SAN = DirName with attrs in order:
     `SN=<'1-X|2-X|3-uuid'>, UID=<VAT>, title=<invoiceType '1100'>,
     registeredAddress=<location>, businessCategory=<industry>`.
2. **Build the CSID onboarding flow** against the sandbox: CSR generation
   on-device (with the four EGS fields above), compliance CSID request,
   compliance-check submission, production CSID exchange, and renewal.
3. **Fix the Basic-auth encoding + add `accept-version: v2`** in the Fatoora
   client before any live call (see the audit note above).
4. **Surface CSID expiry** per terminal in the platform fleet view, so
   renewal never surprises a shop.
5. ~~Endpoint paths/base URLs are not in the manual text~~ — **DONE**, pulled
   from the live OpenAPI files and recorded above (2026-08-17). No login was
   needed: the Sandbox page and its spec files are public.
