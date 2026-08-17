# zatca-kit

Everything needed to make a product **ZATCA (Fatoora) phase-2 compliant**
without re-learning the hard way. Every fact in here was verified against
ZATCA's live sandbox, their published OpenAPI files, and their official
SDK validator — not blog posts.

## What's inside

| Path | What it is |
|---|---|
| `docs/zatca-contract.md` | **Start here.** The full API contract: base URLs, all six endpoints, exact headers, auth format, status-code semantics, sandbox magic OTPs, CSR ASN.1 layout, SDK usage, every trap we hit. |
| `src/fatoora-client.ts` | Dependency-free TypeScript client: B2C reporting + the CSID onboarding chain (compliance CSID → checks → production CSID → renewal). Timeout-hardened. |
| `src/csr.ts` | EGS CSR generator: secp256k1 keypair + hand-rolled PKCS#10 DER on `node:crypto` alone, byte-locked against ZATCA's own SDK output. |
| `src/*.spec.ts` | The tests that pin the wire contract (headers, auth encoding, every status code) and the CSR ASN.1. `npm test`. |
| `fixtures/` | Golden simplified-invoice XML that passes the SDK's XSD/EN/KSA/PIH validation, + the regeneration rules. |
| `reference/nestjs/` | Real-world integration reference: onboarding service + admin controller + append-only credentials migration from the POS SaaS this kit was extracted from. Read, adapt, don't import. |
| `.github/workflows/golden.yml` | CI: unit tests + golden-file validation with ZATCA's real SDK CLI. |

## The five traps this kit saves you from

1. **The `binarySecurityToken` is already base64** — it's the Basic-auth
   username *verbatim*. Re-encoding it = guaranteed 401.
2. **HTTP 409 on reporting = SUCCESS** ("already reported"). Treating 4xx
   as rejection marks successfully-filed invoices as failed forever.
3. **`dispositionMessage: NOT_COMPLIANT` arrives with HTTP 200.** The
   onboarding gate must branch on the body, never the status code.
4. **The SDK validator requires Java 11** — JDK 15+ removed secp256k1, and
   only the signature check breaks, silently weakening your CI gate.
5. **BR-KSA-04 vs UTC**: KSA is UTC+3; an invoice issued 00:00–03:00
   Riyadh time is "future-dated" to a UTC validator. Fixtures must be
   past-dated; production issue-dates need timezone care.

(There are more in `docs/zatca-contract.md` — the openssl `SN` = surname
trap, ZATCA's own `erroMessages` typo you must mirror, the SDK's
hardcoded `C:\SDK` config paths, the sandbox holding POSTs open for
minutes...)

## Quickstart

```bash
npm ci
npm test          # wire contract + CSR tests, no network needed
```

Sandbox onboarding smoke (no account needed — magic OTPs `123345` valid,
`111111` invalid, `222222` expired):

```ts
import { FatooraClient } from './src/fatoora-client';
import { generateCsr } from './src/csr';

const { csrPem } = generateCsr(
  {
    commonName: 'TST-886431145-399999999900003',
    serialNumber: '1-POS|2-A920|3-<uuid>',
    organizationIdentifier: '399999999900003', // 15 digits, starts+ends with 3
    organizationUnitName: 'Riyadh Branch',
    organizationName: 'My Company LTD',
    countryName: 'SA',
    invoiceType: '0100',                       // TSCZ map: simplified-only B2C
    locationAddress: 'RRRD2929',
    industryBusinessCategory: 'Retail',
  },
  'sandbox', // picks the TST/PRE/plain certificateTemplateName
);

const client = new FatooraClient();           // ZATCA_API_BASE overrides env
const csid = await client.complianceCsid(
  Buffer.from(csrPem).toString('base64'),
  '123345',
);
// csid.dispositionMessage === 'ISSUED' → binarySecurityToken + secret + requestID
```

## SDK mirror

The 329MB official SDK zip lives as a **release asset on this repo**
(tag `zatca-sdk-238-R3.3.8`) because ZATCA's SharePoint rejects headless
downloads. CI pulls it from there. When ZATCA ships a new SDK, download
it from https://sandbox.zatca.gov.sa/ in a browser and
`gh release create <new-tag> <zip>` here.

## Environments

| | Base URL | certificateTemplateName |
|---|---|---|
| Sandbox | `https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal` | `TSTZATCA-Code-Signing` |
| Simulation | `.../e-invoicing/simulation` | `PREZATCA-Code-Signing` |
| Production | `.../e-invoicing/core` | `ZATCA-Code-Signing` |

Same code, config change only. A CSID from one environment is useless in
another. Simulation/production onboarding needs a real OTP from the
taxpayer's Fatoora portal (1-hour validity) — sandbox does not.
