# zatca-kit

**A battle-tested TypeScript toolkit for ZATCA (Fatoora) e-invoicing in
Saudi Arabia — CSR generation, QR codes, XAdES signing, and the live API
contract, with every undocumented trap we hit written down.**

Everything here was verified against ZATCA's **real servers** — the full
onboarding chain (compliance CSID → compliance checks → production CSID →
invoice reported) has been executed live with this code's algorithms, in
both the developer sandbox and the official simulation environment, and
the cryptographic output is byte-verified against ZATCA's own SDK.

Zero runtime dependencies. Everything runs on `node:crypto`.

---

## Why this exists

ZATCA Phase 2 integration looks simple on paper and then eats weeks:
the OpenAPI files contain typos the live service doesn't have, the
signing templates have whitespace that is load-bearing, digests are
double-encoded in a way no standard library produces, the official SDK
wants key files in a format no tool emits, and half the failure modes
only appear against the live gateway. This kit packages the working
code **and** the hard-won knowledge, so you don't rediscover any of it.

## What's inside

| Module | What it does |
|---|---|
| `src/csr.ts` | **EGS CSR generator** — secp256k1 keypair + hand-rolled PKCS#10 DER (subject, ZATCA SAN dirName with EGS serial/VAT/invoice-type map, per-environment `certificateTemplateName`). Byte-locked against ZATCA's own SDK output. |
| `src/qr.ts` | **Phase 1 AND Phase 2 receipt QR.** `buildPhase1Qr` (TLV tags 1–5, fully offline — for businesses outside the integration waves this is ALL of ZATCA compliance) and `buildPhase2Qr` (tags 6–9 cryptographic stamp). Money is integer halalas end to end — no floats, ever. |
| `src/xades.ts` | **XAdES B-B cryptographic stamp** — `parseCertificate` (dependency-free DER walk of the CSID: issuer, serial, raw public key, CA signature, double-encoded digest), `signInvoiceHash`, `buildXadesExtension` with the reference templates whose whitespace must not be touched. |
| `src/fatoora-client.ts` | **The live API contract** — compliance CSID, compliance checks, production CSID + renewal, B2C reporting, B2B clearance. Every header, auth quirk, and status-code meaning verified against the real gateway. |
| `ONBOARDING.md` | **Agent-executable onboarding runbook** — a human with portal access plus an AI agent (or a careful engineer) can drive sandbox, simulation, or production onboarding end to end. |
| `docs/zatca-contract.md` | The full annotated API contract with the live-verification log. |

## Quickstart

```bash
npm ci
npm test        # 50 tests, no network needed
```

### 1. Phase 1 QR — many businesses need nothing else

```ts
import { buildPhase1Qr } from './src/qr';

const qrBase64 = buildPhase1Qr({
  sellerName: 'متجر التجربة',
  vatNumber: '3XXXXXXXXXXXXX3',   // 15 digits, starts and ends with 3
  timestamp: new Date(),
  totalWithVatHalalas: 11500,      // SAR 115.00 — integer minor units
  vatHalalas: 1500,
});
// Render as a QR on the receipt. That is all of Phase 1.
```

### 2. Onboarding — CSR to production CSID

```ts
import { generateCsr } from './src/csr';

const { csrBase64, privateKeyPem } = generateCsr({
  commonName: 'POS-TERMINAL-1',
  serialNumber: '1-MyPOS|2-1.0|3-<device-uuid>',
  organizationIdentifier: '3XXXXXXXXXXXXX3',
  organizationUnitName: 'Main Branch',
  organizationName: 'My Company LTD',
  countryName: 'SA',
  invoiceType: '0100',             // TSCZ map: simplified-only B2C
  locationAddress: 'Riyadh',
  industryBusinessCategory: 'Retail',
}, 'simulation');                  // 'sandbox' | 'simulation' | 'production'

// POST csrBase64 + the taxpayer's Fatoora-portal OTP to /compliance,
// run the compliance checks, exchange for the production CSID.
// ONBOARDING.md walks every step with expected outputs & failure modes.
```

**Guard the private key.** It should be generated on the device that
signs (never in a repo, never in logs) — the CSR travels, the key does not.

### 3. Signing — the cryptographic stamp

```ts
import { parseCertificate, signInvoiceHash, buildXadesExtension } from './src/xades';

const cert = parseCertificate(binarySecurityTokenDecodedOnce);
const signature = signInvoiceHash(invoiceHashBase64, privateKeyPem);
const ublExtension = buildXadesExtension({
  invoiceHashBase64,
  signatureBase64: signature,
  certificate: cert,
  signingTime: new Date(),
});
// Embed in <ext:UBLExtensions>; QR tags 8/9 = cert.publicKeyBytes /
// cert.signatureBytes per BR-KSA-27.
```

## The three environments

| env | base URL suffix | CSR template | OTP source |
|---|---|---|---|
| sandbox | `/developer-portal` | `TSTZATCA-Code-Signing` | magic: `123345` valid · `111111` invalid · `222222` expired |
| simulation | `/simulation` | `PREZATCA-Code-Signing` | Fatoora **Simulation** Portal |
| production | `/core` | `ZATCA-Code-Signing` | Fatoora Portal |

Base: `https://gw-fatoora.zatca.gov.sa/e-invoicing` + suffix.
CSIDs are environment-exclusive — one never works in another.

## The traps (all hit live, all handled here)

1. **Basic auth username is the `binarySecurityToken` VERBATIM.** It is
   already base64 — re-encoding it (the "obvious" fix) is a 401 on every
   call. `Authorization: Basic base64(token + ":" + secret)`.
2. **`Accept-Version: V2` — capital V.** Anything else is a 406.
3. **`NOT_COMPLIANT` arrives with HTTP 200.** Branch on
   `dispositionMessage`, never the status code, or a failed production
   CSID exchange looks like success.
4. **409 on reporting = "already reported" = SUCCESS.** Your crash-safe
   retry will produce it; counting it as failure poisons your queue.
5. **The spec's `erroMessages` typo is spec-only.** The live service
   responds `errorMessages`. Accept both spellings or validation errors
   silently read as `undefined`.
6. **Digests are double-encoded**: `base64(hexString(sha256(bytes)))` —
   for the certificate hash AND the SignedProperties hash. Standard
   `digest('base64')` output is wrong.
7. **The SignedProperties whitespace is load-bearing.** The block that
   gets HASHED differs from the block that gets RENDERED (indentation,
   per-element `xmlns:ds`, self-closed `DigestMethod`). Reformat either
   and SIGNATURE validation fails.
8. **Sign with the clock in UTC.** ZATCA's SDK stamps `SigningTime` from
   the local clock with no timezone suffix and validators parse it as
   UTC — a UTC+3 machine emits signatures "from the future" that fail
   nondeterministically depending on when they're checked.
9. **`/compliance/invoices` rejects browsers.** Its CORS preflight
   returns 403 (the other endpoints allow it). Server-side calls only.
10. **ZATCA's official SDK wants bare base64 files** — the private key
    WITHOUT `-----BEGIN EC PRIVATE KEY-----` lines, the cert as the
    decoded `binarySecurityToken` text with no PEM wrapper. And it needs
    **Java 11**: newer JREs removed secp256k1 and signature validation
    dies with "Curve not supported".
11. **The SDK's own sample invoices violate the current rules**
    (BR-KSA-EN16931-06: price-level charge with `ChargeIndicator=true`).
    Strip that block before using them as compliance-check documents.
12. **The gateway has bad days.** The same endpoint held POSTs open for
    6+ minutes one day and answered in 0.6s the next. Keep ~90s
    timeouts, treat hangs as "later", and never conclude your request
    is wrong from a hang alone.
13. **OTPs live 60 minutes** and are consumed by the FIRST call
    (compliance CSID). After that step succeeds there is no time
    pressure — don't rush the rest.
14. **Simulation enforces the compliance-check gate that sandbox skips**
    (`Missing-ComplianceSteps` names exactly which document types are
    missing — one per type declared in your CSR's invoice-type map).

## Design principles

- **Money is integer halalas** (SAR minor units). Nothing here converts
  through floating point.
- **Zero runtime dependencies** — auditable, portable, no supply-chain
  surface. `node:crypto` does all the cryptography.
- **Per-environment everything** — templates, base URLs, and credentials
  never cross environments by construction.
- **Tests lock bytes, not vibes** — DER output, digest vectors, and
  template bytes are pinned; a formatting "cleanup" fails the suite.

## Contributing

Issues and PRs welcome — especially new live-verified failure modes for
the traps list (please include the exact request shape and response).
Run `npm test` and `npm run typecheck` before submitting. Never commit
a real private key, secret, or taxpayer identity — test fixtures use
anonymized self-signed certificates.

## Disclaimer

Not affiliated with ZATCA. Verify your integration against ZATCA's
official documentation and your own compliance requirements; this kit
documents observed behavior of the live service at the dates noted in
`docs/zatca-contract.md`.

## License

[MIT](./LICENSE)
