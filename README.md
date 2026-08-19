<div align="center">

## بِسْمِ اللَّهِ الرَّحْمَٰنِ الرَّحِيمِ

</div>

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

## Which stack can use this?

The code is **TypeScript on Node.js** — but the knowledge transfers to
any stack, and the byte-locked test vectors make porting safe.

| Your stack | How you use zatca-kit |
|---|---|
| **Node.js / TypeScript / JavaScript** (NestJS, Express, Fastify, Next.js API routes) | Directly — drop `src/` in and import. Needs Node ≥ 20 (`node:crypto` with secp256k1). |
| **Bun / Deno** | The crypto primitives (secp256k1 ECDSA, SHA-256, DER) are standard; run the test suite first — 50 green tests means your runtime is compatible. |
| **Electron / Tauri (Node side)** | Same as Node.js — sign on the main process, never in the renderer. |
| **Flutter / Dart, Python, Go, Java, PHP, .NET, Rust** | Port the algorithms using this repo as the **reference implementation**: every digest, DER structure, and template is pinned by exact test vectors in `src/*.spec.ts`, so you can verify your port byte-for-byte. (A Dart port of the CSR + XAdES modules already exists and passes ZATCA's official SDK validation.) |
| **ERPNext / Odoo / existing ERPs** | Use `docs/zatca-contract.md` + the traps list as the integration manual — the API contract and failure modes are stack-independent. |
| **Browsers / frontend-only apps** | ❌ Not supported by design: ZATCA's `/compliance/invoices` blocks browser CORS preflights, and a signing private key must never live in a browser. Sign server-side or on-device. |

**Rule of thumb:** if you write JS/TS, use the code. If you write
anything else, use the vectors and the docs — they're the part that
took weeks to get right.

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
15. **QR tag 3 takes seconds precision — `2022-04-25T15:30:00Z`, no
    milliseconds.** `Date.toISOString()` (JS) and `toIso8601String()`
    (Dart) both emit `.000Z`, which diverges from ZATCA's published
    sample AND can never equal the invoice XML's `cbc:IssueTime`
    (HH:MM:SS) that Phase 2 validation cross-checks the QR against.
    Sneaky because per-field tests happily assert the wrong string —
    lock your builder against ZATCA's published sample base64, byte
    for byte, like `qr.spec.ts` does.
16. **QR tag 8 is the FULL SubjectPublicKeyInfo DER (88 bytes), not the
    bare 65-byte EC point.** Every X.509 parser hands you the tempting
    raw `04‖X‖Y` from the BIT STRING; ZATCA's validation wants the whole
    `3056 3010 06072a8648ce3d0201 06052b8104000a 034200 04‖X‖Y`
    structure. Related caps: the encoded QR maxes out at 700 chars, and
    the CSR invoice-type map allows only `1000`/`0100`/`1100` (last two
    TSCZ digits are reserved zeros). Duplicate submissions: the spec
    documents 208, the live service now sends 409 — treat both as
    "already filed", and remember a duplicate clearance reply carries NO
    clearedInvoice (your archived first response is the legal copy).

## Design principles

- **Money is integer halalas** (SAR minor units). Nothing here converts
  through floating point.
  > In plain words: money is never stored as `25.50` — it's stored as
  > `2550` halalas (the smallest coin unit, like cents). Computers get
  > decimal math subtly wrong (`0.1 + 0.2` is `0.30000000000000004` in
  > JavaScript), and a one-halala rounding error can fail ZATCA
  > validation. Whole numbers never have this problem; amounts only
  > become `"25.50"` text at the last moment, when rendering.
- **Zero runtime dependencies** — auditable, portable, no supply-chain
  surface. `node:crypto` does all the cryptography.
  > In plain words: `npm install` here pulls in **nothing**. Most
  > libraries drag in dozens of strangers' packages, any of which can
  > break or be hacked — a bad trade for code that signs tax invoices
  > with your company's cryptographic identity. What you read in `src/`
  > is 100% of what runs.
- **Per-environment everything** — templates, base URLs, and credentials
  never cross environments by construction.
  > In plain words: ZATCA has three separate worlds — sandbox
  > (playground), simulation (dress rehearsal), production (real taxes) —
  > and credentials from one are useless or dangerous in another. You
  > pick the world once (`'simulation'`) and the right template, URL,
  > and certificate follow automatically. There is no code path that
  > lets a test invoice reach the real tax authority.
- **Tests lock bytes, not vibes** — DER output, digest vectors, and
  template bytes are pinned; a formatting "cleanup" fails the suite.
  > In plain words: the tests check the **exact bytes** the code
  > produces, because ZATCA checks exact bytes too. Some whitespace in
  > the signing templates looks like sloppy formatting but is actually
  > part of what gets cryptographically hashed — "tidy" it up and every
  > invoice fails validation in a way that's brutal to debug. Touch the
  > bytes, tests go red, disaster caught before it ships.

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

[AGPL-3.0](./LICENSE) — the same license used by other open-source ZATCA
compliance projects in the ecosystem.

> In plain words: you can use, modify, and even sell software built on
> this kit for free — but if you run a modified version as a service
> (SaaS, API, hosted product), you must offer your users the source code
> of your modifications. Improvements flow back to the community instead
> of disappearing behind a server. Using the kit **unmodified** inside
> your product carries the same share-alike terms for the covered code.
