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
15. **QR tag 3 is `2022-04-25T15:30:00` — seconds precision, no
    milliseconds, and NO `Z`.** Live-verified: the phase-2 KSA-25 check
    wants tag 3 byte-equal to `IssueDate + 'T' + IssueTime`, and a `Z`
    draws `invoiceTimeStamp_QRCODE_INVALID`; ZATCA's own SDK emits no Z.
    Meanwhile ZATCA's PUBLISHED phase-1 sample carries a Z — the
    published sample and the live validator disagree, and the live
    validator wins. (`Date.toISOString()` / Dart's `toIso8601String()`
    are wrong twice over: `.000` millis AND the Z.) Per-field tests
    happily assert whatever you wrote — lock the full base64, byte for
    byte, against a LIVE-ACCEPTED vector like `qr.spec.ts` does.
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
17. **The invoice hash is NOT what the signature's declared transforms
    say.** The SDK's real pipeline is an identity XSLT dropping
    UBLExtensions/Signature/QR-ADR (element bytes only — surrounding
    whitespace text nodes SURVIVE), no XML declaration, then C14N11.
    And the SignedProperties digest is over the RENDERED block
    re-serialized by a plain Java Transformer: document indentation
    kept, `xmlns:ds` added to every ds: element, empty DigestMethod
    self-closed. The community's deeper-indented "for signing" template
    only works when your document happens to render at that indent.
    Related: quotes in TEXT stay bare (C14N doesn't escape them there),
    the KSA-2 subtype for a plain receipt is `0200000` (the samples'
    `0211010` sets the summary bit → BR-KSA-71 warnings), and the SDK
    CLI **on Windows** hashes Arabic invoices wrong (it decodes its own
    transform output with the platform charset — run it with
    `-Dfile.encoding=UTF-8` to match ZATCA's Linux servers). All of
    this was proven 2026-08-19 with a clean live acceptance:
    `reportingStatus REPORTED`, zero warnings, zero errors.

## What this kit refuses to do

Every rule below exists because a real input got past an earlier version
of this code during adversarial review. They are the difference between
"the call returned 200" and "the invoice is actually filed", and each one
is pinned by a test.

**Success needs evidence, never a status code.**

- Reporting is `ok` only on HTTP 200/202 **with** `reportingStatus:
  REPORTED`, or a documented duplicate (208/409). A bare 2xx with an
  empty body proves nothing and must never mark an invoice permanently
  reported.
- Clearance is `ok` only with `clearanceStatus: CLEARED` **and** a
  stamped `clearedInvoice`. A duplicate reply carrying no payload is
  flagged `duplicate` but not `ok` — your archived first response is the
  legal copy.
- If the same body carries a `validationResults` block, it must
  **affirm** success (`PASS`/`WARNING`). `REPORTED` alongside
  `status: ERROR`, an unknown status, or a populated error list is a
  contradiction, and contradictions fail closed. Both spellings of the
  error array (`errorMessages`, ZATCA's `erroMessages`) are merged, never
  coalesced — an empty array in one must not hide a full one in the
  other. Anything unreadable (a string where an object belongs, a
  non-array error field) also fails closed instead of throwing.

**Cryptographic material is verified, not inspected.**

- QR tags 6/7/8 must be a *matched set*: the signature has to verify over
  the invoice hash under the tag-8 key. Three individually valid blobs
  from different invoices or terminals produce a QR that every offline
  verifier rejects — and nothing downstream would catch it.
- The XAdES envelope verifies the signature against the public key of the
  certificate it embeds, before assembling anything.
- Tag 8 must be the canonical 88-byte uncompressed SPKI on secp256k1. A
  compressed point parses fine, names the same curve, and round-trips
  unchanged — only an explicit shape check sees it.
- Signatures (tags 7 and 9) must be DER `SEQUENCE { INTEGER r, INTEGER s }`
  with `r`,`s` minimally encoded and inside `[1, n-1]` for the secp256k1
  group order. `30 06 02 01 00 02 01 00` (r=0, s=0) and any value at or
  above `n` are well-formed DER and mathematically impossible.
- Base64 is decoded **strictly** everywhere it is evidence. Node's
  decoder silently skips invalid characters, so `not-base64!!!` "decodes"
  and would otherwise be signed.

**The cleared invoice is parsed, not sniffed.**

`clearedInvoice` becomes the legal document you archive and hand the
buyer, so a leading `<` is not good enough. It must be canonical base64
of a document that is well-formed by XML's *actual* rules, whose root is
`Invoice` (or `CreditNote`/`DebitNote`) and is **in** the matching UBL
2.1 namespace, read from that element's own parsed declaration. All of
these are rejected:

| Input | Why |
| --- | --- |
| `<Invoice…><cbc:ID>1` | truncated — tags left open |
| `…:xsd:Order-2` | wrong UBL namespace |
| `<Invoice><x xmlns="…Invoice-2"/>` | namespace declared only on a child |
| `<Invoice note=" xmlns='…'"/>` | namespace hidden in another attribute's value |
| `&nbsp;` | undefined entity (there is no DTD) |
| `&#0;` | character reference outside XML 1.0's Char production |
| `<!-- a -- b -->` | `--` is forbidden inside comments |
| `<Invoice…><?xml version="1.0"?>` | the declaration is legal only at byte 0 |
| `<cbc:ID>` with no `xmlns:cbc` | prefix used but never declared |
| `<![CDATA[…]]>` before the root | character data outside the document element |

Namespace prefixes resolve against a scope stack, so a prefix declared on
an **ancestor** works exactly as a real parser would treat it.

**Fields must be what they claim.**

Seller name non-empty; VAT number 15 digits starting and ending with `3`;
amounts non-negative integer halalas; and VAT never exceeds the
VAT-**inclusive** total (tag 4 contains tag 5 — an auditor's first
recomputation). Timestamps are real instants, not merely well-shaped
strings: `2026-99-99T99:99:99` and `2026-02-30` are rejected, and a
`Date` is rendered as **Arabia Standard Time** wall clock, never as UTC
digits with the `Z` deleted — that silently shifts every invoice three
hours.

**Onboarding data you cannot fix later.**

The EGS serial is baked into the CSID, so it must be exactly three
pipe-free components (`1-…|2-…|3-…`), each with real content — a CSR of
spaces is structurally perfect and identifies nobody, so every required
field is checked after trimming. `countryName` is checked against
the real ISO 3166-1 alpha-2 list, not "any two capitals" — `ZZ` exists
nowhere. And a VAT number whose **11th digit is `1`** is a VAT-group
registration: its `organizationUnitName` must be the member's own
10-digit TIN, detected from the number itself rather than left to a flag
the caller has to remember.

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
- **Fails closed, always** — an outcome is a success only on positive
  evidence. Ambiguity, unreadable payloads and self-contradicting
  responses all resolve to "not proven", never to "probably fine".
  > In plain words: when ZATCA's answer is unclear, this library says
  > "not filed" rather than "filed". Getting that backwards is the
  > expensive direction: an invoice wrongly marked *reported* is
  > forgotten forever and surfaces as a penalty at audit, while one
  > wrongly marked *pending* just gets retried a minute later. Every
  > check in the section above picks the recoverable failure.
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
