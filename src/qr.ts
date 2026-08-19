/**
 * ZATCA e-invoicing QR payloads — TLV over base64.
 *
 * PHASE 1 (generation, mandatory since 2021-12-04): tags 1–5, generated
 * fully offline at print time. No CSID, no signing, no reporting — for many
 * small tenants this is ALL of ZATCA compliance. Structure per tag:
 * [tag: 1 byte][length: 1 byte][UTF-8 value], concatenated then base64d.
 *
 *   1 seller name        2 VAT number          3 timestamp (AST, no zone)
 *   4 total with VAT     5 VAT amount          (amounts as "25.50" strings)
 *
 * PHASE 2 (integration) reuses tags 1–5 and adds the cryptographic stamp:
 *   6 invoice hash (the base64 STRING as bytes)
 *   7 ECDSA signature (the base64 STRING as bytes)
 *   8 secp256k1 public key (RAW bytes)
 *   9 certificate signature (RAW bytes) — simplified invoices only
 * Tags 6–7 carry base64 strings re-encoded as UTF-8 bytes while 8–9 carry
 * raw bytes — a documented asymmetry verified against ZATCA's reference
 * implementations; getting it backwards fails BR-KSA-27 QR validation.
 *
 * Amounts are integer halalas in, decimal-SAR strings out — money never
 * touches floating point.
 */

import { createPublicKey } from 'node:crypto';
import { decodeBase64Strict } from './base64';

export interface Phase1Fields {
  sellerName: string;
  vatNumber: string;
  /**
   * Invoice issue time. PREFER the string form: the exact
   * `IssueDate + 'T' + IssueTime` from the invoice XML, passed through
   * verbatim — tag 3 must be byte-equal to the XML (KSA-25), and only the
   * caller knows the XML's wall-clock time. A `Date` is converted to
   * Arabia Standard Time (UTC+3, no DST) — NOT to UTC: ZATCA reads a
   * suffix-less timestamp as Saudi local time, so emitting shifted UTC
   * digits without the `Z` would corrupt the time by three hours.
   */
  timestamp: Date | string;
  totalWithVatHalalas: number;
  vatHalalas: number;
}

export interface Phase2Fields extends Phase1Fields {
  /** base64 SHA-256 of the canonicalized invoice XML. */
  invoiceHashBase64: string;
  /** base64 ECDSA signature over the invoice hash. */
  signatureBase64: string;
  /**
   * FULL DER SubjectPublicKeyInfo bytes (88 for secp256k1) — exactly what
   * parseCertificate().publicKeyBytes returns. NOT the bare 65-byte point.
   */
  publicKeyBytes: Uint8Array;
  /**
   * Raw ECDSA signature bytes from the CSID certificate — tag 9, required
   * on SIMPLIFIED (B2C) invoices only; omit for standard (B2B).
   */
  certificateSignature?: Uint8Array;
}

/**
 * QR tag 3 timestamp: `2022-04-25T15:30:00` — seconds precision, NO
 * milliseconds, NO `Z`. Live-verified 2026-08-19 against the simulation
 * gateway: the Phase-2 KSA-25 cross-check wants tag 3 byte-equal to
 * `IssueDate + 'T' + IssueTime`, and a `Z` suffix draws
 * `invoiceTimeStamp_QRCODE_INVALID`; ZATCA's own SDK emits no Z. Note
 * the trap: ZATCA's PUBLISHED phase-1 sample carries a Z — the published
 * sample and the live validator disagree, and the live validator wins.
 *
 * A suffix-less timestamp is read as SAUDI LOCAL TIME (AST, UTC+3), so a
 * `Date` is rendered as AST wall-clock digits — never as UTC digits with
 * the Z merely deleted (that would silently shift the time by 3 hours).
 * A string is the caller's own `IssueDate + 'T' + IssueTime` and passes
 * through verbatim after a format check, keeping tag 3 byte-equal to the
 * invoice XML.
 */
export function formatQrTimestamp(date: Date | string): string {
  if (typeof date === 'string') {
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/.test(date)) {
      throw new TypeError(
        `timestamp string must be YYYY-MM-DDTHH:mm:ss (no zone suffix, ` +
          `exactly the XML IssueDate + 'T' + IssueTime), got '${date}'`,
      );
    }
    // Shape is not existence: '2026-99-99T99:99:99' and '2026-02-30T…'
    // both match the pattern. Round-trip through the calendar so only
    // real instants reach tag 3.
    const [y, mo, d, h, mi, s] = date.split(/[-T:]/).map(Number);
    const probe = new Date(Date.UTC(y, mo - 1, d, h, mi, s));
    if (
      probe.getUTCFullYear() !== y ||
      probe.getUTCMonth() !== mo - 1 ||
      probe.getUTCDate() !== d ||
      probe.getUTCHours() !== h ||
      probe.getUTCMinutes() !== mi ||
      probe.getUTCSeconds() !== s
    ) {
      throw new TypeError(`timestamp '${date}' is not a real date and time`);
    }
    return date;
  }
  if (Number.isNaN(date.getTime())) {
    throw new TypeError('timestamp Date is Invalid Date');
  }
  // AST = UTC+3, permanently (Saudi Arabia has no DST).
  const ast = new Date(date.getTime() + 3 * 3_600_000);
  return ast.toISOString().replace(/\.\d{3}Z$/, '');
}

/** "2550" halalas → "25.50" (ZATCA wants decimal SAR with 2 places). */
export function halalasToSar(halalas: number): string {
  // isSafeInteger, not isInteger: past 2^53 JS has ALREADY silently
  // rounded the halalas — the money is wrong before we ever format it.
  if (!Number.isSafeInteger(halalas)) {
    throw new TypeError(`halalas must be a safe integer, got ${halalas}`);
  }
  const sign = halalas < 0 ? '-' : '';
  const abs = Math.abs(halalas);
  return `${sign}${Math.floor(abs / 100)}.${String(abs % 100).padStart(2, '0')}`;
}

function tlv(tag: number, value: Uint8Array): Buffer {
  if (value.length > 255) {
    throw new RangeError(
      `TLV tag ${tag} value is ${value.length} bytes — exceeds one-byte length`,
    );
  }
  return Buffer.concat([Buffer.from([tag, value.length]), value]);
}

const utf8 = (s: string): Uint8Array => Buffer.from(s, 'utf8');

function phase1Tlvs(f: Phase1Fields): Buffer[] {
  return [
    tlv(1, utf8(f.sellerName)),
    tlv(2, utf8(f.vatNumber)),
    tlv(3, utf8(formatQrTimestamp(f.timestamp))),
    tlv(4, utf8(halalasToSar(f.totalWithVatHalalas))),
    tlv(5, utf8(halalasToSar(f.vatHalalas))),
  ];
}

/**
 * ZATCA's ceiling on the whole encoded QR payload (technical guideline):
 * past it the QR is structurally fine but non-compliant, so builders
 * throw rather than hand back something a validator will reject.
 */
export const QR_MAX_CHARS = 700;

function encodeQr(parts: Buffer[]): string {
  const b64 = Buffer.concat(parts).toString('base64');
  if (b64.length > QR_MAX_CHARS) {
    throw new RangeError(
      `QR payload is ${b64.length} base64 chars — ZATCA caps it at ${QR_MAX_CHARS}. ` +
        'Shorten the seller name (tag 1 is the usual culprit).',
    );
  }
  return b64;
}

/** Phase-1 (generation) QR payload — all a phase-1 tenant needs. */
export function buildPhase1Qr(fields: Phase1Fields): string {
  return encodeQr(phase1Tlvs(fields));
}

/**
 * Tag 8 must be the COMPLETE DER SubjectPublicKeyInfo for the secp256k1
 * CSID key — 88 bytes for that curve. Length and a leading 0x30 only
 * prove "88 bytes of something DER-shaped"; the compliance failure this
 * guards against is a WRONG KEY, so the bytes are actually parsed and
 * the curve checked. (The bare 65-byte point is the classic mistake.)
 */
function assertSecp256k1Spki(bytes: Uint8Array): void {
  let namedCurve: string | undefined;
  try {
    namedCurve = createPublicKey({
      key: Buffer.from(bytes),
      format: 'der',
      type: 'spki',
    }).asymmetricKeyDetails?.namedCurve;
  } catch (err) {
    throw new TypeError(
      `publicKeyBytes (${bytes.length} bytes) is not a parseable DER ` +
        `SubjectPublicKeyInfo: ${(err as Error).message}`,
    );
  }
  if (namedCurve !== 'secp256k1') {
    throw new TypeError(
      `publicKeyBytes must be a secp256k1 public key, got ` +
        `${namedCurve ?? 'a non-EC key'}`,
    );
  }
}

/**
 * DER ECDSA signature: `SEQUENCE { INTEGER r, INTEGER s }`. Tag 7 carries
 * the base64 of exactly these bytes; anything else is a signature ZATCA
 * cannot verify, so it must never reach a printed receipt.
 */
function isDerEcdsaSignature(sig: Buffer): boolean {
  if (sig.length < 8 || sig[0] !== 0x30) return false;
  const seqLen = sig[1];
  // ECDSA-P256K signatures are ~70-72 bytes: always DER short form.
  if (seqLen & 0x80 || seqLen !== sig.length - 2) return false;
  let off = 2;
  for (let i = 0; i < 2; i += 1) {
    if (sig[off] !== 0x02) return false; // INTEGER tag
    const len = sig[off + 1];
    if (len === 0 || len & 0x80) return false;
    off += 2 + len;
    if (off > sig.length) return false;
  }
  return off === sig.length;
}

/** Phase-2 (integration) QR payload — BR-KSA-27. Tag 9 rides only when
 * provided (simplified invoices); standard invoices omit it. */
export function buildPhase2Qr(fields: Phase2Fields): string {
  // Tags 6-8 are the cryptographic proof a verifier re-checks offline.
  // Each is validated for what it must BE, not merely that it is a
  // non-empty string: a QR that carries garbage here prints fine and
  // fails at the auditor's scanner, long after the sale.
  const hash = decodeBase64Strict(
    fields.invoiceHashBase64,
    'invoiceHashBase64',
  );
  if (hash.length !== 32) {
    throw new TypeError(
      `invoiceHashBase64 must decode to 32 SHA-256 bytes, got ${hash.length}`,
    );
  }
  const signature = decodeBase64Strict(
    fields.signatureBase64,
    'signatureBase64',
  );
  if (!isDerEcdsaSignature(signature)) {
    throw new TypeError(
      `signatureBase64 must decode to a DER ECDSA signature ` +
        `(SEQUENCE of two INTEGERs), got ${signature.length} bytes`,
    );
  }
  assertSecp256k1Spki(fields.publicKeyBytes);
  return encodeQr([
    ...phase1Tlvs(fields),
    tlv(6, utf8(fields.invoiceHashBase64)),
    tlv(7, utf8(fields.signatureBase64)),
    tlv(8, fields.publicKeyBytes),
    ...(fields.certificateSignature
      ? [tlv(9, fields.certificateSignature)]
      : []),
  ]);
}
