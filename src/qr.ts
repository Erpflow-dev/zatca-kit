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

import { createPublicKey, createVerify, type KeyObject } from 'node:crypto';
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
  // Tags 1-5 are MANDATORY content, not just mandatory slots: a QR with
  // an empty seller name or a malformed VAT number is a non-compliant
  // receipt, and nothing catches it until an inspection months later.
  if (f.sellerName.trim().length === 0) {
    throw new TypeError('sellerName is required (tag 1)');
  }
  if (!/^3\d{13}3$/.test(f.vatNumber)) {
    throw new TypeError(
      `vatNumber must be 15 digits starting and ending with 3 (tag 2), ` +
        `got '${f.vatNumber}'`,
    );
  }
  // Credit notes carry POSITIVE amounts and reference the original
  // invoice, so a negative total on a QR is always a caller bug.
  for (const [label, amount] of [
    ['totalWithVatHalalas', f.totalWithVatHalalas],
    ['vatHalalas', f.vatHalalas],
  ] as const) {
    if (!Number.isSafeInteger(amount) || amount < 0) {
      throw new TypeError(
        `${label} must be a non-negative integer of halalas, got ${amount}`,
      );
    }
  }
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
function parseTag8Key(bytes: Uint8Array): KeyObject {
  const input = Buffer.from(bytes);
  // The CONTRACT is the canonical 88-byte UNCOMPRESSED SPKI:
  //   30 56 | AlgorithmIdentifier(18) | 03 42 00 | 04 ‖ X(32) ‖ Y(32)
  // A compressed point (56 bytes, 02/03 marker) is a valid secp256k1 key
  // that Node parses AND round-trips unchanged, so neither parsing nor a
  // re-export comparison can catch it — only an explicit shape check.
  if (input.length !== 88 || input[0] !== 0x30 || input[23] !== 0x04) {
    throw new TypeError(
      `publicKeyBytes must be the canonical 88-byte uncompressed DER ` +
        `SubjectPublicKeyInfo (point marker 0x04), got ${input.length} ` +
        `byte(s)${input.length > 23 ? ` with marker 0x${input[23].toString(16)}` : ''}`,
    );
  }
  let key: KeyObject;
  try {
    key = createPublicKey({ key: input, format: 'der', type: 'spki' });
  } catch (err) {
    throw new TypeError(
      `publicKeyBytes (${bytes.length} bytes) is not a parseable DER ` +
        `SubjectPublicKeyInfo: ${(err as Error).message}`,
    );
  }
  if (key.asymmetricKeyDetails?.namedCurve !== 'secp256k1') {
    throw new TypeError(
      `publicKeyBytes must be a secp256k1 public key, got ` +
        `${key.asymmetricKeyDetails?.namedCurve ?? 'a non-EC key'}`,
    );
  }
  // Parseable + right curve is still not the CONTRACT: tag 8 is the
  // canonical 88-byte UNCOMPRESSED SPKI. A compressed point (0x02/0x03,
  // 56 bytes) parses fine and names the same curve, yet is not the form
  // the field documents or that verifiers expect. Re-exporting and
  // comparing enforces the canonical encoding in one step.
  const canonical = key.export({ type: 'spki', format: 'der' });
  if (!canonical.equals(input)) {
    throw new TypeError(
      `publicKeyBytes must be the canonical 88-byte uncompressed DER ` +
        `SubjectPublicKeyInfo; got a ${bytes.length}-byte non-canonical ` +
        `encoding (compressed point?)`,
    );
  }
  return key;
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
  const key = parseTag8Key(fields.publicKeyBytes);
  // THE check that makes tags 6-8 a proof instead of three unrelated
  // blobs: the signature must actually verify over the invoice hash
  // under this key. Individually-valid fields from different invoices
  // or different terminals produce a QR that every offline verifier
  // rejects — and nothing else in the pipeline catches it.
  if (!createVerify('sha256').update(hash).verify(key, signature)) {
    throw new TypeError(
      'signatureBase64 does not verify over invoiceHashBase64 with ' +
        'publicKeyBytes — tags 6, 7 and 8 belong to different invoices ' +
        'or different keys',
    );
  }
  if (fields.certificateSignature !== undefined) {
    // Tag 9 is the CA's DER ECDSA signature over the CSID certificate.
    // It cannot be verified without the issuer's key, but a malformed
    // DER value (`30 00` and friends) is detectable and never valid.
    if (!isDerEcdsaSignature(Buffer.from(fields.certificateSignature))) {
      throw new TypeError(
        `certificateSignature must be a DER ECDSA signature (tag 9), got ` +
          `${fields.certificateSignature.length} bytes`,
      );
    }
  }
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
