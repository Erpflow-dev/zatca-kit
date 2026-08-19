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
    return date;
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

/** Phase-2 (integration) QR payload — BR-KSA-27. Tag 9 rides only when
 * provided (simplified invoices); standard invoices omit it. */
export function buildPhase2Qr(fields: Phase2Fields): string {
  // Tag 8 must be the COMPLETE DER SubjectPublicKeyInfo — 88 bytes for
  // secp256k1, starting with a DER SEQUENCE (0x30). Accepting anything
  // shorter (the bare 65-byte point is the classic mistake) rebuilds the
  // exact tag-8 compliance failure this field's docs warn about, so it
  // fails here instead of inside ZATCA's validator.
  const pk = fields.publicKeyBytes;
  if (pk.length !== 88 || pk[0] !== 0x30) {
    throw new TypeError(
      `publicKeyBytes must be the full 88-byte DER SubjectPublicKeyInfo ` +
        `for secp256k1 (starts 0x30), got ${pk.length} byte(s)` +
        (pk.length > 0 ? ` starting 0x${pk[0].toString(16)}` : ''),
    );
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
