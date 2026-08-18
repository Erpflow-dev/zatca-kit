/**
 * ZATCA e-invoicing QR payloads — TLV over base64.
 *
 * PHASE 1 (generation, mandatory since 2021-12-04): tags 1–5, generated
 * fully offline at print time. No CSID, no signing, no reporting — for many
 * small tenants this is ALL of ZATCA compliance. Structure per tag:
 * [tag: 1 byte][length: 1 byte][UTF-8 value], concatenated then base64d.
 *
 *   1 seller name        2 VAT number          3 ISO-8601 UTC timestamp
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
  /** Invoice issue time; encoded as UTC ISO-8601. */
  timestamp: Date;
  totalWithVatHalalas: number;
  vatHalalas: number;
}

export interface Phase2Fields extends Phase1Fields {
  /** base64 SHA-256 of the canonicalized invoice XML. */
  invoiceHashBase64: string;
  /** base64 ECDSA signature over the invoice hash. */
  signatureBase64: string;
  /** Raw secp256k1 public key bytes (uncompressed point). */
  publicKeyBytes: Uint8Array;
  /** Raw ECDSA signature bytes from the CSID certificate. */
  certificateSignature: Uint8Array;
}

/** "2550" halalas → "25.50" (ZATCA wants decimal SAR with 2 places). */
export function halalasToSar(halalas: number): string {
  if (!Number.isInteger(halalas)) {
    throw new TypeError(`halalas must be an integer, got ${halalas}`);
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
    tlv(3, utf8(f.timestamp.toISOString())),
    tlv(4, utf8(halalasToSar(f.totalWithVatHalalas))),
    tlv(5, utf8(halalasToSar(f.vatHalalas))),
  ];
}

/** Phase-1 (generation) QR payload — all a phase-1 tenant needs. */
export function buildPhase1Qr(fields: Phase1Fields): string {
  return Buffer.concat(phase1Tlvs(fields)).toString('base64');
}

/** Phase-2 (integration) QR payload — BR-KSA-27, simplified invoices. */
export function buildPhase2Qr(fields: Phase2Fields): string {
  return Buffer.concat([
    ...phase1Tlvs(fields),
    tlv(6, utf8(fields.invoiceHashBase64)),
    tlv(7, utf8(fields.signatureBase64)),
    tlv(8, fields.publicKeyBytes),
    tlv(9, fields.certificateSignature),
  ]).toString('base64');
}
