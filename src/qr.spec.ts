import {
  buildPhase1Qr,
  buildPhase2Qr,
  formatQrTimestamp,
  halalasToSar,
} from './qr';

/**
 * Vectors mirror the Flutter till's zatca_qr_test.dart exactly — the two
 * implementations must stay bit-identical or the same sale prints different
 * QRs depending on which side generated the receipt.
 */

function decodeTlv(b64: string): Map<number, Buffer> {
  const bytes = Buffer.from(b64, 'base64');
  const tags = new Map<number, Buffer>();
  let i = 0;
  while (i < bytes.length) {
    const tag = bytes[i];
    const len = bytes[i + 1];
    tags.set(tag, bytes.subarray(i + 2, i + 2 + len));
    i += 2 + len;
  }
  return tags;
}

describe('buildPhase1Qr', () => {
  /**
   * Full-QR byte lock in the LIVE-VERIFIED tag-3 format: seconds, no
   * millis, NO Z (the phase-2 KSA-25 cross-check rejects a Z with
   * invoiceTimeStamp_QRCODE_INVALID; ZATCA's own SDK emits none —
   * proven against the live simulation gateway 2026-08-19). ZATCA's
   * PUBLISHED phase-1 sample carries a Z; the live validator disagrees
   * with the sample and wins. Fields otherwise mirror that sample.
   */
  it('byte-matches the live-verified sample QR encoding', () => {
    const b64 = buildPhase1Qr({
      sellerName: 'Bobs Records',
      vatNumber: '310122393500003',
      timestamp: '2022-04-25T15:30:00',
      totalWithVatHalalas: 100000,
      vatHalalas: 15000,
    });
    expect(b64).toBe(
      'AQxCb2JzIFJlY29yZHMCDzMxMDEyMjM5MzUwMDAwMwMTMjAyMi0wNC0yNVQxNTozMD' +
        'owMAQHMTAwMC4wMAUGMTUwLjAw',
    );
  });

  it('golden: known invoice encodes to expected TLV structure', () => {
    const b64 = buildPhase1Qr({
      sellerName: 'Bobs Records',
      vatNumber: '310122393500003',
      timestamp: '2022-04-25T15:30:00',
      totalWithVatHalalas: 100000,
      vatHalalas: 15000,
    });
    const tags = decodeTlv(b64);
    expect(tags.get(1)?.toString('utf8')).toBe('Bobs Records');
    expect(tags.get(2)?.toString('utf8')).toBe('310122393500003');
    // 19 bytes: seconds precision, no millis, NO Z (live KSA-25 form).
    expect(tags.get(3)?.toString('utf8')).toBe('2022-04-25T15:30:00');
    expect(tags.get(4)?.toString('utf8')).toBe('1000.00');
    expect(tags.get(5)?.toString('utf8')).toBe('150.00');
    expect(tags.size).toBe(5);
  });

  it('formatQrTimestamp renders a Date as AST wall clock (UTC+3), never as bare UTC digits', () => {
    // 10:00 UTC = 13:00 in Riyadh. Emitting '10:00:00' without a zone
    // suffix would be read by ZATCA as 10:00 AST — three hours wrong.
    expect(formatQrTimestamp(new Date('2022-04-25T10:00:00.123Z'))).toBe(
      '2022-04-25T13:00:00',
    );
    // Same instant given with a +03:00 offset: identical AST output.
    expect(formatQrTimestamp(new Date('2022-04-25T13:00:00+03:00'))).toBe(
      '2022-04-25T13:00:00',
    );
  });

  it('formatQrTimestamp passes a string through VERBATIM (byte-equal to the XML IssueDate/IssueTime)', () => {
    expect(formatQrTimestamp('2022-04-25T15:30:00')).toBe(
      '2022-04-25T15:30:00',
    );
  });

  it('formatQrTimestamp rejects malformed strings and zone suffixes', () => {
    for (const bad of [
      '2022-04-25 15:30:00',
      '2022-04-25T15:30:00Z',
      '2022-04-25T15:30:00+03:00',
      '2022-04-25T15:30',
      'yesterday',
    ]) {
      expect(() => formatQrTimestamp(bad)).toThrow(TypeError);
    }
  });

  it('Arabic seller name survives UTF-8 round trip', () => {
    const name = 'سوبرماركت التجربة';
    const b64 = buildPhase1Qr({
      sellerName: name,
      vatNumber: '310000000000003',
      timestamp: new Date(Date.UTC(2026, 0, 1)),
      totalWithVatHalalas: 2550,
      vatHalalas: 333,
    });
    expect(decodeTlv(b64).get(1)?.toString('utf8')).toBe(name);
  });

  it('rejects a payload past ZATCA\'s 700-char QR ceiling', () => {
    // 200 ASCII chars fit one TLV byte length but push the base64 QR past
    // 700 — structurally valid, compliance-invalid, so the builder throws.
    expect(() =>
      buildPhase2Qr({
        sellerName: 'S'.repeat(200),
        vatNumber: '310122393500003',
        timestamp: '2022-04-25T15:30:00',
        totalWithVatHalalas: 100000,
        vatHalalas: 15000,
        invoiceHashBase64: 'a'.repeat(44),
        signatureBase64: 'b'.repeat(96),
        publicKeyBytes: fakeSpki(),
        certificateSignature: new Uint8Array(72),
      }),
    ).toThrow(RangeError);
  });

  it('rejects a seller name whose UTF-8 exceeds one TLV byte length', () => {
    expect(() =>
      buildPhase1Qr({
        sellerName: 'م'.repeat(200), // 400 UTF-8 bytes
        vatNumber: '3',
        timestamp: new Date(),
        totalWithVatHalalas: 0,
        vatHalalas: 0,
      }),
    ).toThrow(RangeError);
  });
});

describe('halalasToSar', () => {
  it.each([
    [5, '0.05'],
    [0, '0.00'],
    [2550, '25.50'],
    [100000, '1000.00'],
    [-125, '-1.25'],
  ])('%i halalas → %s', (halalas, expected) => {
    expect(halalasToSar(halalas)).toBe(expected);
  });

  it('refuses non-integer amounts — money never floats', () => {
    expect(() => halalasToSar(25.5)).toThrow(TypeError);
  });

  it('refuses unsafe integers — precision is already gone past 2^53', () => {
    expect(() => halalasToSar(Number.MAX_SAFE_INTEGER + 1)).toThrow(TypeError);
    expect(halalasToSar(Number.MAX_SAFE_INTEGER)).toMatch(/\.\d{2}$/);
  });
});

describe('buildPhase2Qr', () => {
  it('adds tags 6-7 as base64 STRINGS and 8-9 as RAW bytes', () => {
    const publicKeyBytes = fakeSpki();
    const certificateSignature = Uint8Array.from([48, 68, 2, 32]);
    const b64 = buildPhase2Qr({
      sellerName: 'Bobs Records',
      vatNumber: '310122393500003',
      timestamp: '2022-04-25T15:30:00',
      totalWithVatHalalas: 100000,
      vatHalalas: 15000,
      invoiceHashBase64: 'aGFzaA==',
      signatureBase64: 'c2ln',
      publicKeyBytes,
      certificateSignature,
    });
    const tags = decodeTlv(b64);
    expect(tags.size).toBe(9);
    // 6-7: the base64 text itself is the value…
    expect(tags.get(6)?.toString('utf8')).toBe('aGFzaA==');
    expect(tags.get(7)?.toString('utf8')).toBe('c2ln');
    // …8-9: raw bytes, NOT base64 text (the documented asymmetry).
    expect([...(tags.get(8) ?? [])]).toEqual([...publicKeyBytes]);
    expect([...(tags.get(9) ?? [])]).toEqual([...certificateSignature]);
  });

  it('omits tag 9 when no certificate signature (standard invoices)', () => {
    const b64 = buildPhase2Qr({
      sellerName: 'Bobs Records',
      vatNumber: '310122393500003',
      timestamp: '2022-04-25T15:30:00',
      totalWithVatHalalas: 100000,
      vatHalalas: 15000,
      invoiceHashBase64: 'aGFzaA==',
      signatureBase64: 'c2ln',
      publicKeyBytes: fakeSpki(),
    });
    const tags = decodeTlv(b64);
    expect(tags.size).toBe(8);
    expect(tags.has(9)).toBe(false);
  });

  it('rejects tag-8 input that is not a full 88-byte DER SPKI', () => {
    const base = {
      sellerName: 'Bobs Records',
      vatNumber: '310122393500003',
      timestamp: '2022-04-25T15:30:00',
      totalWithVatHalalas: 100000,
      vatHalalas: 15000,
      invoiceHashBase64: 'aGFzaA==',
      signatureBase64: 'c2ln',
    };
    // Four arbitrary bytes — the case that recreated the tag-8 failure.
    expect(() =>
      buildPhase2Qr({ ...base, publicKeyBytes: Uint8Array.from([4, 1, 2, 3]) }),
    ).toThrow(TypeError);
    // The bare 65-byte EC point (the classic mistake — right key, wrong form).
    const barePoint = new Uint8Array(65);
    barePoint[0] = 0x04;
    expect(() =>
      buildPhase2Qr({ ...base, publicKeyBytes: barePoint }),
    ).toThrow(TypeError);
    // 88 bytes but not DER (no leading SEQUENCE tag).
    expect(() =>
      buildPhase2Qr({ ...base, publicKeyBytes: new Uint8Array(88) }),
    ).toThrow(TypeError);
    // Correct shape passes.
    expect(() =>
      buildPhase2Qr({ ...base, publicKeyBytes: fakeSpki() }),
    ).not.toThrow();
  });
});

/** 88 bytes shaped like a secp256k1 SPKI: DER SEQUENCE header + filler. */
function fakeSpki(): Uint8Array {
  const b = new Uint8Array(88);
  b[0] = 0x30;
  b[1] = 0x56;
  return b;
}
