import {
  createHash,
  createPublicKey,
  createSign,
  generateKeyPairSync,
} from 'node:crypto';
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

  it('formatQrTimestamp rejects well-shaped strings that are not real instants', () => {
    // Right shape, impossible calendar values — a regex alone passes these.
    for (const bad of [
      '2026-99-99T99:99:99',
      '2026-02-30T10:00:00',
      '2026-13-01T10:00:00',
      '2026-01-01T24:00:00',
      '2026-01-01T10:60:00',
    ]) {
      expect(() => formatQrTimestamp(bad)).toThrow(TypeError);
    }
    // Leap day in a real leap year still passes.
    expect(formatQrTimestamp('2028-02-29T10:00:00')).toBe(
      '2028-02-29T10:00:00',
    );
  });

  it('formatQrTimestamp rejects an Invalid Date instead of throwing RangeError deep inside', () => {
    expect(() => formatQrTimestamp(new Date('nope'))).toThrow(TypeError);
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
        ...signedTriple(),
        certificateSignature: derSig(),
      }),
    ).toThrow(RangeError);
  });

  it('rejects a seller name whose UTF-8 exceeds one TLV byte length', () => {
    expect(() =>
      buildPhase1Qr({
        sellerName: 'م'.repeat(200), // 400 UTF-8 bytes
        vatNumber: '310122393500003',
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
    const { publicKeyBytes, invoiceHashBase64, signatureBase64 } =
      signedTriple();
    const certificateSignature = derSig();
    const b64 = buildPhase2Qr({
      sellerName: 'Bobs Records',
      vatNumber: '310122393500003',
      timestamp: '2022-04-25T15:30:00',
      totalWithVatHalalas: 100000,
      vatHalalas: 15000,
      invoiceHashBase64,
      signatureBase64,
      publicKeyBytes,
      certificateSignature,
    });
    const tags = decodeTlv(b64);
    expect(tags.size).toBe(9);
    // 6-7: the base64 text itself is the value…
    expect(tags.get(6)?.toString('utf8')).toBe(invoiceHashBase64);
    expect(tags.get(7)?.toString('utf8')).toBe(signatureBase64);
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
      ...signedTriple(),
    });
    const tags = decodeTlv(b64);
    expect(tags.size).toBe(8);
    expect(tags.has(9)).toBe(false);
  });

  it('rejects tag-8 input that is not a full 88-byte DER SPKI', () => {
    const signed = signedTriple();
    const base = {
      sellerName: 'Bobs Records',
      vatNumber: '310122393500003',
      timestamp: '2022-04-25T15:30:00',
      totalWithVatHalalas: 100000,
      vatHalalas: 15000,
      invoiceHashBase64: signed.invoiceHashBase64,
      signatureBase64: signed.signatureBase64,
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
    // THE hole a length+first-byte check cannot see: 88 bytes that open
    // with a DER SEQUENCE header and are otherwise filler. Only actually
    // parsing the key rejects this.
    const fakeSpki = new Uint8Array(88);
    fakeSpki[0] = 0x30;
    fakeSpki[1] = 0x56;
    expect(() =>
      buildPhase2Qr({ ...base, publicKeyBytes: fakeSpki }),
    ).toThrow(TypeError);
    // A real key on the WRONG curve is still wrong (P-256 ≠ secp256k1).
    // Its SPKI is 91 bytes, so the canonical-form check fires first —
    // either way the key never reaches a receipt.
    const p256 = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
      .publicKey.export({ type: 'spki', format: 'der' });
    expect(() => buildPhase2Qr({ ...base, publicKeyBytes: p256 })).toThrow(
      /secp256k1|canonical 88-byte/,
    );
    // The genuine article — the key that actually made the signature.
    expect(() =>
      buildPhase2Qr({ ...base, publicKeyBytes: signed.publicKeyBytes }),
    ).not.toThrow();
  });

  it('rejects tag-6/7 payloads that are not a real hash and DER signature', () => {
    const signed = signedTriple();
    const base = {
      sellerName: 'Bobs Records',
      vatNumber: '310122393500003',
      timestamp: '2022-04-25T15:30:00',
      totalWithVatHalalas: 100000,
      vatHalalas: 15000,
      publicKeyBytes: signed.publicKeyBytes,
    };
    const goodHash = signed.invoiceHashBase64;
    const goodSig = signed.signatureBase64;

    // Tag 6 must decode canonically to 32 SHA-256 bytes.
    for (const badHash of [
      'not-base64!!!',
      'QUJD', // valid base64, 3 bytes
      'a'.repeat(44), // 44 chars → 33 bytes, the old fixture's shape
      goodHash.slice(0, -1), // broken padding
    ]) {
      expect(() =>
        buildPhase2Qr({ ...base, invoiceHashBase64: badHash, signatureBase64: goodSig }),
      ).toThrow(TypeError);
    }

    // Tag 7 must decode to a DER ECDSA SEQUENCE of two INTEGERs.
    for (const badSig of [
      'not-base64!!!',
      'c2ln', // 3 arbitrary bytes
      'b'.repeat(96), // right length, wrong structure
      Buffer.from([0x30, 0x06, 0x02, 0x01, 0x01]).toString('base64'), // truncated
    ]) {
      expect(() =>
        buildPhase2Qr({ ...base, invoiceHashBase64: goodHash, signatureBase64: badSig }),
      ).toThrow(TypeError);
    }

    expect(() =>
      buildPhase2Qr({ ...base, invoiceHashBase64: goodHash, signatureBase64: goodSig }),
    ).not.toThrow();
  });
});

describe('buildPhase2Qr cryptographic linkage', () => {
  const base = {
    sellerName: 'Bobs Records',
    vatNumber: '310122393500003',
    timestamp: '2022-04-25T15:30:00',
    totalWithVatHalalas: 100000,
    vatHalalas: 15000,
  };

  it('refuses a signature from a DIFFERENT key than tag 8', () => {
    const mine = signedTriple();
    const other = signedTriple();
    // Every field individually valid; the QR still cannot be verified
    // by anyone, because tag 7 was not made by tag 8's key.
    expect(() =>
      buildPhase2Qr({
        ...base,
        invoiceHashBase64: mine.invoiceHashBase64,
        signatureBase64: other.signatureBase64,
        publicKeyBytes: mine.publicKeyBytes,
      }),
    ).toThrow(/does not verify/);
  });

  it('refuses a signature over a DIFFERENT invoice hash', () => {
    const a = signedTriple('invoice-A');
    const b = signedTriple('invoice-B');
    expect(() =>
      buildPhase2Qr({
        ...base,
        invoiceHashBase64: b.invoiceHashBase64,
        signatureBase64: a.signatureBase64,
        publicKeyBytes: a.publicKeyBytes,
      }),
    ).toThrow(/does not verify/);
  });

  it('refuses a COMPRESSED SPKI — tag 8 is the canonical 88-byte form', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
      namedCurve: 'secp256k1',
    });
    const hash = createHash('sha256').update('invoice').digest();
    const signer = createSign('sha256');
    signer.update(hash);
    // Node cannot EXPORT a compressed SPKI, so build one: same key, same
    // curve, valid DER — but the 56-byte compressed-point encoding
    // instead of the 88-byte uncompressed form the field documents.
    const spki = publicKey.export({ type: 'spki', format: 'der' });
    const algorithm = spki.subarray(2, 20); // AlgorithmIdentifier
    const x = spki.subarray(24, 56);
    const y = spki.subarray(56, 88);
    const point = Buffer.concat([
      Buffer.from([(y[31] & 1) === 1 ? 0x03 : 0x02]),
      x,
    ]);
    const compressed = Buffer.concat([
      Buffer.from([0x30, 0x36]),
      algorithm,
      Buffer.from([0x03, 0x22, 0x00]),
      point,
    ]);
    expect(compressed.length).toBe(56);
    expect(() =>
      buildPhase2Qr({
        ...base,
        invoiceHashBase64: hash.toString('base64'),
        signatureBase64: signer.sign(privateKey).toString('base64'),
        publicKeyBytes: compressed,
      }),
      // Rejected either way: Node may refuse to parse it, or our
      // canonical re-export comparison catches it.
    ).toThrow(/canonical 88-byte uncompressed|not a parseable DER/);
  });

  it('refuses a malformed tag-9 certificate signature', () => {
    const signed = signedTriple();
    for (const bad of [
      Uint8Array.from([0x30, 0x00]), // the reported case
      Uint8Array.from([0x30, 0x44, 0x02, 0x20]), // truncated
      new Uint8Array(72), // right length, all zeros
      // Well-formed DER, mathematically impossible: r = 0, s = 0.
      Uint8Array.from([0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]),
      // r valid, s = 0.
      Uint8Array.from([0x30, 0x06, 0x02, 0x01, 0x07, 0x02, 0x01, 0x00]),
      // Negative r (high bit set with no 0x00 pad).
      Uint8Array.from([0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x07]),
      // Non-minimal encoding: a 0x00 pad that clears nothing.
      Uint8Array.from([0x30, 0x08, 0x02, 0x02, 0x00, 0x07, 0x02, 0x02, 0x00, 0x07]),
      // r == n (the curve order): well-formed DER, but r must be < n.
      derSigWithR(SECP256K1_N),
      // r > n.
      derSigWithR(SECP256K1_N + 1n),
    ]) {
      expect(() =>
        buildPhase2Qr({ ...base, ...signed, certificateSignature: bad }),
      ).toThrow(/certificateSignature/);
    }
    expect(() =>
      buildPhase2Qr({ ...base, ...signed, certificateSignature: derSig() }),
    ).not.toThrow();
  });
});

describe('QR mandatory fields (tags 1-5)', () => {
  const ok = {
    sellerName: 'Bobs Records',
    vatNumber: '310122393500003',
    timestamp: '2022-04-25T15:30:00',
    totalWithVatHalalas: 100000,
    vatHalalas: 15000,
  };

  it('rejects an empty or blank seller name', () => {
    for (const sellerName of ['', '   ']) {
      expect(() => buildPhase1Qr({ ...ok, sellerName })).toThrow(/sellerName/);
    }
  });

  it('rejects VAT numbers that are not 15 digits starting and ending with 3', () => {
    for (const vatNumber of [
      '',
      '31012239350000', // 14 digits
      '3101223935000031', // 16 digits
      '410122393500003', // wrong leading digit
      '310122393500004', // wrong trailing digit
      '31012239350000A',
    ]) {
      expect(() => buildPhase1Qr({ ...ok, vatNumber })).toThrow(/vatNumber/);
    }
  });

  it('rejects VAT larger than the VAT-INCLUSIVE total', () => {
    // Tag 4 includes the VAT of tag 5, so this is arithmetically
    // impossible — and it is the first thing an auditor recomputes.
    expect(() =>
      buildPhase1Qr({ ...ok, totalWithVatHalalas: 100, vatHalalas: 101 }),
    ).toThrow(/cannot exceed/);
    // Equal is legal: a 100%-VAT-on-zero-base edge, and zero VAT always.
    expect(() =>
      buildPhase1Qr({ ...ok, totalWithVatHalalas: 100, vatHalalas: 100 }),
    ).not.toThrow();
  });

  it('rejects negative amounts — credit notes carry POSITIVE totals', () => {
    expect(() =>
      buildPhase1Qr({ ...ok, totalWithVatHalalas: -100 }),
    ).toThrow(/totalWithVatHalalas/);
    expect(() => buildPhase1Qr({ ...ok, vatHalalas: -1 })).toThrow(
      /vatHalalas/,
    );
    // Zero is legitimate (a fully exempt line).
    expect(() => buildPhase1Qr({ ...ok, vatHalalas: 0 })).not.toThrow();
  });
});

/** secp256k1 group order — r and s must both land in [1, n-1]. */
const SECP256K1_N = BigInt(
  '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
);

/** DER `SEQUENCE { INTEGER r, INTEGER 7 }` for an arbitrary r. */
function derSigWithR(r: bigint): Uint8Array {
  let hex = r.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  let bytes = Buffer.from(hex, 'hex');
  // DER: pad so the value stays positive.
  if (bytes[0] & 0x80) bytes = Buffer.concat([Buffer.from([0x00]), bytes]);
  const rPart = Buffer.concat([Buffer.from([0x02, bytes.length]), bytes]);
  const sPart = Buffer.from([0x02, 0x01, 0x07]);
  return Buffer.concat([
    Buffer.from([0x30, rPart.length + sPart.length]),
    rPart,
    sPart,
  ]);
}

/**
 * A MATCHED tags 6/7/8 triple: the signature really verifies over the
 * hash under that key. Independently-valid-but-unrelated fixtures are
 * exactly what buildPhase2Qr must now reject, so the happy path needs
 * genuine crypto rather than three plausible blobs.
 */
function signedTriple(payload = 'invoice'): {
  invoiceHashBase64: string;
  signatureBase64: string;
  publicKeyBytes: Uint8Array;
} {
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'secp256k1',
  });
  const hash = createHash('sha256').update(payload).digest();
  const signer = createSign('sha256');
  signer.update(hash);
  return {
    invoiceHashBase64: hash.toString('base64'),
    signatureBase64: signer.sign(privateKey).toString('base64'),
    publicKeyBytes: publicKey.export({ type: 'spki', format: 'der' }),
  };
}

/** Just the canonical SPKI, for tag-8 shape tests. */
function realSpki(): Uint8Array {
  return signedTriple().publicKeyBytes;
}

/**
 * A structurally valid DER ECDSA signature for tag 9 (the CA's signature
 * over the CSID cert). Its issuer key is not available to a verifier, so
 * only the DER structure is checkable — `30 00` must not pass.
 */
function derSig(): Uint8Array {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  const signer = createSign('sha256');
  signer.update('cert');
  return signer.sign(privateKey);
}
