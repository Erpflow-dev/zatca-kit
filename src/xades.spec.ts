import {
  createHash,
  createSign,
  createVerify,
  generateKeyPairSync,
} from 'node:crypto';
import {
  buildXadesExtension,
  formatSigningTime,
  parseCertificate,
  signInvoiceHash,
  signedPropertiesForSigning,
  signedPropertiesHash,
  signedPropertiesRendered,
} from './xades';

/**
 * Anonymized self-signed secp256k1 certificate (CN=eInvoicing, like the
 * real CSID issuer). The expected values below are locked vectors for the
 * ZATCA double-encoding algorithms (sha256 → hex string → base64); the
 * same code paths are additionally verified against ZATCA's official SDK
 * output in the parent project's test suite with a real CSID.
 */
const CERT_B64 =
  'MIIBezCCASKgAwIBAgIUWK66k7gO4tb4eBMj1iGW3H3EMJswCgYIKoZIzj0EAwIw' +
  'FTETMBEGA1UEAwwKZUludm9pY2luZzAeFw0yNjA4MTgxODEwMDdaFw0zNjA4MTUx' +
  'ODEwMDdaMBUxEzARBgNVBAMMCmVJbnZvaWNpbmcwVjAQBgcqhkjOPQIBBgUrgQQA' +
  'CgNCAASF+ALL1k8lfpz8E8SEoocTUokDNgvWfgAfaci70qx6LeeT3EkfBRBC8c9n' +
  'ZpYX0yGxR8Sq69NVl8cNFijznCmxo1MwUTAdBgNVHQ4EFgQUsKiEHRrwm+e8b9S/' +
  '/to3Qha+EaYwHwYDVR0jBBgwFoAUsKiEHRrwm+e8b9S//to3Qha+EaYwDwYDVR0T' +
  'AQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiBehXZRtaMus3abvVmk+7yUW5On' +
  'ddZB293O7tOIjf/PdwIgMHFhPT6RmJH76PjOsaOKorG+WhXFzPZIAujwzr2vlz4=';

const CERT_HASH =
  'OWM5NDJmZjM3NWU0ZGUwMTEzMWI2NTMyYjE2ODMxOTIyZjhmNGJlODBiOGRkMGM2' +
  'NjlmMDNhYTMzYjE2ODE3NA==';
const CERT_SERIAL = '506287770648388695579712932838298178911138492571';
// Recomputed 2026-08-19 for the live-proven for-signing form (rendered
// indentation + Java-serializer quirks); the previous vector locked the
// deeper-indented folklore template that SDK validation rejects.
const SIGNED_PROPS_HASH =
  'ODA4MjdjYWNkZjNlMzVhNDY5Yzc4NjIyMWRlZTBjZmM1MWEwOGM3ZmM2Zjk4ODU2' +
  'ZTQ4YmYxMzhmNDU3ZWQ1NA==';
const SIGNING_TIME = '2026-01-01T00:00:00Z';

describe('parseCertificate', () => {
  const cert = parseCertificate(CERT_B64);

  it('hash is the ZATCA double encoding: base64(hex(sha256(base64 text)))', () => {
    expect(cert.hashBase64).toBe(CERT_HASH);
  });

  it('issuer and serial come from the DER', () => {
    expect(cert.issuerName).toBe('CN=eInvoicing');
    expect(cert.serialDecimal).toBe(CERT_SERIAL);
  });

  it('public key is the FULL SubjectPublicKeyInfo DER (QR tag 8)', () => {
    // 88 bytes for secp256k1: SEQUENCE(0x30 0x56) wrapping algorithm ids
    // and the BIT STRING that holds the raw 0x04‖X‖Y point. A previous
    // version asserted the bare 65-byte point — the representation ZATCA
    // QR validation rejects.
    expect(cert.publicKeyBytes.length).toBe(88);
    expect(cert.publicKeyBytes[0]).toBe(0x30);
    expect(cert.publicKeyBytes[1]).toBe(0x56);
    // The raw point rides INSIDE the structure (tail 65 bytes).
    expect(cert.publicKeyBytes[88 - 65]).toBe(0x04);
  });

  it('certificate signature bytes are DER ECDSA (QR tag 9)', () => {
    expect(cert.signatureBytes[0]).toBe(0x30);
    expect(cert.signatureBytes.length).toBeGreaterThanOrEqual(68);
    expect(cert.signatureBytes.length).toBeLessThanOrEqual(74);
  });
});

describe('SignedProperties templates', () => {
  const cert = parseCertificate(CERT_B64);

  it('digest matches the locked vector (reference algorithm)', () => {
    expect(signedPropertiesHash(SIGNING_TIME, cert)).toBe(SIGNED_PROPS_HASH);
  });

  it('hashed and rendered variants differ only in the documented quirks', () => {
    const forSigning = signedPropertiesForSigning(SIGNING_TIME, cert);
    const rendered = signedPropertiesRendered(SIGNING_TIME, cert);
    expect(forSigning).not.toBe(rendered);
    expect(forSigning).toContain('sha256"/>');
    expect(rendered).toContain('></ds:DigestMethod>');
    for (const v of [cert.hashBase64, cert.issuerName, cert.serialDecimal]) {
      expect(forSigning).toContain(v);
      expect(rendered).toContain(v);
    }
  });

  it('signing time is UTC seconds with Z, no millis', () => {
    expect(formatSigningTime(new Date(Date.UTC(2026, 0, 1)))).toBe(
      SIGNING_TIME,
    );
  });
});

describe('signInvoiceHash', () => {
  it('produces a DER ECDSA signature that verifies against the key', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
      namedCurve: 'secp256k1',
    });
    const invoiceHash = Buffer.from('a'.repeat(32)).toString('base64');
    const sig = signInvoiceHash(
      invoiceHash,
      privateKey.export({ type: 'sec1', format: 'pem' }).toString(),
    );
    const verifier = createVerify('sha256');
    verifier.update(Buffer.from(invoiceHash, 'base64'));
    expect(verifier.verify(publicKey, Buffer.from(sig, 'base64'))).toBe(true);
  });

  it('rejects hashes that are not canonical base64 of exactly 32 bytes', () => {
    const { privateKey } = generateKeyPairSync('ec', {
      namedCurve: 'secp256k1',
    });
    const pem = privateKey.export({ type: 'sec1', format: 'pem' }).toString();
    for (const bad of [
      'not-base64!!!', // Node's lenient decoder would sign this garbage
      'QUJD', // valid base64, but 3 bytes — not a SHA-256
      Buffer.from('a'.repeat(31)).toString('base64'), // 31 bytes
      Buffer.from('a'.repeat(32)).toString('base64').slice(0, -1), // broken padding
    ]) {
      expect(() => signInvoiceHash(bad, pem)).toThrow(TypeError);
    }
  });
});

describe('buildXadesExtension', () => {
  // The envelope now VERIFIES its inputs, so the fixture must be a real
  // certificate whose private key we hold — an unrelated signature is
  // precisely what must fail. (The live-proven SignedProperties vector
  // stays pinned to CERT_B64 in the describe above, which calls
  // signedPropertiesHash directly.)
  const { cert, sign } = selfSignedFixture();

  it('assembles a complete envelope with the for-signing digest embedded', () => {
    const invoiceHashBase64 = createHash('sha256')
      .update('<Invoice/>')
      .digest('base64');
    const signatureBase64 = sign(invoiceHashBase64);
    const xml = buildXadesExtension({
      invoiceHashBase64,
      signatureBase64,
      certificate: cert,
      signingTime: new Date(Date.UTC(2026, 0, 1)),
    });
    expect(xml).toContain(
      `<ds:DigestValue>${invoiceHashBase64}</ds:DigestValue>`,
    );
    expect(xml).toContain(
      `<ds:DigestValue>${signedPropertiesHash(SIGNING_TIME, cert)}</ds:DigestValue>`,
    );
    expect(xml).toContain(
      `<ds:SignatureValue>${signatureBase64}</ds:SignatureValue>`,
    );
    expect(xml).toContain(
      `<ds:X509Certificate>${cert.base64Der}</ds:X509Certificate>`,
    );
    expect(xml).not.toContain('SET_');
  });

  it('refuses a signature made by a key unrelated to the embedded certificate', () => {
    const other = selfSignedFixture();
    const invoiceHashBase64 = createHash('sha256')
      .update('<Invoice/>')
      .digest('base64');
    expect(() =>
      buildXadesExtension({
        invoiceHashBase64,
        // Correct hash, valid DER ECDSA — but the WRONG key. ZATCA would
        // reject every invoice this terminal ever files.
        signatureBase64: other.sign(invoiceHashBase64),
        certificate: cert,
        signingTime: new Date(Date.UTC(2026, 0, 1)),
      }),
    ).toThrow(/does not verify/);
  });

  it('refuses a signature over a DIFFERENT invoice hash', () => {
    const mine = createHash('sha256').update('<Invoice/>').digest('base64');
    const theirs = createHash('sha256').update('<Other/>').digest('base64');
    expect(() =>
      buildXadesExtension({
        invoiceHashBase64: mine,
        signatureBase64: sign(theirs),
        certificate: cert,
        signingTime: new Date(Date.UTC(2026, 0, 1)),
      }),
    ).toThrow(/does not verify/);
  });

  it('refuses non-32-byte digests and non-DER signatures', () => {
    const good = createHash('sha256').update('<Invoice/>').digest('base64');
    expect(() =>
      buildXadesExtension({
        invoiceHashBase64: 'QUJD', // 3 bytes
        signatureBase64: sign(good),
        certificate: cert,
        signingTime: new Date(Date.UTC(2026, 0, 1)),
      }),
    ).toThrow(/32 SHA-256 bytes/);
    expect(() =>
      buildXadesExtension({
        invoiceHashBase64: good,
        signatureBase64: 'not-base64!!!',
        certificate: cert,
        signingTime: new Date(Date.UTC(2026, 0, 1)),
      }),
    ).toThrow(TypeError);
  });
});

// ---- minimal self-signed certificate builder (test-only) ------------------
// Node generates keys but not certificates, and the kit ships no deps.
// This emits just enough X.509 v3 DER for parseCertificate + verification.

// Function declarations, not consts: the fixture is built while the
// describe bodies run, which is before later const initializers exist.
function derLen(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const b: number[] = [];
  for (let v = n; v > 0; v >>= 8) b.unshift(v & 0xff);
  return Buffer.from([0x80 | b.length, ...b]);
}
function der(tag: number, ...parts: Buffer[]): Buffer {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag]), derLen(body.length), body]);
}
function derOid(dotted: string): Buffer {
  const p = dotted.split('.').map(Number);
  const out = [p[0] * 40 + p[1]];
  for (const n of p.slice(2)) {
    const chunk: number[] = [n & 0x7f];
    for (let v = n >> 7; v > 0; v >>= 7) chunk.unshift((v & 0x7f) | 0x80);
    out.push(...chunk);
  }
  return der(0x06, Buffer.from(out));
}
function utcTime(d: Date): Buffer {
  return der(
    0x17,
    Buffer.from(`${d.toISOString().slice(2, 19).replace(/[-:T]/g, '')}Z`),
  );
}

function selfSignedFixture(): {
  cert: ReturnType<typeof parseCertificate>;
  sign: (hashBase64: string) => string;
} {
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'secp256k1',
  });
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const ecdsaSha256 = der(0x30, derOid('1.2.840.10045.4.3.2'));
  const name = der(
    0x30,
    der(
      0x31,
      der(0x30, derOid('2.5.4.3'), der(0x0c, Buffer.from('eInvoicing'))),
    ),
  );
  const tbs = der(
    0x30,
    der(0xa0, der(0x02, Buffer.from([0x02]))), // v3
    der(0x02, Buffer.from([0x01, 0x2c])), // serialNumber
    ecdsaSha256,
    name,
    der(
      0x30,
      utcTime(new Date('2026-01-01T00:00:00Z')),
      utcTime(new Date('2036-01-01T00:00:00Z')),
    ),
    name,
    spki,
  );
  const signer = createSign('sha256');
  signer.update(tbs);
  const certDer = der(
    0x30,
    tbs,
    ecdsaSha256,
    der(0x03, Buffer.from([0x00]), signer.sign(privateKey)),
  );
  return {
    cert: parseCertificate(certDer.toString('base64')),
    sign: (hashBase64: string) =>
      signInvoiceHash(
        hashBase64,
        privateKey.export({ type: 'sec1', format: 'pem' }).toString(),
      ),
  };
}
