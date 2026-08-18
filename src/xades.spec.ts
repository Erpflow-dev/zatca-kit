import { createVerify, generateKeyPairSync } from 'node:crypto';
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
const SIGNED_PROPS_HASH =
  'NjMwNzEwZjBjZDUzMWQxNWM4ZjNhNmQyNmI4OTI3NWZiYzExN2M2NWU5ZWE5MWRh' +
  'MDFjZDY5OWJkOWQ0ZDA2Ng==';
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

  it('public key is the raw uncompressed secp256k1 point (QR tag 8)', () => {
    expect(cert.publicKeyBytes.length).toBe(65);
    expect(cert.publicKeyBytes[0]).toBe(0x04);
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
});

describe('buildXadesExtension', () => {
  it('assembles a complete envelope with the for-signing digest embedded', () => {
    const cert = parseCertificate(CERT_B64);
    const xml = buildXadesExtension({
      invoiceHashBase64: 'SGFzaA==',
      signatureBase64: 'U2ln',
      certificate: cert,
      signingTime: new Date(Date.UTC(2026, 0, 1)),
    });
    expect(xml).toContain('<ds:DigestValue>SGFzaA==</ds:DigestValue>');
    expect(xml).toContain(`<ds:DigestValue>${SIGNED_PROPS_HASH}</ds:DigestValue>`);
    expect(xml).toContain('<ds:SignatureValue>U2ln</ds:SignatureValue>');
    expect(xml).toContain(`<ds:X509Certificate>${CERT_B64}</ds:X509Certificate>`);
    expect(xml).not.toContain('SET_');
  });
});
