/**
 * ZATCA XAdES B-B cryptographic stamp — the server/tooling twin of the
 * Flutter till's on-device signer (saudi-pos-saas
 * apps/pos_app/lib/features/zatca/zatca_xades.dart). Test vectors are
 * shared between the two so they stay byte-identical.
 *
 * The templates are ported from the proven reference implementation and
 * their whitespace is LOAD-BEARING:
 * - the SignedProperties block that gets HASHED (for the
 *   `URI="#xadesSignedProperties"` reference digest) deliberately differs
 *   from the one RENDERED into the XML: deeper indent, per-element
 *   `xmlns:ds`, self-closed DigestMethod;
 * - digests are sha256 → HEX STRING → base64 of the hex (ZATCA's double
 *   encoding, same as the certificate hash).
 * Do not reformat either template.
 */
import {
  X509Certificate,
  createHash,
  createSign,
  createVerify,
  type KeyObject,
} from 'node:crypto';
import { decodeBase64Strict } from './base64';

export interface CertificateInfo {
  /** The bare base64-DER text (goes verbatim into ds:X509Certificate). */
  base64Der: string;
  /** base64(hex(sha256(base64Der))) — the double-encoded cert digest. */
  hashBase64: string;
  /** RFC 2253 order, e.g. "CN=eInvoicing". */
  issuerName: string;
  serialDecimal: string;
  /**
   * FULL DER SubjectPublicKeyInfo (88 bytes for secp256k1) — what QR
   * tag 8 requires. NOT the bare 65-byte EC point: the reference
   * implementations that pass ZATCA validation all embed the complete
   * SPKI structure (30 56 30 10 … 03 42 00 04‖X‖Y).
   */
  publicKeyBytes: Buffer;
  /** The CA's DER ECDSA signature over the cert (QR tag 9). */
  signatureBytes: Buffer;
}

// ---- minimal DER walker (enough for an X.509 v3 certificate) --------------

interface Tlv {
  tag: number;
  value: Buffer;
  /** Offset just past this TLV, for sibling iteration. */
  end: number;
}

function readTlv(buf: Buffer, offset: number): Tlv {
  const tag = buf[offset];
  let len = buf[offset + 1];
  let headerLen = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = Number(buf.subarray(offset + 2, offset + 2 + n).reduce((a, b) => a * 256 + b, 0));
    headerLen = 2 + n;
  }
  const start = offset + headerLen;
  return { tag, value: buf.subarray(start, start + len), end: start + len };
}

function children(node: Buffer): Tlv[] {
  const out: Tlv[] = [];
  let off = 0;
  while (off < node.length) {
    const tlv = readTlv(node, off);
    out.push(tlv);
    off = tlv.end;
  }
  return out;
}

const OID_NAMES: Record<string, string> = {
  '2.5.4.3': 'CN',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '0.9.2342.19200300.100.1.25': 'DC',
};

function decodeOid(bytes: Buffer): string {
  const first = bytes[0];
  const parts = [Math.floor(first / 40), first % 40];
  let acc = 0;
  for (let i = 1; i < bytes.length; i++) {
    acc = acc * 128 + (bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) {
      parts.push(acc);
      acc = 0;
    }
  }
  return parts.join('.');
}

export function parseCertificate(base64Der: string): CertificateInfo {
  const cleaned = base64Der.replace(/\s/g, '');
  const der = Buffer.from(cleaned, 'base64');
  const cert = readTlv(der, 0);
  const [tbs, , sigBits] = children(cert.value);

  const tbsParts = children(tbs.value);
  // Optional [0] EXPLICIT version, then serialNumber INTEGER.
  const i = tbsParts[0].tag === 0xa0 ? 1 : 0;
  const serial = BigInt('0x' + tbsParts[i].value.toString('hex')).toString(10);
  const issuerSeq = tbsParts[i + 2];
  const spki = tbsParts[i + 5];
  const spkBits = children(spki.value)[1];

  const rdns = children(issuerSeq.value).map((rdn) => {
    const atv = children(children(rdn.value)[0].value);
    const oid = decodeOid(atv[0].value);
    return `${OID_NAMES[oid] ?? oid}=${atv[1].value.toString('utf8')}`;
  });

  return {
    base64Der: cleaned,
    hashBase64: Buffer.from(
      createHash('sha256').update(cleaned, 'ascii').digest('hex'),
    ).toString('base64'),
    issuerName: rdns.reverse().join(', '),
    serialDecimal: serial,
    // QR tag 8 wants the COMPLETE SubjectPublicKeyInfo DER (88 bytes),
    // not the bare point inside its BIT STRING — node:crypto re-emits
    // the canonical structure. (spkBits stays parsed above so a malformed
    // SPKI still fails loudly here rather than downstream.)
    publicKeyBytes: new X509Certificate(
      `-----BEGIN CERTIFICATE-----\n${cleaned}\n-----END CERTIFICATE-----`,
    ).publicKey.export({ type: 'spki', format: 'der' }) as Buffer,
    signatureBytes: Buffer.from(sigBits.value.subarray(1)),
  };
}

// ---- signing ---------------------------------------------------------------

/**
 * ECDSA-SHA256 over the base64-DECODED invoice hash bytes, DER, base64.
 * The hash must decode canonically to EXACTLY 32 bytes (SHA-256): Node's
 * lenient decoder would happily "decode" `not-base64!!!` and sign the
 * resulting garbage, producing a signature that can never verify against
 * the real invoice.
 */
export function signInvoiceHash(
  invoiceHashBase64: string,
  privateKeyPem: string,
): string {
  const hash = decodeBase64Strict(invoiceHashBase64, 'invoiceHashBase64');
  if (hash.length !== 32) {
    throw new TypeError(
      `invoiceHashBase64 must decode to 32 SHA-256 bytes, got ${hash.length}`,
    );
  }
  const signer = createSign('sha256');
  signer.update(hash);
  return signer.sign(privateKeyPem).toString('base64');
}

// ---- templates -------------------------------------------------------------

/** `YYYY-MM-DDTHH:mm:ssZ` (UTC, no millis) — the reference format. */
export function formatSigningTime(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * The EXACT bytes hashed for the SignedProperties reference digest —
 * reverse-engineered from SDK 3.3.8 and proven live 2026-08-19 (GLOBAL
 * PASSED + clean simulation-gateway acceptance): the validator serializes
 * the RENDERED node with a plain Java identity Transformer, which keeps
 * the document's own indentation, adds `xmlns:ds` to every ds:-prefixed
 * element, and self-closes the empty DigestMethod. So the hashed form is
 * the rendered block + those serializer quirks — NOT a deeper-indented
 * variant (that folklore only worked for implementations whose documents
 * happen to render at the deeper indent).
 */
export function signedPropertiesForSigning(
  signingTime: string,
  cert: CertificateInfo,
): string {
  return (
    '<xades:SignedProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="xadesSignedProperties">\n' +
    '                                <xades:SignedSignatureProperties>\n' +
    `                                    <xades:SigningTime>${signingTime}</xades:SigningTime>\n` +
    '                                    <xades:SigningCertificate>\n' +
    '                                        <xades:Cert>\n' +
    '                                            <xades:CertDigest>\n' +
    '                                                <ds:DigestMethod xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>\n' +
    `                                                <ds:DigestValue xmlns:ds="http://www.w3.org/2000/09/xmldsig#">${cert.hashBase64}</ds:DigestValue>\n` +
    '                                            </xades:CertDigest>\n' +
    '                                            <xades:IssuerSerial>\n' +
    `                                                <ds:X509IssuerName xmlns:ds="http://www.w3.org/2000/09/xmldsig#">${cert.issuerName}</ds:X509IssuerName>\n` +
    `                                                <ds:X509SerialNumber xmlns:ds="http://www.w3.org/2000/09/xmldsig#">${cert.serialDecimal}</ds:X509SerialNumber>\n` +
    '                                            </xades:IssuerSerial>\n' +
    '                                        </xades:Cert>\n' +
    '                                    </xades:SigningCertificate>\n' +
    '                                </xades:SignedSignatureProperties>\n' +
    '                            </xades:SignedProperties>'
  );
}

/** base64(hex(sha256(forSigning))) — the double-encoded digest. */
export function signedPropertiesHash(
  signingTime: string,
  cert: CertificateInfo,
): string {
  return Buffer.from(
    createHash('sha256')
      .update(signedPropertiesForSigning(signingTime, cert), 'utf8')
      .digest('hex'),
  ).toString('base64');
}

/** The SignedProperties block as RENDERED inside the invoice. */
export function signedPropertiesRendered(
  signingTime: string,
  cert: CertificateInfo,
): string {
  return (
    '<xades:SignedProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="xadesSignedProperties">\n' +
    '                                <xades:SignedSignatureProperties>\n' +
    `                                    <xades:SigningTime>${signingTime}</xades:SigningTime>\n` +
    '                                    <xades:SigningCertificate>\n' +
    '                                        <xades:Cert>\n' +
    '                                            <xades:CertDigest>\n' +
    '                                                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>\n' +
    `                                                <ds:DigestValue>${cert.hashBase64}</ds:DigestValue>\n` +
    '                                            </xades:CertDigest>\n' +
    '                                            <xades:IssuerSerial>\n' +
    `                                                <ds:X509IssuerName>${cert.issuerName}</ds:X509IssuerName>\n` +
    `                                                <ds:X509SerialNumber>${cert.serialDecimal}</ds:X509SerialNumber>\n` +
    '                                            </xades:IssuerSerial>\n' +
    '                                        </xades:Cert>\n' +
    '                                    </xades:SigningCertificate>\n' +
    '                                </xades:SignedSignatureProperties>\n' +
    '                            </xades:SignedProperties>'
  );
}

export interface XadesInput {
  invoiceHashBase64: string;
  signatureBase64: string;
  certificate: CertificateInfo;
  signingTime: Date;
}

/**
 * The complete `ext:UBLExtension` block (goes inside ext:UBLExtensions).
 *
 * Assembling is the LAST gate before an invoice leaves the terminal, so
 * the three cryptographic inputs are checked against each other here:
 * the digest must be a real SHA-256, the signature a real DER ECDSA
 * value, and — the invariant a verifier re-runs — the signature must
 * verify over that digest under the public key of the very certificate
 * this envelope embeds. A signature from an unrelated key produces a
 * structurally perfect XML that ZATCA rejects for every invoice the
 * terminal ever files.
 */
export function buildXadesExtension(input: XadesInput): string {
  const hash = decodeBase64Strict(input.invoiceHashBase64, 'invoiceHashBase64');
  if (hash.length !== 32) {
    throw new TypeError(
      `invoiceHashBase64 must decode to 32 SHA-256 bytes, got ${hash.length}`,
    );
  }
  const signature = decodeBase64Strict(
    input.signatureBase64,
    'signatureBase64',
  );
  let certKey: KeyObject;
  try {
    certKey = new X509Certificate(
      `-----BEGIN CERTIFICATE-----\n${input.certificate.base64Der}\n` +
        `-----END CERTIFICATE-----`,
    ).publicKey;
  } catch (err) {
    throw new TypeError(
      `certificate.base64Der is not a parseable X.509 certificate: ` +
        `${(err as Error).message}`,
    );
  }
  if (!createVerify('sha256').update(hash).verify(certKey, signature)) {
    throw new TypeError(
      'signatureBase64 does not verify over invoiceHashBase64 with the ' +
        "embedded certificate's public key — the signature was made by a " +
        'different key or over a different invoice',
    );
  }
  const signingTime = formatSigningTime(input.signingTime);
  const propsHash = signedPropertiesHash(signingTime, input.certificate);
  const rendered = signedPropertiesRendered(signingTime, input.certificate);
  return `
    <ext:UBLExtension>
        <ext:ExtensionURI>urn:oasis:names:specification:ubl:dsig:enveloped:xades</ext:ExtensionURI>
        <ext:ExtensionContent>
            <sig:UBLDocumentSignatures
                    xmlns:sac="urn:oasis:names:specification:ubl:schema:xsd:SignatureAggregateComponents-2"
                    xmlns:sbc="urn:oasis:names:specification:ubl:schema:xsd:SignatureBasicComponents-2"
                    xmlns:sig="urn:oasis:names:specification:ubl:schema:xsd:CommonSignatureComponents-2">
                <sac:SignatureInformation>
                    <cbc:ID>urn:oasis:names:specification:ubl:signature:1</cbc:ID>
                    <sbc:ReferencedSignatureID>urn:oasis:names:specification:ubl:signature:Invoice</sbc:ReferencedSignatureID>
                    <ds:Signature Id="signature" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                        <ds:SignedInfo>
                            <ds:CanonicalizationMethod
                                    Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                            <ds:SignatureMethod
                                    Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>
                            <ds:Reference Id="invoiceSignedData" URI="">
                                <ds:Transforms>
                                    <ds:Transform
                                            Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                                        <ds:XPath>not(//ancestor-or-self::ext:UBLExtensions)</ds:XPath>
                                    </ds:Transform>
                                    <ds:Transform
                                            Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                                        <ds:XPath>not(//ancestor-or-self::cac:Signature)</ds:XPath>
                                    </ds:Transform>
                                    <ds:Transform
                                            Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                                        <ds:XPath>not(//ancestor-or-self::cac:AdditionalDocumentReference[cbc:ID='QR'])</ds:XPath>
                                    </ds:Transform>
                                    <ds:Transform
                                            Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                                </ds:Transforms>
                                <ds:DigestMethod
                                        Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                                <ds:DigestValue>${input.invoiceHashBase64}</ds:DigestValue>
                            </ds:Reference>
                            <ds:Reference
                                    Type="http://www.w3.org/2000/09/xmldsig#SignatureProperties"
                                    URI="#xadesSignedProperties">
                                <ds:DigestMethod
                                        Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                                <ds:DigestValue>${propsHash}</ds:DigestValue>
                            </ds:Reference>
                        </ds:SignedInfo>
                        <ds:SignatureValue>${input.signatureBase64}</ds:SignatureValue>
                        <ds:KeyInfo>
                            <ds:X509Data>
                                <ds:X509Certificate>${input.certificate.base64Der}</ds:X509Certificate>
                            </ds:X509Data>
                        </ds:KeyInfo>
                        <ds:Object>
                            <xades:QualifyingProperties Target="signature"
                                                        xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">
                                ${rendered}
                            </xades:QualifyingProperties>
                        </ds:Object>
                    </ds:Signature>
                </sac:SignatureInformation>
            </sig:UBLDocumentSignatures>
        </ext:ExtensionContent>
    </ext:UBLExtension>`;
}
