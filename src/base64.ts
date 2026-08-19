/**
 * Strict base64 — Node's `Buffer.from(s, 'base64')` is PERMISSIVE: it
 * skips invalid characters and truncates silently, so `not-base64!!!`
 * "decodes" without complaint. Everywhere a base64 string is EVIDENCE
 * (an invoice hash about to be signed, ZATCA's stamped legal copy), a
 * lenient decode turns garbage into a false positive. This helper
 * requires the canonical form: alphabet + padding, and a re-encode that
 * reproduces the input byte-for-byte.
 */
export function decodeBase64Strict(value: string, label: string): Buffer {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) {
    throw new TypeError(`${label} is not valid base64`);
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64') !== value) {
    throw new TypeError(`${label} is not canonical base64`);
  }
  return decoded;
}
