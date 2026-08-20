import { decodeBase64Strict } from './base64';

/**
 * The validation block ZATCA attaches to reporting, clearance AND
 * compliance answers. Both spellings of the error array exist in the
 * wild: the OpenAPI files say `erroMessages`, the live service has sent
 * `errorMessages`.
 */
interface ValidationResultsBody {
  status?: string;
  errorMessages?: unknown[];
  erroMessages?: unknown[];
}

/**
 * Does this validation block contradict a success disposition? Used to
 * refuse REPORTED/CLEARED whenever the SAME response says the invoice
 * failed. The spellings MERGE — coalescing would let an empty array in
 * one spelling hide a populated array in the other.
 */
function contradictsSuccess(vr?: unknown): boolean {
  if (vr == null) return false; // absent block: the disposition stands alone
  // Present but not an object (`validationResults: "PASS"`) is a verdict
  // we cannot read. Trusting the top-level disposition over an unreadable
  // verdict is failing OPEN.
  if (typeof vr !== 'object' || Array.isArray(vr)) return true;
  const block = vr as ValidationResultsBody;
  // A block that is present must AFFIRMATIVELY say it passed. Checking
  // only for the literal 'ERROR' let every other value through —
  // 'UNKNOWN', a typo, a future status, or no status at all.
  const status = String(block.status ?? '').toUpperCase();
  if (status !== 'PASS' && status !== 'WARNING') return true;
  for (const field of [block.errorMessages, block.erroMessages]) {
    if (field == null) continue;
    // A non-array here is also unreadable. Spreading it would throw
    // ("not iterable") and take the whole call down.
    if (!Array.isArray(field)) return true;
    if (field.length > 0) return true;
  }
  return false;
}

/** UBL 2.1 namespace per document root — the exact URI, not a prefix. */
const UBL_NAMESPACES: Record<string, string> = {
  Invoice: 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2',
  CreditNote: 'urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2',
  DebitNote: 'urn:oasis:names:specification:ubl:schema:xsd:DebitNote-2',
};

/**
 * Minimal well-formedness scan: walks the document matching every open
 * tag to its close, and returns the ROOT element's name and attributes —
 * or null if the text is not a single well-formed element tree.
 * Truncated documents (the common corruption) leave the stack non-empty
 * and are rejected. Dependency-free by design: the kit ships no parser.
 */
function scanXmlRoot(
  text: string,
): { name: string; attributes: Map<string, string> } | null {
  const stack: string[] = [];
  let root: { name: string; attributes: Map<string, string> } | null = null;
  let i = 0;
  while (i < text.length) {
    if (text[i] !== '<') {
      const next = text.indexOf('<', i);
      const chunk = text.slice(i, next === -1 ? text.length : next);
      // Character data outside the root element is not well-formed, and
      // inside it every '&' must open a defined reference.
      if (stack.length === 0 && chunk.trim() !== '') return null;
      if (stack.length > 0 && !entitiesAreDefined(chunk)) return null;
      if (next === -1) break;
      i = next;
      continue;
    }
    if (text.startsWith('<!--', i)) {
      const end = text.indexOf('-->', i);
      if (end === -1) return null;
      i = end + 3;
      continue;
    }
    if (text.startsWith('<![CDATA[', i)) {
      // CDATA is character data: legal INSIDE an element, never at the
      // top level. Skipping it unconditionally accepted documents no
      // parser would.
      if (stack.length === 0) return null;
      const end = text.indexOf(']]>', i);
      if (end === -1) return null;
      i = end + 3;
      continue;
    }
    if (text.startsWith('<?', i)) {
      const end = text.indexOf('?>', i);
      if (end === -1) return null;
      i = end + 2;
      continue;
    }
    if (text.startsWith('<!', i)) return null; // DOCTYPE: never in a CSID reply
    if (text.startsWith('</', i)) {
      const end = text.indexOf('>', i);
      if (end === -1) return null;
      if (stack.pop() !== text.slice(i + 2, end).trim()) return null;
      i = end + 1;
      continue;
    }
    // Open tag: find the '>' that is not inside an attribute value.
    let j = i + 1;
    let quote = '';
    for (; j < text.length; j += 1) {
      const c = text[j];
      if (quote) {
        if (c === quote) quote = '';
      } else if (c === '"' || c === "'") {
        quote = c;
      } else if (c === '>') {
        break;
      }
    }
    if (j >= text.length) return null;
    const inner = text.slice(i + 1, j);
    const selfClosing = inner.endsWith('/');
    const parsed = /^([A-Za-z_][\w.-]*(?::[A-Za-z_][\w.-]*)?)([\s\S]*)$/.exec(
      selfClosing ? inner.slice(0, -1) : inner,
    );
    if (parsed === null) return null;
    const [, name, rawAttrs] = parsed;
    if (stack.length === 0 && root !== null) return null; // a second root
    if (root === null) {
      const attributes = parseAttributes(rawAttrs);
      if (attributes === null) return null;
      root = { name, attributes };
    } else if (parseAttributes(rawAttrs) === null) {
      return null;
    }
    if (!selfClosing) stack.push(name);
    i = j + 1;
  }
  return stack.length === 0 ? root : null;
}

/**
 * Without a DTD the only legal references are the five predefined
 * entities and numeric character references. `&foo;` is a fatal error to
 * a real parser, so a document carrying one is not the legal invoice.
 */
function entitiesAreDefined(text: string): boolean {
  return !text
    .replace(/&(?:lt|gt|amp|apos|quot|#\d+|#x[0-9A-Fa-f]+);/g, '')
    .includes('&');
}

/**
 * Parse an element's attributes into name → value. Scanning the RAW
 * attribute text with a regex was the hole: an ordinary attribute whose
 * VALUE contains `xmlns='urn:…:Invoice-2'` looked like a namespace
 * declaration on the element itself.
 */
function parseAttributes(raw: string): Map<string, string> | null {
  const attributes = new Map<string, string>();
  let i = 0;
  while (i < raw.length) {
    if (/\s/.test(raw[i])) {
      i += 1;
      continue;
    }
    const name = /^([A-Za-z_][\w.-]*(?::[A-Za-z_][\w.-]*)?)\s*=\s*/.exec(
      raw.slice(i),
    );
    if (name === null) return null;
    i += name[0].length;
    const quote = raw[i];
    if (quote !== '"' && quote !== "'") return null;
    const end = raw.indexOf(quote, i + 1);
    if (end === -1) return null;
    const value = raw.slice(i + 1, end);
    // '<' is never legal raw inside an attribute value.
    if (value.includes('<') || !entitiesAreDefined(value)) return null;
    if (attributes.has(name[1])) return null; // duplicate attribute
    attributes.set(name[1], value);
    i = end + 1;
  }
  return attributes;
}

export interface FatooraCredentials {
  /**
   * The CSID `binarySecurityToken` exactly as ZATCA returned it. It is
   * ALREADY base64 (a base64 X509) and is the Basic username verbatim —
   * encoding it again double-encodes and earns a 401 (docs/10).
   */
  cert: string;
  secret: string;
}

export interface ReportOutcome {
  ok: boolean;
  /** REPORTED on live success (200 and 202 alike); null when absent. */
  reportingStatus: string | null;
  /**
   * The invoice itself was rejected — retrying the same XML is pointless.
   * ONLY 400 qualifies. 401/406 are our credentials/headers being wrong, and
   * a duplicate means ZATCA already has it; neither says anything about the
   * invoice, so neither may burn it to 'failed' (docs/10 status-code table).
   */
  rejected: boolean;
  /**
   * ZATCA already holds this invoice (crash-safe retry replay). The spec
   * documented 208 for this; the LIVE service moved to 409 (production
   * integrators track the same migration) — both map here. Success, but
   * THIS response carries no fresh payload.
   */
  duplicate: boolean;
  status: number;
  body: string;
}

/**
 * CSID issuance response, shared by POST /compliance, POST /production/csids
 * and PATCH /production/csids (docs/10 endpoints 1–3).
 */
export interface CsidIssuance {
  status: number;
  /**
   * THE onboarding gate. 'ISSUED' on success, 'NOT_COMPLIANT' while the
   * compliance checks have not passed — and NOT_COMPLIANT arrives with
   * HTTP 200, not an error status. Callers must branch on this field,
   * never on `status` alone (docs/10).
   */
  dispositionMessage: string | null;
  /** requestID from /compliance = the compliance_request_id for step 2. */
  requestId: string | null;
  binarySecurityToken: string | null;
  secret: string | null;
  errors: unknown;
  body: string;
}

export interface ClearanceOutcome {
  ok: boolean;
  /** 400 — ZATCA rejected THIS invoice; retrying the same XML is pointless. */
  rejected: boolean;
  /**
   * Replay detected (208 per the official contract, 409 observed live).
   * NOT ok by itself: when the reply carries CLEARED + clearedInvoice
   * (the contract's 208 shape) ok is true with the legal copy in hand;
   * an EMPTY duplicate reply leaves ok false and the caller resolves
   * against its archived first response — never against this reply.
   */
  duplicate: boolean;
  status: number;
  /** CLEARED / NOT_CLEARED. */
  clearanceStatus: string | null;
  /**
   * base64 of the ZATCA-stamped XML — the LEGAL copy to archive and give
   * the buyer. Null on 409 replays (the original response carried it).
   */
  clearedInvoiceBase64: string | null;
  body: string;
}

export interface ComplianceCheckOutcome {
  status: number;
  /** 200/202 — the test document passed (202 = passed with warnings). */
  ok: boolean;
  reportingStatus: string | null;
  clearanceStatus: string | null;
  /**
   * ZATCA's OpenAPI files spell the field `erroMessages`, but the LIVE
   * sandbox responds with `errorMessages` (verified 2026-08-18: reporting
   * returned {"validationResults":{"errorMessages":[],...}}). Accept BOTH —
   * trusting either document alone silently reads undefined on the other.
   */
  validationResults: {
    status?: string;
    infoMessages?: unknown[];
    warningMessages?: unknown[];
    errorMessages?: unknown[];
    erroMessages?: unknown[];
  } | null;
  body: string;
}

interface RawCsidBody {
  requestID?: number | string;
  dispositionMessage?: string;
  binarySecurityToken?: string;
  secret?: string;
  errors?: unknown;
}

/**
 * Fatoora API client (docs/10 — the live OpenAPI contract): B2C reporting
 * plus the CSID onboarding chain (compliance CSID → compliance checks →
 * production CSID → renewal). Auth: Basic with username = the CSID
 * binarySecurityToken verbatim, password = secret. Base URL is
 * environment-driven; the three environments are independent and a sandbox
 * CSID never works in production.
 */
export class FatooraClient {
  // Trailing slashes are stripped: `${base}${path}` with a slashed base
  // yields `.../simulation//compliance`, and gateways are free to 404
  // double slashes even when the un-doubled path would have worked.
  private readonly baseUrl = (
    process.env.ZATCA_API_BASE ??
    'https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal'
  ).replace(/\/+$/, '');

  /**
   * Which of the three independent environments this client posts to —
   * the authority every credential lookup must scope by (a sandbox CSID
   * against simulation is a guaranteed 401; worse, credentials could be
   * replayed against the wrong environment after an ops base-URL switch).
   */
  environment(): 'sandbox' | 'simulation' | 'production' {
    if (this.baseUrl.includes('/simulation')) return 'simulation';
    if (this.baseUrl.endsWith('/core') || this.baseUrl.includes('/core/')) {
      return 'production';
    }
    return 'sandbox';
  }

  async reportSimplified(params: {
    creds: FatooraCredentials;
    invoiceHash: string;
    uuid: string;
    invoiceXmlBase64: string;
  }): Promise<ReportOutcome> {
    const { creds, invoiceHash, uuid, invoiceXmlBase64 } = params;

    const res = await this.request('/invoices/reporting/single', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json',
        // Uppercase V2 exactly — anything else is a 406 (docs/10).
        'Accept-Version': 'V2',
        // Required. '0' = clearance disabled, which is the B2C till's case.
        'Clearance-Status': '0',
        authorization: this.basicAuth(creds),
      },
      body: JSON.stringify({
        invoiceHash,
        uuid,
        invoice: invoiceXmlBase64,
      }),
    });
    // 409 = "already reported successfully earlier". Our own crash-safe retry
    // path produces it whenever the connection dies after ZATCA committed the
    // report, so it is a SUCCESS — the invoice is filed. Counting it as a
    // rejection would mark a compliant invoice 'failed' and alert on it.
    // (208 was the spec's duplicate code before the live service moved to
    // 409 — accept both, flagged so callers can tell replay from first.)
    const duplicate = res.status === 208 || res.status === 409;
    // First-time success needs POSITIVE evidence, not just a 2xx: the live
    // contract answers 200/202 with reportingStatus REPORTED (both
    // observed live 2026-08-19). A 200 with an empty body proves nothing
    // and must never mark an invoice reported permanently. And REPORTED
    // alone is not enough when the SAME body contradicts it: a
    // validationResults block with status ERROR or actual error entries
    // (either spelling — the live service has used both `errorMessages`
    // and `erroMessages`) means the invoice did NOT pass, whatever the
    // top-level disposition claims.
    const parsed = this.tryJson<{
      reportingStatus?: string;
      validationResults?: ValidationResultsBody;
    }>(res.body);
    const reported =
      (res.status === 200 || res.status === 202) &&
      parsed?.reportingStatus === 'REPORTED' &&
      !contradictsSuccess(parsed?.validationResults);
    return {
      ok: reported || duplicate,
      rejected: res.status === 400,
      duplicate,
      reportingStatus: parsed?.reportingStatus ?? null,
      status: res.status,
      body: res.body,
    };
  }

  /**
   * POST /invoices/clearance/single — B2B standard invoices, REAL-TIME
   * (rule 7: clearance happens at sale time, never via the ≤24h batch
   * worker). On success ZATCA returns `clearedInvoice`: base64 of the
   * ZATCA-stamped XML — THAT copy is the legal invoice to archive and
   * hand to the buyer, not the one we sent (docs/10).
   */
  async clearStandard(params: {
    creds: FatooraCredentials;
    invoiceHash: string;
    uuid: string;
    invoiceXmlBase64: string;
  }): Promise<ClearanceOutcome> {
    const { creds, invoiceHash, uuid, invoiceXmlBase64 } = params;
    const res = await this.request('/invoices/clearance/single', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json',
        'Accept-Version': 'V2',
        // '1' = clearance ENABLED — the whole point of this endpoint.
        'Clearance-Status': '1',
        authorization: this.basicAuth(creds),
      },
      body: JSON.stringify({ invoiceHash, uuid, invoice: invoiceXmlBase64 }),
    });
    // Duplicate submission: the official contract documents 208 (whose
    // body still carries CLEARED + clearedInvoice); the live service has
    // been observed sending 409 for replays. Either way, `ok` NEVER
    // comes from the status code alone: it requires the evidence —
    // clearanceStatus CLEARED plus the stamped clearedInvoice (the legal
    // copy). A 208/409 with an empty body is flagged `duplicate` but NOT
    // ok — the caller resolves it against its archived first response
    // instead of treating this reply as proof of anything.
    const duplicate = res.status === 208 || res.status === 409;
    const parsed = this.tryJson<{
      clearanceStatus?: string;
      clearedInvoice?: string;
      validationResults?: ValidationResultsBody;
    }>(res.body);
    // The stamped copy is about to become the LEGAL invoice we archive
    // and hand to the buyer — "non-empty string" is not evidence it is
    // one. It must be canonical base64 that decodes to an actual UBL
    // document, and the SAME body must not contradict CLEARED with a
    // failed validationResults block (clearance answers carry one, and
    // an invalid invoice archived as the legal copy is the worst
    // possible outcome of this call).
    const cleared =
      ((res.status >= 200 && res.status < 300) || res.status === 409) &&
      parsed?.clearanceStatus === 'CLEARED' &&
      !contradictsSuccess(parsed?.validationResults) &&
      typeof parsed?.clearedInvoice === 'string' &&
      this.isBase64Xml(parsed.clearedInvoice);
    return {
      ok: cleared,
      rejected: res.status === 400,
      duplicate,
      status: res.status,
      clearanceStatus: parsed?.clearanceStatus ?? null,
      clearedInvoiceBase64: parsed?.clearedInvoice ?? null,
      body: res.body,
    };
  }

  /**
   * POST /compliance — CSR + OTP in, compliance CSID out. NO auth: this is
   * the first call a fresh EGS unit ever makes (docs/10 endpoint 1). The
   * sandbox accepts magic OTPs 123345/111111/222222 (valid/invalid/expired).
   */
  async complianceCsid(csrBase64: string, otp: string): Promise<CsidIssuance> {
    const res = await this.request('/compliance', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json',
        'Accept-Version': 'V2',
        OTP: otp,
      },
      body: JSON.stringify({ csr: csrBase64 }),
    });
    return this.parseCsid(res);
  }

  /**
   * POST /production/csids — exchanges an ISSUED compliance CSID for the
   * production CSID (docs/10 endpoint 2). Succeeds only after the
   * compliance checks pass; before that the 200 body says NOT_COMPLIANT.
   */
  async productionCsid(
    creds: FatooraCredentials,
    complianceRequestId: string,
  ): Promise<CsidIssuance> {
    const res = await this.request('/production/csids', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json',
        'Accept-Version': 'V2',
        authorization: this.basicAuth(creds),
      },
      // snake_case per the OpenAPI file — NOT complianceRequestId.
      body: JSON.stringify({ compliance_request_id: complianceRequestId }),
    });
    return this.parseCsid(res);
  }

  /**
   * PATCH /production/csids — renewal: fresh CSR + fresh OTP, authorized by
   * the EXISTING production CSID (docs/10 endpoint 3).
   */
  async renewProductionCsid(
    creds: FatooraCredentials,
    csrBase64: string,
    otp: string,
  ): Promise<CsidIssuance> {
    const res = await this.request('/production/csids', {
      method: 'PATCH',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json',
        'Accept-Version': 'V2',
        OTP: otp,
        authorization: this.basicAuth(creds),
      },
      body: JSON.stringify({ csr: csrBase64 }),
    });
    return this.parseCsid(res);
  }

  /**
   * POST /compliance/invoices — the compliance checks between compliance
   * CSID and production CSID (docs/10 endpoint 4). Authorized by the
   * COMPLIANCE CSID; no Clearance-Status header on this one.
   */
  async complianceCheck(
    creds: FatooraCredentials,
    params: { invoiceHash: string; uuid: string; invoiceXmlBase64: string },
  ): Promise<ComplianceCheckOutcome> {
    const res = await this.request('/compliance/invoices', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json',
        'Accept-Version': 'V2',
        authorization: this.basicAuth(creds),
      },
      body: JSON.stringify({
        invoiceHash: params.invoiceHash,
        uuid: params.uuid,
        invoice: params.invoiceXmlBase64,
      }),
    });
    const parsed = this.tryJson<{
      reportingStatus?: string;
      clearanceStatus?: string;
      validationResults?: ComplianceCheckOutcome['validationResults'];
    }>(res.body);
    // Trap 3 applies HERE too: failures can ride inside HTTP 200. `ok`
    // demands FULL positive evidence, never absence of evidence:
    //  - HTTP 200 exactly (the compliance contract defines no 202);
    //  - a REPORTED/CLEARED disposition;
    //  - validationResults PRESENT with status PASS or WARNING (a body
    //    missing them, or carrying status ERROR with a conveniently
    //    empty error list, proves nothing passed);
    //  - zero errorMessages (either spelling).
    const vr = parsed?.validationResults;
    // MERGE both spellings, never coalesce: `errorMessages: []` beside a
    // populated `erroMessages` would otherwise short-circuit the check
    // and hide the real errors.
    const errors = [...(vr?.errorMessages ?? []), ...(vr?.erroMessages ?? [])];
    const vrStatus = String(vr?.status ?? '').toUpperCase();
    const disposition = parsed?.reportingStatus ?? parsed?.clearanceStatus ?? '';
    return {
      status: res.status,
      ok:
        res.status === 200 &&
        (disposition === 'REPORTED' || disposition === 'CLEARED') &&
        (vrStatus === 'PASS' || vrStatus === 'WARNING') &&
        errors.length === 0,
      reportingStatus: parsed?.reportingStatus ?? null,
      clearanceStatus: parsed?.clearanceStatus ?? null,
      validationResults: parsed?.validationResults ?? null,
      body: res.body,
    };
  }

  // ---- transport -----------------------------------------------------------

  /**
   * The sandbox sometimes holds POSTs open for minutes (observed live,
   * docs/10 "sandbox flakiness"). Without a client-side deadline one slow
   * day stalls the reporting worker on a single invoice, so EVERY outbound
   * call goes through here: abort after ZATCA_HTTP_TIMEOUT_MS (default
   * 90s). The AbortError surfaces as a thrown error — the exact path the
   * reporting worker already treats as "keep pending, retry next tick".
   */
  private async request(
    path: string,
    init: { method: string; headers: Record<string, string>; body: string },
  ): Promise<{ status: number; body: string }> {
    const timeoutMs = Number(process.env.ZATCA_HTTP_TIMEOUT_MS ?? 90_000);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(`${this.baseUrl}${path}`, {
        ...init,
        signal: controller.signal,
      });
      return { status: res.status, body: await res.text() };
    } finally {
      clearTimeout(timer);
    }
  }

  private basicAuth(creds: FatooraCredentials): string {
    return `Basic ${Buffer.from(`${creds.cert}:${creds.secret}`).toString(
      'base64',
    )}`;
  }

  private parseCsid(res: { status: number; body: string }): CsidIssuance {
    const parsed = this.tryJson<RawCsidBody>(res.body);
    return {
      status: res.status,
      dispositionMessage: parsed?.dispositionMessage ?? null,
      requestId:
        parsed?.requestID != null ? String(parsed.requestID) : null,
      binarySecurityToken: parsed?.binarySecurityToken ?? null,
      secret: parsed?.secret ?? null,
      errors: parsed?.errors ?? null,
      body: res.body,
    };
  }

  /**
   * Is this canonical base64 of an actual UBL invoice document? A
   * leading `<` proves nothing — base64 of the single byte `<` would
   * pass that, and this string is about to be archived as the LEGAL
   * copy. Three pieces of evidence are required:
   *   1. canonical base64 (Node's decoder alone accepts garbage);
   *   2. a root element whose local name is one clearance returns —
   *      `Invoice` for ZATCA today, with UBL's `CreditNote`/`DebitNote`
   *      accepted so a document-type change can never turn a genuinely
   *      cleared invoice into a false rejection;
   *   3. the UBL 2.1 namespace, which every conformant document MUST
   *      declare for that root — this is what separates a real invoice
   *      from a well-formed `<Invoice/>`.
   */
  private isBase64Xml(value: string): boolean {
    let text: string;
    try {
      text = decodeBase64Strict(value, 'clearedInvoice')
        .toString('utf8')
        .replace(/^﻿/, '');
    } catch {
      return false;
    }
    // Well-formed as a whole — a truncated document (tags left open) is
    // the corruption that a root-name regex cannot see.
    const root = scanXmlRoot(text);
    if (root === null) return false;

    const colon = root.name.indexOf(':');
    const prefix = colon === -1 ? '' : root.name.slice(0, colon);
    const localName = colon === -1 ? root.name : root.name.slice(colon + 1);
    const expectedNs = UBL_NAMESPACES[localName];
    if (expectedNs === undefined) return false;

    // The root must be IN that namespace, read from its OWN parsed
    // declaration — not matched anywhere in the text, which accepted
    // `…:xsd:Order-2`, a namespace on a child, or one hidden inside
    // another attribute's value.
    return (
      root.attributes.get(prefix === '' ? 'xmlns' : `xmlns:${prefix}`) ===
      expectedNs
    );
  }

  private tryJson<T>(body: string): T | null {
    try {
      return JSON.parse(body) as T;
    } catch {
      return null;
    }
  }
}
