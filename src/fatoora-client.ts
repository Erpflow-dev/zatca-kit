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
   * Already cleared earlier (208 per spec, 409 on the live service). ok
   * stays true BUT clearedInvoiceBase64 is null — the legal stamped copy
   * came with the FIRST response; callers must use their archived one,
   * never treat this reply as carrying it.
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
  private readonly baseUrl =
    process.env.ZATCA_API_BASE ??
    'https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal';

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
    return {
      ok: (res.status >= 200 && res.status < 300) || duplicate,
      rejected: res.status === 400,
      duplicate,
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
    // Duplicate submission: the spec documents 208, the live service now
    // sends 409 (the same 208→409 migration production integrators log).
    // A duplicate is a success — the invoice WAS cleared — but this
    // response has no clearedInvoice: the caller's archived copy from the
    // first submission is the legal document, and `duplicate` makes that
    // impossible to miss.
    const duplicate = res.status === 208 || res.status === 409;
    const parsed = this.tryJson<{
      clearanceStatus?: string;
      clearedInvoice?: string;
    }>(res.body);
    // A FIRST-time clearance is only ok with the evidence in hand:
    // CLEARED + the stamped clearedInvoice (the legal copy). A 200 with
    // an empty body fails CLOSED — "cleared" without the legal document
    // is exactly the state a taxpayer must never be left in.
    const cleared =
      res.status >= 200 &&
      res.status < 300 &&
      !duplicate &&
      parsed?.clearanceStatus === 'CLEARED' &&
      typeof parsed?.clearedInvoice === 'string' &&
      parsed.clearedInvoice.length > 0;
    return {
      ok: cleared || duplicate,
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
    // demands POSITIVE evidence, never absence of evidence: a disposition
    // must be present and not NOT_*, and errorMessages (either spelling)
    // must be empty. An empty body fails CLOSED — a 200 with `{}` proves
    // nothing was validated.
    const errors =
      parsed?.validationResults?.errorMessages ??
      parsed?.validationResults?.erroMessages ??
      [];
    const disposition = parsed?.reportingStatus ?? parsed?.clearanceStatus ?? '';
    return {
      status: res.status,
      ok:
        (res.status === 200 || res.status === 202) &&
        errors.length === 0 &&
        disposition.length > 0 &&
        !disposition.startsWith('NOT_'),
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

  private tryJson<T>(body: string): T | null {
    try {
      return JSON.parse(body) as T;
    } catch {
      return null;
    }
  }
}
