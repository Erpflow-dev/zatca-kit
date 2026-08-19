import { FatooraClient } from './fatoora-client';

/**
 * These lock the wire contract taken from ZATCA's own OpenAPI files
 * (docs/10). They are the cheap half of doc 04-B5: the expensive half is the
 * golden-file XML validation, but a header typo or a mis-encoded Basic
 * username fails EVERY invoice a tenant ever files, so it is worth a test
 * that never touches the network.
 */
type FetchArgs = [string, { headers: Record<string, string>; body: string }];

function stubFetch(status: number, body = '{}'): FetchArgs[] {
  const calls: FetchArgs[] = [];
  (globalThis as unknown as { fetch: unknown }).fetch = (
    url: string,
    init: unknown,
  ) => {
    calls.push([url, init as FetchArgs[1]]);
    return Promise.resolve({ status, text: () => Promise.resolve(body) });
  };
  return calls;
}

const creds = { cert: 'TUlJQ1BUQ0NBZU9n', secret: 's3cr3t=' };
/** A cleared-invoice stand-in that is REAL base64 of REAL XML. */
const XML_B64 = Buffer.from(
  '<?xml version="1.0" encoding="UTF-8"?>' +
    '<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2">' +
    '<cbc:ID xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">INV-1</cbc:ID>' +
    '</Invoice>',
).toString('base64');
const invoice = {
  invoiceHash: 'vLGQoYNoM3tf1XAxKpoNTSz/8pkdidXy47HWh0VQmu8=',
  uuid: '8e6000cf-1a98-4174-b3e7-b5d5954bc10d',
  invoiceXmlBase64: 'PD94bWw=',
};

describe('FatooraClient.reportSimplified', () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
    delete process.env.ZATCA_API_BASE;
  });

  it('sends the exact headers and body ZATCA requires', async () => {
    const calls = stubFetch(200);
    await new FatooraClient().reportSimplified({ creds, ...invoice });

    const [url, init] = calls[0];
    expect(url).toBe(
      'https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal' +
        '/invoices/reporting/single',
    );
    // Uppercase V2 — lowercase is a 406 for every invoice.
    expect(init.headers['Accept-Version']).toBe('V2');
    // Required header; '0' = clearance disabled, the B2C till's case.
    expect(init.headers['Clearance-Status']).toBe('0');
    // The binarySecurityToken is ALREADY base64: it is the username
    // verbatim. Encoding it again is the 401 this test exists to prevent.
    expect(init.headers.authorization).toBe(
      `Basic ${Buffer.from(`${creds.cert}:${creds.secret}`).toString('base64')}`,
    );
    expect(JSON.parse(init.body)).toEqual({
      invoiceHash: invoice.invoiceHash,
      uuid: invoice.uuid,
      invoice: invoice.invoiceXmlBase64,
    });
  });

  it('honours ZATCA_API_BASE so simulation/production are a config change', async () => {
    process.env.ZATCA_API_BASE =
      'https://gw-fatoora.zatca.gov.sa/e-invoicing/simulation';
    const calls = stubFetch(200);
    await new FatooraClient().reportSimplified({ creds, ...invoice });
    expect(calls[0][0]).toBe(
      'https://gw-fatoora.zatca.gov.sa/e-invoicing/simulation' +
        '/invoices/reporting/single',
    );
  });

  it('strips trailing slashes from ZATCA_API_BASE — no double-slash paths', async () => {
    process.env.ZATCA_API_BASE =
      'https://gw-fatoora.zatca.gov.sa/e-invoicing/simulation/';
    const calls = stubFetch(200);
    await new FatooraClient().reportSimplified({ creds, ...invoice });
    expect(calls[0][0]).toBe(
      'https://gw-fatoora.zatca.gov.sa/e-invoicing/simulation' +
        '/invoices/reporting/single',
    );
  });

  it('200 REPORTED contradicted by validationResults ERROR fails closed', async () => {
    // The top-level disposition says filed; the SAME body says the
    // invoice failed validation. Marking it permanently reported on the
    // strength of the contradicted disposition would bury the error.
    stubFetch(
      200,
      JSON.stringify({
        reportingStatus: 'REPORTED',
        validationResults: {
          status: 'ERROR',
          errorMessages: [{ code: 'BR-KSA-X', message: 'boom' }],
        },
      }),
    );
    const out = await new FatooraClient().reportSimplified({
      creds,
      ...invoice,
    });
    expect(out.ok).toBe(false);
  });

  it("200 REPORTED with errors only under ZATCA's erroMessages typo also fails closed", async () => {
    stubFetch(
      200,
      JSON.stringify({
        reportingStatus: 'REPORTED',
        validationResults: {
          status: 'PASS',
          errorMessages: [],
          erroMessages: [{ code: 'BR-KSA-Y', message: 'hidden' }],
        },
      }),
    );
    const out = await new FatooraClient().reportSimplified({
      creds,
      ...invoice,
    });
    expect(out.ok).toBe(false);
  });

  it('200 REPORTED with a PASS validationResults block stays ok', async () => {
    stubFetch(
      200,
      JSON.stringify({
        reportingStatus: 'REPORTED',
        validationResults: { status: 'PASS', errorMessages: [] },
      }),
    );
    const out = await new FatooraClient().reportSimplified({
      creds,
      ...invoice,
    });
    expect(out.ok).toBe(true);
  });

  it('treats 202 with reportingStatus REPORTED as reported', async () => {
    // Live shape 2026-08-19: 202 = accepted with warnings, body still
    // carries reportingStatus REPORTED.
    stubFetch(202, '{"reportingStatus":"REPORTED"}');
    const out = await new FatooraClient().reportSimplified({
      creds,
      ...invoice,
    });
    expect(out).toMatchObject({
      ok: true,
      rejected: false,
      reportingStatus: 'REPORTED',
    });
  });

  it.each([200, 202])(
    '%i with an EMPTY body fails closed — no REPORTED, no success',
    async (status) => {
      // A bare 2xx proves nothing; marking the invoice reported forever
      // on it would fail open.
      stubFetch(status, '{}');
      const out = await new FatooraClient().reportSimplified({
        creds,
        ...invoice,
      });
      expect(out.ok).toBe(false);
      expect(out.rejected).toBe(false);
    },
  );

  it.each([409, 208])(
    'treats %i as duplicate-SUCCESS — ZATCA already has the invoice',
    async (status) => {
      // Our crash-safe retry produces this whenever the connection died
      // after ZATCA committed the report (spec documented 208; the live
      // service moved to 409 — both count). Calling it a rejection would
      // mark a compliant invoice 'failed' forever and raise a false alert.
      stubFetch(status, 'Invoice was already Reported successfully earlier.');
      const out = await new FatooraClient().reportSimplified({
        creds,
        ...invoice,
      });
      expect(out.ok).toBe(true);
      expect(out.rejected).toBe(false);
      expect(out.duplicate).toBe(true);
    },
  );

  it('rejects ONLY on 400 — the one code that blames the invoice', async () => {
    stubFetch(400, 'bad xml');
    const out = await new FatooraClient().reportSimplified({
      creds,
      ...invoice,
    });
    expect(out).toMatchObject({ ok: false, rejected: true });
  });

  it.each([401, 406])(
    'leaves %i pending — that is our config, not a bad invoice',
    async (status) => {
      stubFetch(status);
      const out = await new FatooraClient().reportSimplified({
        creds,
        ...invoice,
      });
      // Neither ok nor rejected => the worker keeps it 'pending' and retries
      // once the credentials/headers are fixed, instead of burning the whole
      // tenant queue to 'failed' on one bad config.
      expect(out.ok).toBe(false);
      expect(out.rejected).toBe(false);
    },
  );

  it('leaves 5xx pending for the next tick', async () => {
    stubFetch(503, 'down');
    const out = await new FatooraClient().reportSimplified({
      creds,
      ...invoice,
    });
    expect(out).toMatchObject({ ok: false, rejected: false, status: 503 });
  });
});

describe('FatooraClient timeout hardening', () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
    delete process.env.ZATCA_HTTP_TIMEOUT_MS;
  });

  it('aborts a hung sandbox call after ZATCA_HTTP_TIMEOUT_MS', async () => {
    // The sandbox has held POSTs open >4 minutes (docs/10, observed live).
    // This fake never resolves — it only rejects when the client's own
    // AbortController fires, proving the deadline exists client-side.
    process.env.ZATCA_HTTP_TIMEOUT_MS = '25';
    globalThis.fetch = ((_url: unknown, init: { signal: AbortSignal }) =>
      new Promise((_resolve, reject) => {
        init.signal.addEventListener('abort', () =>
          reject(
            Object.assign(new Error('This operation was aborted'), {
              name: 'AbortError',
            }),
          ),
        );
      })) as unknown as typeof fetch;

    // The abort surfaces as a THROWN error — exactly the path the reporting
    // worker maps to "keep the invoice pending, retry next tick".
    await expect(
      new FatooraClient().reportSimplified({ creds, ...invoice }),
    ).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('network rejections pass through untouched (worker keeps pending)', async () => {
    globalThis.fetch = (() =>
      Promise.reject(new Error('ECONNRESET'))) as unknown as typeof fetch;
    await expect(
      new FatooraClient().complianceCsid('Q1NS', '123345'),
    ).rejects.toThrow('ECONNRESET');
  });
});

describe('FatooraClient onboarding endpoints', () => {
  const realFetch = globalThis.fetch;
  type Init = {
    method: string;
    headers: Record<string, string>;
    body: string;
  };
  let calls: Array<[string, Init]>;

  function stub(status: number, body: string): void {
    calls = [];
    (globalThis as unknown as { fetch: unknown }).fetch = (
      url: string,
      init: unknown,
    ) => {
      calls.push([url, init as Init]);
      return Promise.resolve({ status, text: () => Promise.resolve(body) });
    };
  }

  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  const issued = JSON.stringify({
    requestID: 1234567890123,
    dispositionMessage: 'ISSUED',
    binarySecurityToken: 'TUlJ',
    secret: 'c2VjcmV0',
    errors: null,
  });

  it('complianceCsid: OTP header, NO auth, {csr} body, requestID as string', async () => {
    stub(200, issued);
    const out = await new FatooraClient().complianceCsid('Q1NSLXBlbQ==', '123345');

    const [url, init] = calls[0];
    expect(url).toBe(
      'https://gw-fatoora.zatca.gov.sa/e-invoicing/developer-portal/compliance',
    );
    expect(init.method).toBe('POST');
    expect(init.headers.OTP).toBe('123345');
    expect(init.headers['Accept-Version']).toBe('V2');
    // First call an EGS ever makes — there are no credentials yet.
    expect(init.headers.authorization).toBeUndefined();
    expect(JSON.parse(init.body)).toEqual({ csr: 'Q1NSLXBlbQ==' });
    // requestID is a 13-digit number in JSON; we keep it lossless as string.
    expect(out).toMatchObject({
      status: 200,
      dispositionMessage: 'ISSUED',
      requestId: '1234567890123',
      binarySecurityToken: 'TUlJ',
      secret: 'c2VjcmV0',
    });
  });

  it('productionCsid: Basic compliance auth + snake_case compliance_request_id', async () => {
    stub(200, issued);
    await new FatooraClient().productionCsid(creds, '1234567890123');

    const [url, init] = calls[0];
    expect(url).toMatch(/\/production\/csids$/);
    expect(init.method).toBe('POST');
    expect(init.headers.authorization).toBe(
      `Basic ${Buffer.from(`${creds.cert}:${creds.secret}`).toString('base64')}`,
    );
    expect(JSON.parse(init.body)).toEqual({
      compliance_request_id: '1234567890123',
    });
  });

  it('surfaces NOT_COMPLIANT arriving with HTTP 200 — the docs/10 gate', async () => {
    stub(
      200,
      JSON.stringify({ requestID: 1, dispositionMessage: 'NOT_COMPLIANT' }),
    );
    const out = await new FatooraClient().productionCsid(creds, '1');
    // Status alone says success; only the body tells the truth.
    expect(out.status).toBe(200);
    expect(out.dispositionMessage).toBe('NOT_COMPLIANT');
    expect(out.binarySecurityToken).toBeNull();
  });

  it('renewProductionCsid: PATCH with OTP + existing production auth', async () => {
    stub(200, issued);
    await new FatooraClient().renewProductionCsid(creds, 'Q1NS', '123345');

    const [url, init] = calls[0];
    expect(url).toMatch(/\/production\/csids$/);
    expect(init.method).toBe('PATCH');
    expect(init.headers.OTP).toBe('123345');
    expect(init.headers.authorization).toContain('Basic ');
    expect(JSON.parse(init.body)).toEqual({ csr: 'Q1NS' });
  });

  it("complianceCheck: preserves ZATCA's own erroMessages typo and omits Clearance-Status", async () => {
    stub(
      200,
      JSON.stringify({
        reportingStatus: 'REPORTED',
        validationResults: {
          status: 'PASS',
          infoMessages: [],
          warningMessages: [],
          erroMessages: [], // their spelling — renaming reads as undefined
        },
      }),
    );
    const out = await new FatooraClient().complianceCheck(creds, {
      invoiceHash: invoice.invoiceHash,
      uuid: invoice.uuid,
      invoiceXmlBase64: invoice.invoiceXmlBase64,
    });

    const [url, init] = calls[0];
    expect(url).toMatch(/\/compliance\/invoices$/);
    // Clearance-Status belongs to reporting/clearance only (docs/10 #4).
    expect(init.headers['Clearance-Status']).toBeUndefined();
    expect(out.ok).toBe(true);
    expect(out.validationResults?.erroMessages).toEqual([]);
  });

  it('complianceCheck: errors hiding under the erroMessages spelling beside an EMPTY errorMessages fail closed', async () => {
    // Coalescing (?? ) between the two spellings would pick the empty
    // `errorMessages` array and never look at the populated one. The
    // spellings must MERGE.
    stub(
      200,
      JSON.stringify({
        reportingStatus: 'REPORTED',
        validationResults: {
          status: 'PASS',
          errorMessages: [],
          erroMessages: [{ code: 'BR-KSA-Z', message: 'real error' }],
        },
      }),
    );
    const out = await new FatooraClient().complianceCheck(creds, {
      invoiceHash: invoice.invoiceHash,
      uuid: invoice.uuid,
      invoiceXmlBase64: invoice.invoiceXmlBase64,
    });
    expect(out.ok).toBe(false);
  });

  it('complianceCheck: 200 with an EMPTY body fails closed', async () => {
    // No validationResults, no disposition — nothing proves ZATCA
    // validated anything. ok: true here would let onboarding claim a
    // compliance pass with zero evidence.
    stub(200, '{}');
    const out = await new FatooraClient().complianceCheck(creds, {
      invoiceHash: invoice.invoiceHash,
      uuid: invoice.uuid,
      invoiceXmlBase64: invoice.invoiceXmlBase64,
    });
    expect(out.ok).toBe(false);
  });

  it('complianceCheck: REPORTED without validationResults fails closed', async () => {
    stub(200, JSON.stringify({ reportingStatus: 'REPORTED' }));
    const out = await new FatooraClient().complianceCheck(creds, {
      invoiceHash: invoice.invoiceHash,
      uuid: invoice.uuid,
      invoiceXmlBase64: invoice.invoiceXmlBase64,
    });
    expect(out.ok).toBe(false);
  });

  it('complianceCheck: status ERROR with an empty error list fails closed', async () => {
    // The convenient-empty-list trap: status says ERROR, the list says
    // nothing — believe the status.
    stub(
      200,
      JSON.stringify({
        reportingStatus: 'REPORTED',
        validationResults: { status: 'ERROR', errorMessages: [] },
      }),
    );
    const out = await new FatooraClient().complianceCheck(creds, {
      invoiceHash: invoice.invoiceHash,
      uuid: invoice.uuid,
      invoiceXmlBase64: invoice.invoiceXmlBase64,
    });
    expect(out.ok).toBe(false);
  });

  it('complianceCheck: 202 is not a defined compliance response — not ok', async () => {
    stub(
      202,
      JSON.stringify({
        reportingStatus: 'REPORTED',
        validationResults: { status: 'PASS', errorMessages: [] },
      }),
    );
    const out = await new FatooraClient().complianceCheck(creds, {
      invoiceHash: invoice.invoiceHash,
      uuid: invoice.uuid,
      invoiceXmlBase64: invoice.invoiceXmlBase64,
    });
    expect(out.ok).toBe(false);
  });

  it('clearStandard: 200 with an EMPTY body fails closed', async () => {
    // "Cleared" without the stamped clearedInvoice is a state a taxpayer
    // must never be left in — the legal copy IS the point of clearance.
    stub(200, '{}');
    const out = await new FatooraClient().clearStandard({
      creds,
      invoiceHash: invoice.invoiceHash,
      uuid: invoice.uuid,
      invoiceXmlBase64: invoice.invoiceXmlBase64,
    });
    expect(out.ok).toBe(false);
    expect(out.duplicate).toBe(false);
  });

  it('clearStandard: 200 carries the legal clearedInvoice, not a duplicate', async () => {
    stub(
      200,
      JSON.stringify({ clearanceStatus: 'CLEARED', clearedInvoice: XML_B64 }),
    );
    const out = await new FatooraClient().clearStandard({
      creds,
      invoiceHash: invoice.invoiceHash,
      uuid: invoice.uuid,
      invoiceXmlBase64: invoice.invoiceXmlBase64,
    });
    expect(out.ok).toBe(true);
    expect(out.duplicate).toBe(false);
    expect(out.clearedInvoiceBase64).toBe(XML_B64);
  });

  it('clearStandard: CLEARED contradicted by validationResults fails closed', async () => {
    // Archiving an invoice ZATCA's own body says is invalid — as the
    // LEGAL copy — is the worst outcome this call can produce.
    for (const vr of [
      { status: 'ERROR', errorMessages: [{ code: 'BR-KSA-X' }] },
      { status: 'PASS', erroMessages: [{ code: 'BR-KSA-Y' }] }, // typo spelling
      { status: 'ERROR', errorMessages: [] }, // status alone still counts
    ]) {
      stub(
        200,
        JSON.stringify({
          clearanceStatus: 'CLEARED',
          clearedInvoice: XML_B64,
          validationResults: vr,
        }),
      );
      const out = await new FatooraClient().clearStandard({
        creds,
        invoiceHash: invoice.invoiceHash,
        uuid: invoice.uuid,
        invoiceXmlBase64: invoice.invoiceXmlBase64,
      });
      expect(out.ok).toBe(false);
    }

    // A PASS block alongside CLEARED is still a success.
    stub(
      200,
      JSON.stringify({
        clearanceStatus: 'CLEARED',
        clearedInvoice: XML_B64,
        validationResults: { status: 'PASS', errorMessages: [] },
      }),
    );
    const good = await new FatooraClient().clearStandard({
      creds,
      invoiceHash: invoice.invoiceHash,
      uuid: invoice.uuid,
      invoiceXmlBase64: invoice.invoiceXmlBase64,
    });
    expect(good.ok).toBe(true);
  });

  it('clearStandard: CLEARED with a clearedInvoice that is not base64 XML fails closed', async () => {
    // The stamped copy becomes the LEGAL invoice we archive and hand to
    // the buyer — garbage must never be filed as a legal document.
    for (const junk of [
      '*** not base64 ***',
      'AAAA', // canonical base64, but the bytes are not XML
      'PD94bWw', // non-canonical (unpadded) even though it decodes
      Buffer.from('<').toString('base64'), // a single '<' is not a document
      Buffer.from('<?xml version="1.0"?>').toString('base64'), // declaration only
      Buffer.from('<Invoice/>').toString('base64'), // well-formed, but no UBL
      Buffer.from('<html><body>oops</body></html>').toString('base64'), // wrong root
    ]) {
      stub(
        200,
        JSON.stringify({ clearanceStatus: 'CLEARED', clearedInvoice: junk }),
      );
      const out = await new FatooraClient().clearStandard({
        creds,
        invoiceHash: invoice.invoiceHash,
        uuid: invoice.uuid,
        invoiceXmlBase64: invoice.invoiceXmlBase64,
      });
      expect(out.ok).toBe(false);
    }
  });

  it('clearStandard: 208 WITH the contract payload is ok + duplicate', async () => {
    // The official contract's 208 still carries CLEARED + clearedInvoice.
    stub(
      208,
      JSON.stringify({ clearanceStatus: 'CLEARED', clearedInvoice: XML_B64 }),
    );
    const out = await new FatooraClient().clearStandard({
      creds,
      invoiceHash: invoice.invoiceHash,
      uuid: invoice.uuid,
      invoiceXmlBase64: invoice.invoiceXmlBase64,
    });
    expect(out.ok).toBe(true);
    expect(out.duplicate).toBe(true);
    expect(out.clearedInvoiceBase64).toBe(XML_B64);
  });

  it.each([208, 409])(
    'clearStandard: EMPTY %i is duplicate but NOT ok — no legal copy here',
    async (status) => {
      // A bare replay status without the stamped XML proves nothing this
      // reply can vouch for; the caller resolves it against its archived
      // first response. ok: true here would record "cleared" with no
      // legal document anywhere.
      stub(status, '{}');
      const out = await new FatooraClient().clearStandard({
        creds,
        invoiceHash: invoice.invoiceHash,
        uuid: invoice.uuid,
        invoiceXmlBase64: invoice.invoiceXmlBase64,
      });
      expect(out.ok).toBe(false);
      expect(out.duplicate).toBe(true);
      expect(out.rejected).toBe(false);
      expect(out.clearedInvoiceBase64).toBeNull();
    },
  );
});
