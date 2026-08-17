import { Injectable, Logger } from '@nestjs/common';
import { X509Certificate } from 'node:crypto';
import type { PoolClient } from 'pg';
import { DatabaseService } from '../../database/database.service';
import {
  ComplianceCheckOutcome,
  CsidIssuance,
  FatooraClient,
} from './fatoora.client';

/**
 * Onboarding failures the admin UI must explain, mapped to HTTP by the
 * controller: 409 = a gate (wrong order / compliance checks not passed),
 * >=500 = Fatoora upstream trouble, anything else = the request itself.
 */
export class OnboardingError extends Error {
  constructor(
    message: string,
    readonly httpStatus: number = 400,
  ) {
    super(message);
  }
}

interface CsidRow {
  kind: string;
  binary_security_token: string;
  secret: string;
  request_id: string | null;
  disposition: string;
  expires_at: Date | null;
  created_at: Date;
}

export interface CsidSummary {
  disposition: string;
  requestId: string | null;
  expiresAt: Date | null;
}

/**
 * The CSID onboarding chain (docs/10): compliance CSID → compliance checks
 * → production CSID, plus renewal. Every issuance is appended to
 * zatca_csids (0020); the newest ISSUED production CSID is mirrored into
 * zatca_credentials so the reporting worker (0004) keeps its untouched
 * `select cert, secret from zatca_credentials` read path.
 *
 * The three Fatoora environments are independent — every lookup here is
 * scoped to the environment the client is currently pointed at, so
 * switching ZATCA_API_BASE never lets a sandbox CSID leak into production
 * calls.
 */
@Injectable()
export class FatooraOnboardingService {
  private readonly logger = new Logger(FatooraOnboardingService.name);

  constructor(
    private readonly db: DatabaseService,
    private readonly client: FatooraClient,
  ) {}

  /** Which of the three environments ZATCA_API_BASE points at. */
  environment(): 'sandbox' | 'simulation' | 'production' {
    const base = process.env.ZATCA_API_BASE ?? '';
    if (base.includes('/simulation')) return 'simulation';
    if (base.endsWith('/core') || base.includes('/core/')) return 'production';
    return 'sandbox';
  }

  /**
   * Step 1 — POST /compliance with the EGS CSR + the taxpayer's Fatoora OTP
   * (1-hour validity; sandbox magic OTPs 123345/111111/222222). Stores the
   * compliance CSID; its requestID is what step 3 exchanges.
   */
  async requestComplianceCsid(
    tenantId: string,
    csrBase64: string,
    otp: string,
  ): Promise<CsidSummary> {
    const res = await this.client.complianceCsid(csrBase64, otp);
    this.ensureIssued(res, 'compliance CSID request');

    const expiresAt = csidExpiry(res.binarySecurityToken!);
    await this.db.withTenant(tenantId, (client) =>
      this.insertCsid(client, tenantId, 'compliance', res, expiresAt),
    );
    return {
      disposition: res.dispositionMessage!,
      requestId: res.requestId,
      expiresAt,
    };
  }

  /**
   * Step 2 — POST /compliance/invoices per test document, authorized by the
   * stored compliance CSID. ZATCA unlocks the production exchange only
   * after these pass; results are returned verbatim (including their
   * `erroMessages` spelling) so the admin UI can show what failed.
   */
  async runComplianceChecks(
    tenantId: string,
    invoices: Array<{ invoiceHash: string; uuid: string; invoice: string }>,
  ): Promise<
    Array<{ uuid: string } & Pick<ComplianceCheckOutcome, 'status' | 'ok' | 'validationResults'>>
  > {
    const cred = await this.latest(tenantId, 'compliance');
    if (!cred || cred.disposition !== 'ISSUED') {
      throw new OnboardingError(
        `no ISSUED compliance CSID for ${this.environment()} — run onboarding/compliance first`,
        409,
      );
    }

    const results = [];
    for (const inv of invoices) {
      const out = await this.client.complianceCheck(
        { cert: cred.binary_security_token, secret: cred.secret },
        {
          invoiceHash: inv.invoiceHash,
          uuid: inv.uuid,
          invoiceXmlBase64: inv.invoice,
        },
      );
      results.push({
        uuid: inv.uuid,
        status: out.status,
        ok: out.ok,
        validationResults: out.validationResults,
      });
    }
    return results;
  }

  /**
   * Step 3 — exchange the compliance requestID for the production CSID.
   * CRITICAL GATE (docs/10): while the compliance checks have not passed,
   * this returns HTTP **200** with dispositionMessage NOT_COMPLIANT. We
   * branch on the body, never the status — and store NOTHING unless the
   * disposition is ISSUED, so a NOT_COMPLIANT response can never become
   * reporting credentials.
   */
  async requestProductionCsid(tenantId: string): Promise<CsidSummary> {
    const cred = await this.latest(tenantId, 'compliance');
    if (!cred || cred.disposition !== 'ISSUED' || !cred.request_id) {
      throw new OnboardingError(
        `no ISSUED compliance CSID for ${this.environment()} — production CSID requires compliance onboarding first`,
        409,
      );
    }

    const res = await this.client.productionCsid(
      { cert: cred.binary_security_token, secret: cred.secret },
      cred.request_id,
    );
    this.ensureIssued(res, 'production CSID request');

    const expiresAt = csidExpiry(res.binarySecurityToken!);
    await this.db.withTenant(tenantId, async (client) => {
      await this.insertCsid(client, tenantId, 'production', res, expiresAt);
      await this.activateReportingCredentials(client, tenantId, res);
    });
    this.logger.log(
      `tenant ${tenantId}: production CSID issued (${this.environment()})`,
    );
    return {
      disposition: res.dispositionMessage!,
      requestId: res.requestId,
      expiresAt,
    };
  }

  /**
   * Renewal — PATCH /production/csids with a fresh CSR + fresh OTP,
   * authorized by the EXISTING production CSID. Certificates expire, so
   * this is a first-class flow; the fleet view surfaces expires_at exactly
   * so renewal happens before, not after, reporting starts to 401.
   */
  async renewProductionCsid(
    tenantId: string,
    csrBase64: string,
    otp: string,
  ): Promise<CsidSummary> {
    const cred = await this.latest(tenantId, 'production');
    if (!cred || cred.disposition !== 'ISSUED') {
      throw new OnboardingError(
        `no production CSID for ${this.environment()} to renew — run the onboarding chain first`,
        409,
      );
    }

    const res = await this.client.renewProductionCsid(
      { cert: cred.binary_security_token, secret: cred.secret },
      csrBase64,
      otp,
    );
    this.ensureIssued(res, 'production CSID renewal');

    const expiresAt = csidExpiry(res.binarySecurityToken!);
    await this.db.withTenant(tenantId, async (client) => {
      await this.insertCsid(client, tenantId, 'production', res, expiresAt);
      await this.activateReportingCredentials(client, tenantId, res);
    });
    return {
      disposition: res.dispositionMessage!,
      requestId: res.requestId,
      expiresAt,
    };
  }

  /** The fleet-view surface: disposition, environment, expiry per kind. */
  async status(tenantId: string): Promise<{
    environment: string;
    compliance: { disposition: string; requestedAt: Date } | null;
    production: {
      disposition: string;
      expiresAt: Date | null;
      issuedAt: Date;
    } | null;
    reportingCredentialsPresent: boolean;
  }> {
    const environment = this.environment();
    return this.db.withTenant(tenantId, async (client) => {
      const { rows } = await client.query<CsidRow>(
        `select distinct on (kind)
                kind, binary_security_token, secret, request_id,
                disposition, expires_at, created_at
           from zatca_csids
          where environment = $1
          order by kind, created_at desc`,
        [environment],
      );
      const creds = await client.query('select 1 from zatca_credentials');
      const compliance = rows.find((r) => r.kind === 'compliance') ?? null;
      const production = rows.find((r) => r.kind === 'production') ?? null;
      return {
        environment,
        compliance: compliance && {
          disposition: compliance.disposition,
          requestedAt: compliance.created_at,
        },
        production: production && {
          disposition: production.disposition,
          expiresAt: production.expires_at,
          issuedAt: production.created_at,
        },
        reportingCredentialsPresent: creds.rows.length > 0,
      };
    });
  }

  // ---- internals -----------------------------------------------------------

  /**
   * The single place that decides "did Fatoora actually issue a CSID".
   * NOT_COMPLIANT rides in on HTTP 200 (docs/10), so both checks are
   * needed: transport success AND dispositionMessage === 'ISSUED' with a
   * token+secret present.
   */
  private ensureIssued(res: CsidIssuance, what: string): void {
    if (res.status < 200 || res.status >= 300) {
      // 400 = ZATCA rejected the request itself (bad/expired OTP, bad CSR).
      throw new OnboardingError(
        `${what} failed (${res.status}): ${res.body}`,
        res.status >= 500 ? 502 : 400,
      );
    }
    if (
      res.dispositionMessage !== 'ISSUED' ||
      !res.binarySecurityToken ||
      !res.secret
    ) {
      throw new OnboardingError(
        `${what} refused: dispositionMessage=${res.dispositionMessage ?? 'missing'} — compliance checks not passed yet`,
        409,
      );
    }
  }

  private async insertCsid(
    client: PoolClient,
    tenantId: string,
    kind: 'compliance' | 'production',
    res: CsidIssuance,
    expiresAt: Date | null,
  ): Promise<void> {
    await client.query(
      `insert into zatca_csids
         (tenant_id, environment, kind, binary_security_token, secret,
          request_id, disposition, expires_at)
       values ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        tenantId,
        this.environment(),
        kind,
        res.binarySecurityToken,
        res.secret,
        res.requestId,
        res.dispositionMessage,
        expiresAt,
      ],
    );
  }

  /**
   * Mirror the fresh production CSID into zatca_credentials — the exact
   * row the reporting worker reads. Called ONLY from the ISSUED branches.
   */
  private async activateReportingCredentials(
    client: PoolClient,
    tenantId: string,
    res: CsidIssuance,
  ): Promise<void> {
    await client.query(
      `insert into zatca_credentials (tenant_id, environment, cert, secret, updated_at)
       values ($1, $2, $3, $4, now())
       on conflict (tenant_id) do update
         set environment = excluded.environment,
             cert = excluded.cert,
             secret = excluded.secret,
             updated_at = now()`,
      [tenantId, this.environment(), res.binarySecurityToken, res.secret],
    );
  }

  private async latest(
    tenantId: string,
    kind: 'compliance' | 'production',
  ): Promise<CsidRow | null> {
    return this.db.withTenant(tenantId, async (client) => {
      const { rows } = await client.query<CsidRow>(
        `select kind, binary_security_token, secret, request_id,
                disposition, expires_at, created_at
           from zatca_csids
          where environment = $1 and kind = $2
          order by created_at desc
          limit 1`,
        [this.environment(), kind],
      );
      return rows[0] ?? null;
    });
  }
}

/**
 * The binarySecurityToken base64-decodes to the certificate's PEM body
 * (docs/06 refs) — wrap and parse it for notAfter. Null when the token
 * does not parse as a certificate: expiry becomes "unknown" in the fleet
 * view rather than blocking onboarding.
 */
export function csidExpiry(binarySecurityToken: string): Date | null {
  try {
    const body = Buffer.from(binarySecurityToken, 'base64').toString('utf8');
    const pem = `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----`;
    const notAfter = new Date(new X509Certificate(pem).validTo);
    return Number.isNaN(notAfter.getTime()) ? null : notAfter;
  } catch {
    return null;
  }
}
