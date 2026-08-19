import { Injectable, Logger } from '@nestjs/common';
import { DatabaseService } from '../../database/database.service';
import { FatooraClient } from './fatoora.client';

/**
 * The ≤24h B2C reporting loop (blueprint Part 4). Scans tenants with
 * pending invoices, reports each with the tenant's CSID credentials:
 *  - 2xx, or 409 "already reported earlier" → 'reported' + reported_at
 *  - 400 → status 'failed' (the INVOICE was rejected; retrying the same XML
 *    is pointless — surfaces in the failed-invoices alert)
 *  - network / 5xx, and 401/406 → stays 'pending', retried next tick. Those
 *    two are our credentials/headers being wrong, not the invoice's fault:
 *    failing the batch on them would burn a whole tenant's compliant queue
 *    on one bad config (docs/10 status-code table).
 *  - tenant without credentials → skipped (onboarding incomplete)
 *
 * Scheduling: a simple env-gated interval for now
 * (ZATCA_REPORTING_INTERVAL_MS; 0/absent = disabled — tests drive
 * runOnce() directly). Moves to BullMQ with the Redis infra so retries
 * get backoff + dead-letter alerting per the blueprint.
 */
@Injectable()
export class ZatcaReportingService {
  private readonly logger = new Logger(ZatcaReportingService.name);

  constructor(
    private readonly db: DatabaseService,
    private readonly fatoora: FatooraClient,
  ) {}

  /** One full scan; returns per-invoice outcomes for observability/tests. */
  async runOnce(batchPerTenant = 20): Promise<
    Array<{ invoiceId: string; outcome: 'reported' | 'failed' | 'skipped' | 'pending' }>
  > {
    const results: Array<{
      invoiceId: string;
      outcome: 'reported' | 'failed' | 'skipped' | 'pending';
    }> = [];

    const tenants = await this.db.query<{
      tenants_with_pending_invoices: string;
    }>('select tenants_with_pending_invoices()');

    for (const row of tenants.rows) {
      const tenantId = row.tenants_with_pending_invoices;
      await this.db.withTenant(tenantId, async (client) => {
        // Environment-scoped: credentials issued for one ZATCA
        // environment must never be replayed against another after an
        // ops switch of the base URL — mismatches skip instead of 401ing
        // (or worse, silently submitting to the wrong environment).
        const creds = await client.query(
          'select cert, secret from zatca_credentials where environment = $1',
          [this.fatoora.environment()],
        );
        const pending = await client.query(
          `select id, zatca_uuid, invoice_hash, xml from invoices
            where status = 'pending' order by icv limit $1`,
          [batchPerTenant],
        );

        if (creds.rows.length === 0) {
          for (const inv of pending.rows) {
            results.push({ invoiceId: inv.id, outcome: 'skipped' });
          }
          return;
        }

        for (const inv of pending.rows) {
          if (!inv.xml) {
            results.push({ invoiceId: inv.id, outcome: 'skipped' });
            continue;
          }
          try {
            const outcome = await this.fatoora.reportSimplified({
              creds: creds.rows[0],
              invoiceHash: inv.invoice_hash,
              uuid: inv.zatca_uuid,
              invoiceXmlBase64: Buffer.from(inv.xml).toString('base64'),
            });
            if (outcome.ok) {
              await client.query(
                `update invoices set status = 'reported', reported_at = now()
                  where id = $1`,
                [inv.id],
              );
              results.push({ invoiceId: inv.id, outcome: 'reported' });
            } else if (outcome.rejected) {
              this.logger.warn(
                `invoice ${inv.id} rejected (${outcome.status}): ${outcome.body}`,
              );
              await client.query(
                `update invoices set status = 'failed' where id = $1`,
                [inv.id],
              );
              results.push({ invoiceId: inv.id, outcome: 'failed' });
            } else {
              // 5xx — server side; leave pending for the next tick.
              results.push({ invoiceId: inv.id, outcome: 'pending' });
            }
          } catch (err) {
            this.logger.warn(`invoice ${inv.id} network error: ${String(err)}`);
            results.push({ invoiceId: inv.id, outcome: 'pending' });
          }
        }
      });
    }
    return results;
  }
}
