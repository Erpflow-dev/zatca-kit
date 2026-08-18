# ZATCA golden invoice fixtures (doc 04-B5)

`simplified-invoice.xml` is the output of
`ZatcaInvoiceBuilder.pureXml(...)` from
`apps/pos_app/lib/features/zatca/zatca_invoice.dart` — the exact
"pure" (pre-signature) form the on-device signer hashes for the
PIH chain — evaluated with this fixed dataset:

| field | value |
|---|---|
| seller | CRN `1010010000`, VAT `399999999900003`, King Fahd Road 1234, Al Olaya, Riyadh 12244, registration name `شركة توريدات التجزئة` |
| kind / serial / uuid | sale (`388` / `0211010`), `INV-0001`, `8e6000cf-1a98-4174-b3e7-b5d5954bc10d` |
| issuedAtUtc / ICV / PIH | `2026-08-01T09:30:00Z`, `1`, sha256-of-"0" seed PIH |

**Keep `issuedAtUtc` in the past.** BR-KSA-04 rejects issue dates after the
validator's *current* date, and CI runs on UTC — a fixture stamped "today"
in a timezone ahead of UTC fails on the runner while passing locally
(happened 2026-08-18). Any fixed past date is fine; never "today".
| line | `Dates 1kg` ×2 PCE, 1150 halalas inclusive, 150 VAT (15%) → 10.00 excl / 1.50 VAT / 11.50 incl |
| payment / rounding | cash (`10`), none |

## What CI asserts

The `zatca-golden` job runs ZATCA's own SDK CLI (`fatoora -validate`)
against this file. **XSD, EN (EN16931), KSA and PIH categories must all
PASS** — a change to the XML builder that breaks schema/rule compliance
or the canonicalization contract fails the job.

**QR and SIGNATURE categories are expected to FAIL** for now: this is
the unsigned pure form, and the fixture carries no cryptographic stamp.
When the on-device signer lands, add a second, signed golden file and
tighten the CI step to require a global PASS on it.

## Regenerating

The XML is byte-exact output of the Dart builder — never hand-edit it.
To regenerate after an intentional builder change, evaluate
`ZatcaInvoiceBuilder.pureXml` with the dataset above (e.g. from a
temporary case in `apps/pos_app/test/zatca_invoice_test.dart` that
prints the string), overwrite this file, and re-run the SDK validation
locally if you have Java 11:

```
cd <sdk>/Apps   # SDK: docs/10 — local copy at D:\pos\tools\zatca-sdk\
FATOORA_HOME=$PWD ./fatoora -validate -invoice <this file>
```

Java 11 specifically: JDK 15+ removed secp256k1 from SunEC and the
SDK's signature validation dies on newer JREs.
