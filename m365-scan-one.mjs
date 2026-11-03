/**
 * m365-scan-one.mjs: run the Microsoft 365 account check on one tenant
 * from your own terminal.
 *
 *   M365_TENANT_ID=<tenant id> M365_CLIENT_ID=<app client id> node m365-scan-one.mjs
 *
 * Reads the certificate from ~/vigia-keys/vigia-scanner.crt and .key
 * (override with M365_CERT_PATH / M365_KEY_PATH). The private key is
 * only used to sign the sign-in request locally; it is never sent.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { scanM365Tenant } from "./m365-security.mjs";
import { sortFindings, scoreFindings, gradeForScore } from "./findings.mjs";

const tenantId = process.env.M365_TENANT_ID;
const clientId = process.env.M365_CLIENT_ID;
const certPath = process.env.M365_CERT_PATH || path.join(os.homedir(), "vigia-keys", "vigia-scanner.crt");
const keyPath = process.env.M365_KEY_PATH || path.join(os.homedir(), "vigia-keys", "vigia-scanner.key");

if (!tenantId || !clientId) {
  console.error("Set M365_TENANT_ID and M365_CLIENT_ID first. See the comment at the top of this file.");
  process.exit(1);
}

let certPem, keyPem;
try {
  // Paths come from the person running this on their own machine, not from customers.
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  certPem = fs.readFileSync(certPath, "utf8");
  // eslint-disable-next-line security/detect-non-literal-fs-filename
  keyPem = fs.readFileSync(keyPath, "utf8");
} catch (err) {
  console.error(`Couldn't read the certificate files: ${err.message}`);
  process.exit(1);
}

console.log("Signing in as Vigía Recon Scanner and reading the tenant (read-only)...\n");

try {
  const { findings, summary } = await scanM365Tenant({ tenantId, clientId, certPem, keyPem });
  const score = scoreFindings(findings);

  console.log(`Accounts score: ${score}/100 (grade ${gradeForScore(score)})`);
  console.log(`Billable users: ${summary.billableUsers} · Global Admins: ${summary.globalAdmins}`);
  console.log(`Two-factor data from: ${summary.mfaSource}`);
  console.log(`Security defaults: ${summary.securityDefaults === null ? "couldn't read" : summary.securityDefaults ? "on" : "off"}`);
  console.log(`Conditional Access readable: ${summary.conditionalAccessReadable ? "yes" : "no (needs Entra ID P1)"}`);
  console.log(`Mailboxes checked for forwarding: ${summary.mailboxesChecked}\n`);

  for (const f of sortFindings(findings)) {
    console.log(`[${f.severity.toUpperCase()}] ${f.title}`);
    console.log(`   ${f.detail}`);
    console.log(`   Fix: ${f.fix}\n`);
  }
  if (!findings.length) console.log("No account issues found.");
} catch (err) {
  console.error(`Scan failed: ${err.message}`);
  process.exit(1);
}
