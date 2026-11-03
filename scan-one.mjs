/**
 * scan-one.mjs — run the outside-in security scan on one domain
 * from your own terminal, no Supabase needed.
 *
 *   node scan-one.mjs example.com
 *   node scan-one.mjs example.com --token <verify-token>
 *
 * Without --token, only passive checks run. With --token, the
 * active checks run ONLY if that domain's DNS has the matching
 * vigiarecon-verify TXT record — same ownership rule as production.
 */

import { runSecurityScan } from "./security-scan.mjs";
import { isDomainVerified } from "./domain-verify.mjs";
import { isValidPublicHostname } from "./net-guard.mjs";

const hostname = (process.argv[2] || "").toLowerCase();
const tokenIdx = process.argv.indexOf("--token");
const token = tokenIdx > -1 ? process.argv[tokenIdx + 1] : null;

if (!isValidPublicHostname(hostname)) {
  console.error("Usage: node scan-one.mjs example.com [--token <verify-token>]");
  process.exit(1);
}

let verified = false;
if (token) {
  verified = await isDomainVerified(hostname, token);
  console.log(verified ? "✓ Ownership verified — active checks enabled" : "✗ Verification TXT record not found — passive checks only");
}

console.log(`Scanning ${hostname}...\n`);
const report = await runSecurityScan(hostname, { verified });

console.log(`Score: ${report.score}/100 (grade ${report.grade})`);
if (report.meta.tech.length) {
  console.log(`Software seen: ${report.meta.tech.map((t) => `${t.name} ${t.version}`).join(", ")}`);
}
if (report.meta.behindCdn) console.log("Behind a CDN — origin server ports aren't directly visible.");
console.log("");

for (const f of report.findings) {
  console.log(`[${f.severity.toUpperCase()}] ${f.title}`);
  console.log(`   ${f.detail}`);
  console.log(`   Fix: ${f.fix}\n`);
}
