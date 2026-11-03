/**
 * domain-verify.mjs
 * -----------------------------------------------------------------
 * Proves a customer actually controls a domain before Vigía Recon
 * runs any ACTIVE checks against it (requesting sensitive file
 * paths, etc.). Passive checks run on everything; active checks
 * only run on verified domains.
 *
 * Why: without this, anyone could add someone else's domain and
 * use Vigía Recon to probe it. That's unauthorized scanning, and it
 * would make Vigía Recon the tool doing it.
 *
 * How: same method Google Search Console and most SaaS tools use.
 * The dashboard shows a unique token; the customer adds it as a
 * DNS TXT record; we look for it here. It's re-checked on every
 * run, so if the domain changes hands and the record disappears,
 * active scanning stops automatically.
 *
 * Accepted record locations (either works):
 *   TXT  example.com                    "vigiarecon-verify=<token>"
 *   TXT  _vigiarecon.example.com        "vigiarecon-verify=<token>"
 *
 * Records made before the rename ("certwatch-verify=", or at
 * _certwatch.<domain>) still count, so nobody has to redo DNS.
 */

import dns from "node:dns/promises";

export function hasVerificationRecord(txtRecords, token) {
  if (!token) return false;
  const accepted = new Set([`vigiarecon-verify=${token}`, `certwatch-verify=${token}`]);
  return txtRecords.some((chunks) => accepted.has(chunks.join("").trim()));
}

export async function isDomainVerified(hostname, token) {
  const lookups = await Promise.all([
    dns.resolveTxt(hostname).catch(() => []),
    dns.resolveTxt(`_vigiarecon.${hostname}`).catch(() => []),
    dns.resolveTxt(`_certwatch.${hostname}`).catch(() => []), // pre-rename location
  ]);
  return hasVerificationRecord(lookups.flat(), token);
}
