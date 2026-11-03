/**
 * Vigía Recon — core monitoring check
 * -----------------------------------------------------------------
 * Runs once a day via GitHub Actions. Pulls every real account and
 * domain from Supabase, checks each one (SSL, domain registration,
 * Certificate Transparency, DNS changes), sends alerts through
 * Resend, and saves results back to Supabase — no more local
 * alert-state.json file, and no more hardcoded test account.
 *
 * Also runs the outside-in security scan (security-scan.mjs):
 * email spoofing defenses, web exposure, known CVEs, and — for
 * domains the customer has verified via DNS — active checks for
 * leaked files like .git and .env.
 */

import { createClient } from "@supabase/supabase-js";
import { checkSSLExpiry } from "./ssl-check.mjs";
import { checkDomainExpiryWithRetry } from "./rdap-lookup.mjs";
import { checkNewCertificates } from "./cert-transparency.mjs";
import { getDnsSnapshot, hasDnsChanged } from "./dns-check.mjs";
import { extractSubdomains, checkSubdomainTakeovers } from "./subdomain-takeover.mjs";
import { runSecurityScan } from "./security-scan.mjs";
import { isDomainVerified } from "./domain-verify.mjs";
import { ALERT_SEVERITIES } from "./findings.mjs";

const ALERT_THRESHOLDS = [30, 14, 3]; // days out
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// ---- 1. Pull every domain to check, from the real database ---------

async function loadDomainsToCheck() {
  const { data, error } = await supabase
    .from("domains")
    .select("id, hostname, verify_token, verified_at, accounts(email)");

  if (error) throw new Error(`Failed to load domains: ${error.message}`);

  return data.map((row) => ({
    domainId: row.id,
    hostname: row.hostname,
    email: row.accounts.email,
    verifyToken: row.verify_token,
    wasVerified: Boolean(row.verified_at),
  }));
}

// ---- 2. Load / save the "notebook" — now a real database table -----

function defaultDomainState() {
  return {
    ssl: null, domain: null, knownCertIds: [], dnsSnapshot: null, flaggedTakeoverHostnames: [],
    securityAlertedKeys: [], securityFindings: [], securityScore: null, lastSecurityScanAt: null,
  };
}

async function loadState() {
  const { data, error } = await supabase.from("alert_state").select("*");
  if (error) throw new Error(`Failed to load alert state: ${error.message}`);

  const state = {};
  for (const row of data) {
    state[row.domain_id] = {
      ssl: row.ssl_tier_alerted,
      domain: row.domain_tier_alerted,
      knownCertIds: row.known_cert_ids || [],
      dnsSnapshot: row.dns_snapshot,
      flaggedTakeoverHostnames: row.flagged_takeover_hostnames || [],
      securityAlertedKeys: row.security_alerted_keys || [],
      securityFindings: row.security_findings || [],
      securityScore: row.security_score,
      lastSecurityScanAt: row.last_security_scan_at,
    };
  }
  return state;
}

async function saveState(state) {
  const rows = Object.entries(state).map(([domainId, s]) => ({
    domain_id: domainId,
    ssl_tier_alerted: s.ssl,
    domain_tier_alerted: s.domain,
    known_cert_ids: s.knownCertIds,
    dns_snapshot: s.dnsSnapshot,
    flagged_takeover_hostnames: s.flaggedTakeoverHostnames,
    last_checked_at: new Date().toISOString(),
    last_ssl_days_left: s.lastSslDaysLeft ?? null,
    last_domain_days_left: s.lastDomainDaysLeft ?? null,
    security_findings: s.securityFindings,
    security_score: s.securityScore,
    security_alerted_keys: s.securityAlertedKeys,
    last_security_scan_at: s.lastSecurityScanAt,
  }));

  const { error } = await supabase.from("alert_state").upsert(rows, {
    onConflict: "domain_id",
  });
  if (error) throw new Error(`Failed to save alert state: ${error.message}`);
}

function currentTier(daysLeft) {
  const sorted = [...ALERT_THRESHOLDS].sort((a, b) => a - b);
  for (const t of sorted) {
    if (daysLeft <= t) return t;
  }
  return null;
}

// ---- 3. Alerting -------------------------------------------------

async function sendAlert(toEmail, subject, body) {
  await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: "Vigía Recon <onboarding@resend.dev>",
      to: toEmail,
      subject,
      text: body,
    }),
  });
}

function shouldAlert(state, domainId, checkType, daysLeft) {
  const tier = currentTier(daysLeft);
  const lastAlerted = state[domainId][checkType];

  if (tier === null) {
    state[domainId][checkType] = null;
    return false;
  }
  if (tier === lastAlerted) return false;

  state[domainId][checkType] = tier;
  return true;
}

// ---- 4. Outside-in security scan ---------------------------------

const SEVERITY_ICON = new Map([["critical", "🚨"], ["high", "🔴"], ["medium", "🟠"], ["low", "🟡"], ["info", "ℹ️"]]);

async function runSecurityForDomain(domainState, { domainId, hostname, email, verifyToken, wasVerified }) {
  // Ownership is re-checked every run, so active scanning stops on
  // its own if the TXT record is removed or the domain changes hands.
  const verified = await isDomainVerified(hostname, verifyToken);
  if (verified !== wasVerified) {
    console.log(`  Verification: ${verified ? "now verified" : "no longer verified"}`);
    const { error } = await supabase
      .from("domains")
      .update({ verified_at: verified ? new Date().toISOString() : null })
      .eq("id", domainId);
    if (error) console.error(`  Couldn't save verification status:`, error.message);
  }

  const report = await runSecurityScan(hostname, { verified });
  console.log(`  Security: score ${report.score} (${report.grade}), ${report.findings.length} finding(s)${verified ? ", active checks ran" : ""}`);

  // Alert on medium+ findings we haven't already emailed about.
  // Keys of resolved findings drop off, so a problem that comes
  // back later gets alerted again.
  const alertable = report.findings.filter((f) => ALERT_SEVERITIES.has(f.severity));
  const alreadySent = new Set(domainState.securityAlertedKeys);
  const fresh = alertable.filter((f) => !alreadySent.has(f.key));

  if (fresh.length > 0) {
    console.log(`  → Sending security alert (${fresh.length} new) to ${email}`);
    const lines = fresh.map(
      (f) => `${SEVERITY_ICON.get(f.severity) || ""} [${f.severity.toUpperCase()}] ${f.title}\n   ${f.detail}\n   Fix: ${f.fix}`
    );
    const worst = fresh[0].severity; // findings are sorted worst-first
    await sendAlert(
      email,
      `${SEVERITY_ICON.get(worst) || ""} ${fresh.length} new security finding(s) for ${hostname} — score ${report.score}/100`,
      `Vigía Recon looked at ${hostname} the way an attacker would, from the outside.\n\nScore: ${report.score}/100 (grade ${report.grade})\n\n${lines.join("\n\n")}\n\nFull report in your dashboard: https://vigiarecon.com/dashboard.html`
    );
  }

  domainState.securityAlertedKeys = alertable.map((f) => f.key);
  domainState.securityFindings = report.findings;
  domainState.securityScore = report.score;
  domainState.lastSecurityScanAt = report.scannedAt;
}

// ---- 5. Main runner ------------------------------------------------

async function runChecks() {
  const domains = await loadDomainsToCheck();
  const state = await loadState();

  for (const { domainId, hostname, email, verifyToken, wasVerified } of domains) {
    console.log(`Checking ${hostname} (${email})...`);
    state[domainId] = { ...defaultDomainState(), ...state[domainId] };

    try {
      const ssl = await checkSSLExpiry(hostname);
      console.log(`  SSL: ${ssl.daysLeft} days left`);
      state[domainId].lastSslDaysLeft = ssl.daysLeft;
      if (shouldAlert(state, domainId, "ssl", ssl.daysLeft)) {
        console.log(`  → Sending SSL alert to ${email}`);
        await sendAlert(
          email,
          `⚠️ SSL certificate for ${hostname} expires in ${ssl.daysLeft} days`,
          `The SSL certificate for ${hostname} expires on ${ssl.expiresAt.toDateString()}. Renew it before then to avoid a browser security warning.`
        );
      } else {
        console.log(`  (no new alert needed)`);
      }
    } catch (err) {
      console.error(`  SSL check failed:`, err.message);
    }

    // Separate from the SSL check: a site that can't serve HTTPS
    // (the case where you most need to know) still gets its domain
    // registration checked.
    try {
      const reg = await checkDomainExpiryWithRetry(hostname);
      console.log(`  Domain: ${reg.daysLeft} days left`);
      state[domainId].lastDomainDaysLeft = reg.daysLeft;
      if (shouldAlert(state, domainId, "domain", reg.daysLeft)) {
        console.log(`  → Sending domain alert to ${email}`);
        await sendAlert(
          email,
          `⚠️ Domain registration for ${hostname} expires in ${reg.daysLeft} days`,
          `${hostname} is registered until ${reg.expiresAt.toDateString()}. Renew it to keep the domain from lapsing.`
        );
      } else {
        console.log(`  (no new alert needed)`);
      }
    } catch (err) {
      console.error(`  Domain expiry check failed:`, err.message);
    }

    let ctCerts = null;
    try {
      const { newCertificates, allCertIds, allCerts } = await checkNewCertificates(
        hostname,
        state[domainId].knownCertIds
      );
      const isFirstRun = state[domainId].knownCertIds.length === 0;
      console.log(`  CT: ${newCertificates.length} new certificate(s)`);

      if (!isFirstRun && newCertificates.length > 0) {
        console.log(`  → Sending CT alert to ${email}`);
        const summary = newCertificates
          .map((c) => `- Issued ${c.not_before} by ${c.issuer_name}`)
          .join("\n");
        await sendAlert(
          email,
          `🔍 New SSL certificate detected for ${hostname}`,
          `A new SSL certificate was just issued for ${hostname}. If you just renewed it, this is nothing to worry about. If not, worth checking immediately.\n\n${summary}`
        );
      }
      state[domainId].knownCertIds = allCertIds;
      ctCerts = allCerts;
    } catch (err) {
      console.error(`  CT check failed (crt.sh may be down):`, err.message);
    }

    try {
      if (ctCerts) {
        const subdomains = extractSubdomains(ctCerts, hostname);
        const { newFindings, allFlaggedHostnames } = await checkSubdomainTakeovers(
          subdomains,
          state[domainId].flaggedTakeoverHostnames
        );
        console.log(`  Takeover: checked ${subdomains.length} subdomain(s), ${newFindings.length} new finding(s)`);

        if (newFindings.length > 0) {
          console.log(`  → Sending subdomain takeover alert to ${email}`);
          const summary = newFindings
            .map(
              (f) =>
                `- ${f.hostname} → CNAME points to ${f.cnameTarget} (${f.service}${
                  f.confirmed ? ", confirmed unclaimed" : ", unreachable — worth a manual look"
                })`
            )
            .join("\n");
          await sendAlert(
            email,
            `🚨 Possible subdomain takeover risk for ${hostname}`,
            `One or more subdomains of ${hostname} point to a cloud resource that looks unclaimed. If registered by someone else, they could serve content under your domain.\n\n${summary}`
          );
        }
        state[domainId].flaggedTakeoverHostnames = allFlaggedHostnames;
      } else {
        console.log(`  Takeover: skipped (CT check failed above, no subdomain list available)`);
      }
    } catch (err) {
      console.error(`  Takeover check failed:`, err.message);
    }

    try {
      const currentSnapshot = await getDnsSnapshot(hostname);
      const changed = hasDnsChanged(state[domainId].dnsSnapshot, currentSnapshot);
      console.log(`  DNS: ${changed ? "changed" : "unchanged"}`);

      if (changed) {
        console.log(`  → Sending DNS change alert to ${email}`);
        await sendAlert(
          email,
          `⚠️ DNS records changed for ${hostname}`,
          `The MX or TXT records for ${hostname} have changed since the last check. If you made this change on purpose, no action needed.`
        );
      }
      state[domainId].dnsSnapshot = currentSnapshot;
    } catch (err) {
      console.error(`  DNS check failed:`, err.message);
    }

    try {
      await runSecurityForDomain(state[domainId], { domainId, hostname, email, verifyToken, wasVerified });
    } catch (err) {
      console.error(`  Security scan failed:`, err.message);
    }
  }

  await saveState(state);
  console.log("\nSaved alert state to Supabase.");
}

console.log("Starting Vigía Recon check run...\n");
runChecks().then(() => console.log("\nCheck run finished."));
