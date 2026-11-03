/**
 * Vigía Recon — uptime check
 * -----------------------------------------------------------------
 * Runs every ~15 minutes via a separate GitHub Actions workflow
 * (uptime-check.yml) — much more often than the once-a-day SSL/
 * domain/CT/DNS checks in check.js.
 *
 * Only sends an email when a site's status actually CHANGES:
 *   - was up, now down  → "your site is down" alert
 *   - was down, now up  → "your site is back up" alert
 * It stays quiet on every check in between, so you're not emailed
 * every 15 minutes while a site is (correctly) still up.
 */

import { createClient } from "@supabase/supabase-js";
import { checkUptime } from "./uptime-check.mjs";

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

async function sendAlert(toEmail, subject, body) {
  await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: "Vigía Recon <alerts@vigiarecon.com>",
      to: toEmail,
      subject,
      text: body,
    }),
  });
}

async function loadDomains() {
  const { data, error } = await supabase
    .from("domains")
    .select("id, hostname, accounts(email)");
  if (error) throw new Error(`Failed to load domains: ${error.message}`);
  return data.map((row) => ({
    domainId: row.id,
    hostname: row.hostname,
    email: row.accounts.email,
  }));
}

async function loadUptimeState() {
  const { data, error } = await supabase
    .from("alert_state")
    .select("domain_id, uptime_status, uptime_down_alerted");
  if (error) throw new Error(`Failed to load uptime state: ${error.message}`);
  const state = {};
  for (const row of data) {
    state[row.domain_id] = {
      status: row.uptime_status,
      downAlerted: row.uptime_down_alerted,
    };
  }
  return state;
}

async function saveUptimeResult(domainId, status, downAlerted) {
  const { error } = await supabase.from("alert_state").upsert(
    {
      domain_id: domainId,
      uptime_status: status,
      uptime_down_alerted: downAlerted,
      last_uptime_check_at: new Date().toISOString(),
    },
    { onConflict: "domain_id" }
  );
  if (error) console.error(`Failed to save uptime state: ${error.message}`);
}

async function run() {
  const domains = await loadDomains();
  const state = await loadUptimeState();

  for (const { domainId, hostname, email } of domains) {
    const previous = state[domainId] || { status: null, downAlerted: false };
    const result = await checkUptime(hostname);
    const newStatus = result.up ? "up" : "down";

    console.log(`${hostname}: ${newStatus}${result.statusCode ? ` (${result.statusCode})` : ""}`);

    if (newStatus === "down" && !previous.downAlerted) {
      console.log(`  → Sending DOWN alert to ${email}`);
      await sendAlert(
        email,
        `🔴 ${hostname} appears to be down`,
        `We just checked ${hostname} and it didn't respond normally${result.error ? ` (${result.error})` : ` (status ${result.statusCode})`}. We'll keep checking and let you know when it's back.`
      );
      await saveUptimeResult(domainId, "down", true);
    } else if (newStatus === "up" && previous.status === "down") {
      console.log(`  → Sending RECOVERY alert to ${email}`);
      await sendAlert(
        email,
        `✅ ${hostname} is back up`,
        `${hostname} is responding normally again.`
      );
      await saveUptimeResult(domainId, "up", false);
    } else {
      await saveUptimeResult(domainId, newStatus, previous.downAlerted);
    }
  }
}

console.log("Starting uptime check...\n");
run().then(() => console.log("\nUptime check finished."));
