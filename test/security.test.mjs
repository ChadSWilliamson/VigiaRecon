// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";

import { analyzeSpf, analyzeDmarc, analyzeDkimKey, scanEmailSecurity } from "../email-security.mjs";
import { analyzeHeaders, fingerprintTech } from "../web-exposure.mjs";
import { analyzePorts, cveFinding } from "../vuln-intel.mjs";
import { PROBES } from "../active-scan.mjs";
import { hasVerificationRecord } from "../domain-verify.mjs";
import { isPrivateIp, isValidPublicHostname } from "../net-guard.mjs";
import { scoreFindings, gradeForScore, sortFindings } from "../findings.mjs";

const keys = (fs) => fs.map((f) => f.key);

test("SPF: missing, +all, ?all, too many lookups", () => {
  assert.deepEqual(keys(analyzeSpf([], 0)), ["email:spf-missing"]);
  assert.ok(keys(analyzeSpf(["v=spf1 +all"], 0)).includes("email:spf-pass-all"));
  assert.ok(keys(analyzeSpf(["v=spf1 include:x.com ?all"], 1)).includes("email:spf-neutral-all"));
  assert.ok(keys(analyzeSpf(["v=spf1 include:x.com"], 1)).includes("email:spf-no-all"));
  assert.ok(keys(analyzeSpf(["v=spf1 -all"], 11)).includes("email:spf-too-many-lookups"));
  assert.deepEqual(analyzeSpf(["v=spf1 include:_spf.google.com -all"], 4), []);
  assert.deepEqual(analyzeSpf(["v=spf1 redirect=_spf.example.com"], 2), []);
});

test("DMARC: missing, none, partial pct, reject is clean", () => {
  assert.deepEqual(keys(analyzeDmarc([])), ["email:dmarc-missing"]);
  assert.ok(keys(analyzeDmarc(["v=DMARC1; p=none; rua=mailto:a@b.com"])).includes("email:dmarc-policy-none"));
  assert.ok(keys(analyzeDmarc(["v=DMARC1; p=reject; pct=50; rua=mailto:a@b.com"])).includes("email:dmarc-partial-pct"));
  assert.deepEqual(analyzeDmarc(["v=DMARC1; p=reject; rua=mailto:a@b.com"]), []);
});

test("DKIM key size estimate", () => {
  const k1024 = Buffer.alloc(162).toString("base64");
  const k2048 = Buffer.alloc(294).toString("base64");
  assert.equal(analyzeDkimKey("s1", `v=DKIM1; k=rsa; p=${k1024}`).bits, 1024);
  assert.equal(analyzeDkimKey("s1", `v=DKIM1; k=rsa; p=${k2048}`).bits, 2048);
  assert.equal(analyzeDkimKey("s1", "v=DKIM1; p=").revoked, true);
});

test("Email scan end-to-end with a fake DNS resolver", async () => {
  const zone = {
    "example.com": [["v=spf1 include:_spf.google.com ~all"]],
    "_spf.google.com": [["v=spf1 include:a.google.com -all"]],
    "_dmarc.example.com": [["v=DMARC1; p=none"]],
    "google._domainkey.example.com": [[`v=DKIM1; k=rsa; p=${Buffer.alloc(294).toString("base64")}`]],
  };
  const resolver = {
    resolveTxt: async (n) => { if (zone[n]) return zone[n]; throw new Error("ENOTFOUND"); },
    resolveMx: async () => [{ priority: 1, exchange: "aspmx.l.google.com" }],
  };
  const { findings, summary } = await scanEmailSecurity("example.com", resolver);
  const k = keys(findings);
  assert.equal(summary.receivesMail, true);
  assert.ok(k.includes("email:dmarc-policy-none"));
  assert.ok(k.includes("email:dmarc-no-reports"));
  assert.ok(!k.includes("email:dkim-not-found"));
  assert.ok(!k.includes("email:spf-missing"));
});

test("Headers: bare response flags the basics, hardened response is clean", () => {
  const bare = keys(analyzeHeaders({ server: "Apache/2.4.49 (Unix)", "x-powered-by": "PHP/7.4.3" }, ["sid=1; Path=/"]));
  for (const k of ["web:hsts-missing", "web:csp-missing", "web:clickjacking", "web:nosniff-missing", "web:server-version", "web:powered-by", "web:cookie-flags"]) {
    assert.ok(bare.includes(k), k);
  }
  const hardened = analyzeHeaders({
    "strict-transport-security": "max-age=63072000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    server: "cloudflare",
  }, ["sid=1; Path=/; Secure; HttpOnly; SameSite=Lax"]);
  assert.deepEqual(hardened, []);
});

test("Tech fingerprint builds CPEs", () => {
  const t = fingerprintTech({ server: "Apache/2.4.49 (Unix) OpenSSL/1.0.2k", "x-powered-by": "PHP/7.4.3" });
  assert.deepEqual(t.map((x) => x.cpe23), [
    "cpe:2.3:a:apache:http_server:2.4.49",
    "cpe:2.3:a:php:php:7.4.3",
    "cpe:2.3:a:openssl:openssl:1.0.2k",
  ]);
});

test("Risky ports and CVE severity (KEV forces critical)", () => {
  const f = analyzePorts("1.2.3.4", [80, 443, 3389, 6379]);
  assert.deepEqual(keys(f), ["network:port-3389", "network:port-6379"]);
  assert.equal(cveFinding({ cve_id: "CVE-1", cvss_v3: 5.3, kev: true }, "x").severity, "critical");
  assert.equal(cveFinding({ cve_id: "CVE-2", cvss_v3: 7.5, kev: false }, "x").severity, "high");
});

test("Active probes confirm content, not just status", () => {
  const p = Object.fromEntries(PROBES.map((x) => [x.path, x.test]));
  assert.ok(p["/.git/HEAD"]("ref: refs/heads/main\n"));
  assert.ok(!p["/.git/HEAD"]("<!doctype html><html>Not found</html>"));
  assert.ok(p["/.env"]("APP_KEY=abc\nDB_PASSWORD=hunter2\n"));
  assert.ok(!p["/.env"]("<html><body>DB_PASSWORD=x</body></html>"));
  assert.ok(p["/.DS_Store"]("\x00\x00\x00\x01Bud1\x00\x00"));
  assert.ok(p["/.htpasswd"]("admin:$apr1$abc$def"));
});

test("Domain verification token match", () => {
  assert.ok(hasVerificationRecord([["vigiarecon-verify=abc123"]], "abc123"));
  assert.ok(hasVerificationRecord([["certwatch-verify=abc123"]], "abc123")); // legacy
  assert.ok(hasVerificationRecord([["certwatch-", "verify=abc123"]], "abc123"));
  assert.ok(!hasVerificationRecord([["certwatch-verify=abc1234"]], "abc123"));
  assert.ok(!hasVerificationRecord([["certwatch-verify="]], ""));
});

test("SSRF guard", () => {
  for (const ip of ["127.0.0.1", "10.1.2.3", "169.254.169.254", "192.168.1.1", "172.20.0.1", "::1", "fd00::1", "::ffff:10.0.0.1"]) {
    assert.ok(isPrivateIp(ip), ip);
  }
  for (const ip of ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"]) assert.ok(!isPrivateIp(ip), ip);
  assert.ok(isValidPublicHostname("shop.example.co.uk"));
  for (const h of ["localhost", "127.0.0.1", "example", "-bad.com", "a..com"]) assert.ok(!isValidPublicHostname(h), h);
});

test("Scoring and ordering", () => {
  const fs = [{ severity: "low" }, { severity: "critical" }, { severity: "medium" }, { severity: "info" }];
  assert.equal(scoreFindings(fs), 100 - 25 - 7 - 2);
  assert.equal(gradeForScore(66), "C");
  assert.equal(sortFindings(fs)[0].severity, "critical");
});
