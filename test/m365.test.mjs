// Run with: npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { analyzeTenant, buildClientAssertion } from "../m365-security.mjs";

const keys = (fs_) => fs_.map((f) => f.key);

// The exact test tenant set up on 2026-11-03.
const users = [
  { id: "chad", userPrincipalName: "vigiarecon.dev_outlook.com#EXT#@contoso.onmicrosoft.com", accountEnabled: true, userType: "Member" },
  { id: "tadmin", userPrincipalName: "testadmin@contoso.onmicrosoft.com", accountEnabled: true, userType: "Member" },
  { id: "ana", userPrincipalName: "ana.test@contoso.onmicrosoft.com", accountEnabled: true, userType: "Member" },
  { id: "ben", userPrincipalName: "ben.test@contoso.onmicrosoft.com", accountEnabled: true, userType: "Member" },
];
const base = {
  users,
  mfa: new Map([["chad", true], ["tadmin", false], ["ana", true], ["ben", false]]),
  globalAdmins: ["chad", "tadmin"],
  securityDefaults: true,
  caRequiresMfa: null,
  forwarding: [],
  mailboxesChecked: 0,
};

test("Test tenant: admin without MFA is critical, Ben is high", () => {
  const f = analyzeTenant(base);
  assert.deepEqual(keys(f), ["accounts:admin-no-mfa", "accounts:users-no-mfa", "accounts:no-mailboxes"]);
  assert.equal(f[0].severity, "critical");
  assert.match(f[0].detail, /testadmin@/);
  assert.match(f[1].title, /1 of 4 users/);
  assert.match(f[1].detail, /ben\.test@/);
  assert.doesNotMatch(f[1].detail, /ana\.test@/);
});

test("Security defaults off with no readable CA policy is flagged", () => {
  const f = analyzeTenant({ ...base, securityDefaults: false });
  assert.ok(keys(f).includes("accounts:mfa-not-required"));
  const ok = analyzeTenant({ ...base, securityDefaults: false, caRequiresMfa: true });
  assert.ok(!keys(ok).includes("accounts:mfa-not-required"));
});

test("Admin counts", () => {
  assert.ok(keys(analyzeTenant({ ...base, globalAdmins: ["chad"] })).includes("accounts:single-admin"));
  const many = analyzeTenant({ ...base, globalAdmins: ["chad", "tadmin", "ana", "ben", "x"] });
  assert.ok(!keys(many).includes("accounts:too-many-admins")); // "x" isn't an enabled user
  const users6 = [...users, { id: "x", userPrincipalName: "x@contoso.onmicrosoft.com" }];
  assert.ok(keys(analyzeTenant({ ...base, users: users6, globalAdmins: ["chad", "tadmin", "ana", "ben", "x"] })).includes("accounts:too-many-admins"));
});

test("Only external forwarding is flagged; guests and disabled users are ignored", () => {
  const f = analyzeTenant({
    ...base,
    mailboxesChecked: 2,
    forwarding: [
      { user: "ana.test@contoso.onmicrosoft.com", rule: "to Ben", to: "ben.test@contoso.onmicrosoft.com" },
      { user: "ben.test@contoso.onmicrosoft.com", rule: "invoices", to: "pay-me@gmail.com" },
    ],
  });
  const fwd = f.find((x) => x.key === "accounts:external-forwarding");
  assert.ok(fwd);
  assert.match(fwd.title, /^1 inbox rule/);
  assert.match(fwd.detail, /pay-me@gmail\.com/);

  const withGuest = analyzeTenant({
    ...base,
    users: [...users, { id: "g", userPrincipalName: "guest@else.com", userType: "Guest" }, { id: "d", userPrincipalName: "old@contoso.onmicrosoft.com", accountEnabled: false }],
    mfa: new Map([...base.mfa, ["g", false], ["d", false]]),
  });
  assert.match(withGuest.find((x) => x.key === "accounts:users-no-mfa").title, /1 of 4 users/);
});

test("Client assertion is a valid RS256 JWT signed by the certificate's key", { skip: !hasOpenssl() }, () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vr-cert-"));
  const key = path.join(dir, "k.pem"), crt = path.join(dir, "c.pem");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=test"], { stdio: "ignore" });
  // eslint-disable-next-line security/detect-non-literal-fs-filename -- temp files this test just created
  const certPem = fs.readFileSync(crt, "utf8"), keyPem = fs.readFileSync(key, "utf8");
  const tenantId = "4fb8d485-4eb6-4ff2-8aec-0a0c92bd1ba0", clientId = "f9fc8318-c013-459d-a109-2daac4185a19";

  const jwt = buildClientAssertion({ tenantId, clientId, certPem, keyPem, now: 1_800_000_000_000 });
  const [h, p, s] = jwt.split(".");
  const header = JSON.parse(Buffer.from(h, "base64url"));
  const payload = JSON.parse(Buffer.from(p, "base64url"));

  assert.equal(header.alg, "RS256");
  const sha1 = Buffer.from(new crypto.X509Certificate(certPem).fingerprint.replace(/:/g, ""), "hex");
  assert.equal(header.x5t, sha1.toString("base64url"));
  assert.equal(payload.aud, `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`);
  assert.equal(payload.iss, clientId);
  assert.equal(payload.exp - payload.iat, 600);
  const pub = new crypto.X509Certificate(certPem).publicKey;
  assert.ok(crypto.verify("RSA-SHA256", Buffer.from(`${h}.${p}`), pub, Buffer.from(s, "base64url")));
  fs.rmSync(dir, { recursive: true, force: true });
});

function hasOpenssl() {
  try { execFileSync("openssl", ["version"], { stdio: "ignore" }); return true; } catch { return false; }
}
