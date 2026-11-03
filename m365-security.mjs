/**
 * m365-security.mjs
 * -----------------------------------------------------------------
 * Account security check for a customer's Microsoft 365 / Entra ID
 * tenant: the inside-the-account counterpart to the outside-in scan.
 *
 * Read-only. Signs in as the "Vigía Recon Scanner" app with a
 * certificate (no client secret), then reads settings through
 * Microsoft Graph. It never changes anything and never reads email
 * content.
 *
 * Graph permissions it uses (application, admin-consented):
 *   AuditLog.Read.All                 who has two-factor (registration report)
 *   UserAuthenticationMethod.Read.All fallback when that report needs a paid license
 *   User.Read.All                     list users
 *   RoleManagement.Read.Directory     count Global Administrators
 *   Policy.Read.All                   security defaults / Conditional Access
 *   MailboxSettings.Read              inbox rules that forward mail out
 *
 * Only built-in Node modules: no extra npm packages to vet.
 */

import crypto from "node:crypto";
import { finding } from "./findings.mjs";

const GRAPH = "https://graph.microsoft.com/v1.0";
const GLOBAL_ADMIN_ROLE_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10";
const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_PER_USER_CALLS = 300;
const TIMEOUT_MS = 15000;

// Methods that count as a real second factor. Email and password don't.
const STRONG_METHODS = new Set([
  "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
  "#microsoft.graph.phoneAuthenticationMethod",
  "#microsoft.graph.fido2AuthenticationMethod",
  "#microsoft.graph.softwareOathAuthenticationMethod",
  "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod",
  "#microsoft.graph.platformCredentialAuthenticationMethod",
]);

const b64url = (input) => Buffer.from(input).toString("base64url");

// ---- 1. Sign in with the certificate ------------------------------

/**
 * Builds the signed "client assertion" Microsoft accepts instead of a
 * password. The private key signs it locally and never leaves this machine.
 */
export function buildClientAssertion({ tenantId, clientId, certPem, keyPem, now = Date.now() }) {
  const cert = new crypto.X509Certificate(certPem);
  const sha1 = Buffer.from(cert.fingerprint.replace(/:/g, ""), "hex");
  const header = { alg: "RS256", typ: "JWT", x5t: b64url(sha1) };
  const iat = Math.floor(now / 1000);
  const payload = {
    aud: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
    iss: clientId,
    sub: clientId,
    jti: crypto.randomUUID(),
    nbf: iat,
    iat,
    exp: iat + 600,
  };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const signature = crypto.sign("RSA-SHA256", Buffer.from(signingInput), keyPem);
  return `${signingInput}.${b64url(signature)}`;
}

export async function getAppToken({ tenantId, clientId, certPem, keyPem }) {
  if (!GUID_RE.test(tenantId) || !GUID_RE.test(clientId)) {
    throw new Error("Tenant ID and client ID must be GUIDs");
  }
  const body = new URLSearchParams({
    client_id: clientId,
    scope: "https://graph.microsoft.com/.default",
    grant_type: "client_credentials",
    client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    client_assertion: buildClientAssertion({ tenantId, clientId, certPem, keyPem }),
  });
  const res = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.access_token) {
    // Microsoft's error codes are safe to show; the token never is.
    throw new Error(`Sign-in failed (${res.status}): ${data.error || "unknown"} ${(data.error_description || "").split("\r\n")[0]}`);
  }
  return data.access_token;
}

// ---- 2. Talk to Microsoft Graph -----------------------------------

async function graphGet(token, path) {
  const res = await fetch(path.startsWith("https://") ? path : `${GRAPH}${path}`, {
    headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data, code: data?.error?.code };
}

// Follows @odata.nextLink so tenants with many users are read fully.
async function graphList(token, path, limit = 2000) {
  const items = [];
  let next = path;
  while (next && items.length < limit) {
    const r = await graphGet(token, next);
    if (!r.ok) return { ok: false, status: r.status, code: r.code, items };
    items.push(...(r.data.value || []));
    next = r.data["@odata.nextLink"];
    if (next && !next.startsWith(`${GRAPH}/`)) break; // only follow Graph's own links
  }
  return { ok: true, items };
}

// ---- 3. Collect raw facts -----------------------------------------

async function collectMfa(token, users) {
  const mfa = new Map();

  // Preferred: one call for everyone. Microsoft may require Entra ID P1 for it.
  const report = await graphList(token, "/reports/authenticationMethods/userRegistrationDetails?$select=id,isMfaRegistered");
  if (report.ok) {
    for (const r of report.items) mfa.set(r.id, Boolean(r.isMfaRegistered));
    return { mfa, source: "registration report" };
  }

  // Fallback for free tenants: ask user by user (fine for small businesses).
  for (const u of users.slice(0, MAX_PER_USER_CALLS)) {
    const r = await graphList(token, `/users/${encodeURIComponent(u.id)}/authentication/methods`);
    mfa.set(u.id, r.ok ? r.items.some((m) => STRONG_METHODS.has(m["@odata.type"])) : null);
  }
  return { mfa, source: `per-user lookup (registration report unavailable: ${report.code || report.status})` };
}

async function collectPolicies(token) {
  const sd = await graphGet(token, "/policies/identitySecurityDefaultsEnforcementPolicy");
  const securityDefaults = sd.ok ? Boolean(sd.data.isEnabled) : null;

  // Conditional Access needs Entra ID P1; on free tenants this returns 403.
  let caRequiresMfa = null;
  const ca = await graphList(token, "/identity/conditionalAccess/policies");
  if (ca.ok) {
    caRequiresMfa = ca.items.some(
      (p) =>
        p.state === "enabled" &&
        (p.grantControls?.builtInControls || []).includes("mfa") &&
        (p.conditions?.users?.includeUsers || []).includes("All")
    );
  }
  return { securityDefaults, caRequiresMfa };
}

async function collectForwarding(token, users) {
  const forwarding = [];
  let checked = 0;
  for (const u of users.slice(0, MAX_PER_USER_CALLS)) {
    const r = await graphList(token, `/users/${encodeURIComponent(u.id)}/mailFolders/inbox/messageRules`);
    if (!r.ok) continue; // no mailbox / no Exchange license
    checked += 1;
    for (const rule of r.items) {
      if (!rule.isEnabled) continue;
      const a = rule.actions || {};
      const targets = [...(a.forwardTo || []), ...(a.redirectTo || []), ...(a.forwardAsAttachmentTo || [])]
        .map((t) => (t.emailAddress?.address || "").toLowerCase())
        .filter(Boolean);
      for (const to of targets) forwarding.push({ user: u.userPrincipalName, rule: rule.displayName || "", to });
    }
  }
  return { forwarding, mailboxesChecked: checked };
}

// ---- 4. Turn facts into findings (pure, testable) ------------------

// Accounts that sign in through somewhere else (a personal Microsoft
// account, or a guest from another company) show up with "#EXT#" in
// their sign-in name. Their two-factor lives with that other account, so
// this tenant can't see it and we must not report it as missing.
export const isExternalIdentity = (u) => /#EXT#@/i.test(u.userPrincipalName || "");

const domainOf = (email) => String(email).split("@").pop().toLowerCase();
const listNames = (names, max = 5) =>
  names.slice(0, max).join(", ") + (names.length > max ? ` and ${names.length - max} more` : "");

export function analyzeTenant({ users, mfa, globalAdmins, securityDefaults, caRequiresMfa, forwarding, mailboxesChecked }) {
  const out = [];
  const people = users.filter((u) => u.accountEnabled !== false && u.userType !== "Guest");
  const adminIds = new Set(globalAdmins);
  const internalDomains = new Set(users.map((u) => domainOf(u.userPrincipalName)));

  // Admins without two-factor
  const local = people.filter((u) => !isExternalIdentity(u));
  const adminsNoMfa = local.filter((u) => adminIds.has(u.id) && mfa.get(u.id) === false);
  if (adminsNoMfa.length) {
    out.push(finding(
      "accounts:admin-no-mfa", "accounts", "critical",
      `${adminsNoMfa.length} admin account${adminsNoMfa.length > 1 ? "s" : ""} without two-factor`,
      `${listNames(adminsNoMfa.map((u) => u.userPrincipalName))} can sign in with only a password. An admin account is the master key to the whole tenant.`,
      "Have each admin sign in at https://aka.ms/mysecurityinfo and add the Microsoft Authenticator app today."
    ));
  }

  // Everyone else without two-factor
  const usersNoMfa = local.filter((u) => !adminIds.has(u.id) && mfa.get(u.id) === false);
  if (usersNoMfa.length) {
    out.push(finding(
      "accounts:users-no-mfa", "accounts", "high",
      `${usersNoMfa.length} of ${people.length} users have no second factor`,
      `${listNames(usersNoMfa.map((u) => u.userPrincipalName))} can be taken over with a stolen or guessed password.`,
      "Ask each person to add Microsoft Authenticator at https://aka.ms/mysecurityinfo, then require it for everyone (see the next check)."
    ));
  }

  const externalAdmins = people.filter((u) => adminIds.has(u.id) && isExternalIdentity(u));
  if (externalAdmins.length) {
    out.push(finding(
      "accounts:external-admins", "accounts", "low",
      `${externalAdmins.length} admin${externalAdmins.length > 1 ? "s" : ""} sign in with an outside account`,
      `${listNames(externalAdmins.map((u) => u.userPrincipalName.split("#EXT#")[0].replace(/_([^_]+)$/, "@$1")))} ${externalAdmins.length > 1 ? "use accounts" : "uses an account"} from outside this organization, so two-factor can't be checked from here.`,
      "Make sure two-step verification is on in that outside account (for a personal Microsoft account: account.microsoft.com → Security). Better: give admins a work account in this tenant."
    ));
  }

  const unknown = local.filter((u) => mfa.get(u.id) == null).length;
  if (unknown) {
    out.push(finding(
      "accounts:mfa-unknown", "accounts", "info",
      `Couldn't check two-factor for ${unknown} user${unknown > 1 ? "s" : ""}`,
      "Microsoft didn't return sign-in methods for these accounts.",
      "Nothing to do unless this persists; it usually clears on the next scan."
    ));
  }

  // Is two-factor actually required?
  if (securityDefaults === false && caRequiresMfa !== true) {
    out.push(finding(
      "accounts:mfa-not-required", "accounts", "high",
      "Two-factor isn't required for the organization",
      caRequiresMfa === null
        ? "Security defaults are off, and no Conditional Access policy could be found requiring it."
        : "Security defaults are off and no Conditional Access policy requires two-factor for all users.",
      "In the Entra admin center go to Overview → Properties → Manage security defaults and turn them on (free on every plan)."
    ));
  }

  // Global Administrator count
  const gaCount = people.filter((u) => adminIds.has(u.id)).length;
  if (gaCount > 4) {
    out.push(finding(
      "accounts:too-many-admins", "accounts", "medium",
      `${gaCount} Global Administrators`,
      "Every extra Global Admin is another account that can take over the whole tenant if its password leaks.",
      "Keep 2 to 4. Give everyone else a narrower role (User Administrator, Exchange Administrator, etc.)."
    ));
  } else if (gaCount === 1) {
    out.push(finding(
      "accounts:single-admin", "accounts", "low",
      "Only one Global Administrator",
      "If that person is locked out or leaves, nobody can recover the account settings.",
      "Add a second Global Administrator, protected with two-factor, as a backup."
    ));
  }

  // Mail forwarded outside the company
  const external = forwarding.filter((f) => !internalDomains.has(domainOf(f.to)));
  if (external.length) {
    out.push(finding(
      "accounts:external-forwarding", "accounts", "high",
      `${external.length} inbox rule${external.length > 1 ? "s" : ""} forward mail outside the company`,
      external.slice(0, 5).map((f) => `${f.user} → ${f.to}${f.rule ? ` (rule "${f.rule}")` : ""}`).join("; ") +
        ". Attackers who get into a mailbox often add a rule like this to keep reading invoices after they're kicked out.",
      "Confirm each rule with its owner. Remove any nobody recognizes, and reset that user's password."
    ));
  }
  if (mailboxesChecked === 0) {
    out.push(finding(
      "accounts:no-mailboxes", "accounts", "info",
      "No mailboxes to check for forwarding",
      "None of the accounts has an Exchange Online mailbox, so inbox rules couldn't be read.",
      "Nothing to do if this tenant doesn't use Microsoft email."
    ));
  }

  return out;
}

// ---- 5. Main entry point -------------------------------------------

export async function scanM365Tenant({ tenantId, clientId, certPem, keyPem }) {
  const token = await getAppToken({ tenantId, clientId, certPem, keyPem });

  const usersRes = await graphList(token, "/users?$select=id,displayName,userPrincipalName,accountEnabled,userType&$top=999");
  if (!usersRes.ok) throw new Error(`Couldn't list users (${usersRes.code || usersRes.status})`);
  const users = usersRes.items;
  const people = users.filter((u) => u.accountEnabled !== false && u.userType !== "Guest");

  const ga = await graphList(token, `/directoryRoles(roleTemplateId='${GLOBAL_ADMIN_ROLE_TEMPLATE}')/members?$select=id`);
  const globalAdmins = ga.ok ? ga.items.map((m) => m.id) : [];

  const { mfa, source } = await collectMfa(token, people);
  const { securityDefaults, caRequiresMfa } = await collectPolicies(token);
  const { forwarding, mailboxesChecked } = await collectForwarding(token, people);

  const findings = analyzeTenant({ users, mfa, globalAdmins, securityDefaults, caRequiresMfa, forwarding, mailboxesChecked });

  return {
    findings,
    summary: {
      billableUsers: people.length,
      globalAdmins: globalAdmins.length,
      mfaSource: source,
      securityDefaults,
      conditionalAccessReadable: caRequiresMfa !== null,
      mailboxesChecked,
    },
  };
}
