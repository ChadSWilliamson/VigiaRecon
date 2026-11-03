/**
 * web-exposure.mjs
 * -----------------------------------------------------------------
 * The first thing an attacker does: load the site like any visitor
 * and read what it gives away. One normal page load over HTTPS,
 * one over plain HTTP, and one TLS handshake test. Nothing a
 * regular browser wouldn't do, so this is passive and safe to run
 * on any domain.
 *
 * What we look at:
 *   - Missing security headers (HSTS, CSP, clickjacking, MIME sniffing)
 *   - Software + version numbers leaked in headers (Server, X-Powered-By)
 *     → these become CVE lookups in vuln-intel.mjs
 *   - Cookies missing Secure / HttpOnly
 *   - Plain HTTP not redirecting to HTTPS
 *   - Old TLS 1.0 / 1.1 still accepted
 *   - Directory listing on the home page
 */

import tls from "node:tls";
import { finding } from "./findings.mjs";

export const USER_AGENT = "VigiaRecon-Scanner/1.0 (+https://vigiarecon.com/)";
const TIMEOUT_MS = 10000;

// ---- Header analysis (pure, testable) ------------------------------

export function analyzeHeaders(headers, setCookies = []) {
  const h = (name) => headers[name.toLowerCase()];
  const out = [];

  const hsts = h("strict-transport-security");
  if (!hsts) {
    out.push(finding(
      "web:hsts-missing", "web", "medium",
      "HSTS header missing",
      "Browsers aren't told to always use HTTPS, so a first visit can be downgraded on hostile Wi-Fi.",
      'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains".'
    ));
  } else {
    const maxAge = Number((/max-age=(\d+)/i.exec(hsts) || [])[1] || 0);
    if (maxAge < 15552000) {
      out.push(finding(
        "web:hsts-short", "web", "low",
        "HSTS max-age is short",
        `max-age is ${maxAge} seconds (under 6 months).`,
        "Raise max-age to at least 31536000 (1 year)."
      ));
    }
  }

  const csp = h("content-security-policy");
  if (!csp) {
    out.push(finding(
      "web:csp-missing", "web", "low",
      "No Content-Security-Policy",
      "If an attacker finds a way to inject script, nothing limits what it can load or run.",
      "Add a Content-Security-Policy header. Start in report-only mode to avoid breaking the site."
    ));
  }

  const frameProtected = h("x-frame-options") || (csp && /frame-ancestors/i.test(csp));
  if (!frameProtected) {
    out.push(finding(
      "web:clickjacking", "web", "low",
      "Site can be framed (clickjacking)",
      "Another site could load this one invisibly inside a frame and trick users into clicking.",
      'Add "X-Frame-Options: DENY" or a CSP "frame-ancestors \'self\'".'
    ));
  }

  if ((h("x-content-type-options") || "").toLowerCase() !== "nosniff") {
    out.push(finding(
      "web:nosniff-missing", "web", "low",
      "X-Content-Type-Options missing",
      "Browsers may guess file types, which can turn an uploaded file into running script.",
      'Add "X-Content-Type-Options: nosniff".'
    ));
  }

  if (!h("referrer-policy")) {
    out.push(finding(
      "web:referrer-policy-missing", "web", "info",
      "No Referrer-Policy",
      "Full page URLs (which can include tokens) may be sent to other sites.",
      'Add "Referrer-Policy: strict-origin-when-cross-origin".'
    ));
  }

  const server = h("server");
  if (server && /\d/.test(server)) {
    out.push(finding(
      "web:server-version", "web", "low",
      "Server software version is public",
      `The Server header reveals "${server}". Attackers match versions against known exploits.`,
      "Hide the version (e.g. ServerTokens Prod on Apache, server_tokens off on nginx)."
    ));
  }
  const poweredBy = h("x-powered-by");
  if (poweredBy) {
    out.push(finding(
      "web:powered-by", "web", "low",
      "X-Powered-By header leaks the tech stack",
      `Header says "${poweredBy}".`,
      "Remove the X-Powered-By header (e.g. expose_php = Off for PHP)."
    ));
  }
  const aspnet = h("x-aspnet-version") || h("x-aspnetmvc-version");
  if (aspnet) {
    out.push(finding(
      "web:aspnet-version", "web", "low",
      "ASP.NET version is public",
      `Header reveals ASP.NET ${aspnet}.`,
      'Set enableVersionHeader="false" in web.config.'
    ));
  }

  const insecureCookies = setCookies
    .map((c) => ({ name: c.split("=")[0].trim(), lower: c.toLowerCase() }))
    .filter((c) => !c.lower.includes("; secure") || !c.lower.includes("httponly"));
  if (insecureCookies.length) {
    out.push(finding(
      "web:cookie-flags", "web", "low",
      "Cookies missing Secure or HttpOnly",
      `Cookies: ${insecureCookies.map((c) => c.name).slice(0, 5).join(", ")}. Missing flags let cookies leak over HTTP or be read by injected script.`,
      "Set the Secure and HttpOnly flags (and SameSite) on session cookies."
    ));
  }

  return out;
}

// ---- Tech fingerprinting (pure, testable) -------------------------

// Maps a header token like "Apache/2.4.49" to a CPE, so vuln-intel
// can look up known CVEs for that exact version.
const PRODUCTS = [
  { re: /apache\/(\d+\.\d+\.\d+)/i, name: "Apache httpd", cpe: "cpe:2.3:a:apache:http_server" },
  { re: /nginx\/(\d+\.\d+\.\d+)/i, name: "nginx", cpe: "cpe:2.3:a:f5:nginx" },
  { re: /microsoft-iis\/(\d+\.\d+)/i, name: "Microsoft IIS", cpe: "cpe:2.3:a:microsoft:internet_information_services" },
  { re: /php\/(\d+\.\d+\.\d+)/i, name: "PHP", cpe: "cpe:2.3:a:php:php" },
  { re: /openssl\/(\d+\.\d+\.\d+[a-z]?)/i, name: "OpenSSL", cpe: "cpe:2.3:a:openssl:openssl" },
  // eslint-disable-next-line security/detect-unsafe-regex -- bounded digit groups, no nesting
  { re: /litespeed\/(\d+\.\d+(?:\.\d+)?)/i, name: "LiteSpeed", cpe: "cpe:2.3:a:litespeedtech:litespeed_web_server" },
  // eslint-disable-next-line security/detect-unsafe-regex -- bounded digit groups, no nesting
  { re: /openresty\/(\d+\.\d+\.\d+(?:\.\d+)?)/i, name: "OpenResty", cpe: "cpe:2.3:a:openresty:openresty" },
  { re: /jetty\((\d+\.\d+\.\d+)/i, name: "Jetty", cpe: "cpe:2.3:a:eclipse:jetty" },
];

export function fingerprintTech(headers) {
  const haystack = [headers["server"], headers["x-powered-by"]].filter(Boolean).join(" ");
  const tech = [];
  for (const p of PRODUCTS) {
    const m = p.re.exec(haystack);
    if (m) tech.push({ name: p.name, version: m[1], cpe23: `${p.cpe}:${m[1]}` });
  }
  return tech;
}

// ---- Network pieces ------------------------------------------------

function headersToObject(res) {
  const obj = {};
  res.headers.forEach((v, k) => { obj[k.toLowerCase()] = v; });
  return obj;
}

async function fetchPage(url, redirect = "follow") {
  const res = await fetch(url, {
    redirect,
    signal: AbortSignal.timeout(TIMEOUT_MS),
    headers: { "User-Agent": USER_AGENT },
  });
  // Only read the start of the body — enough to spot directory listings.
  const body = (await res.text()).slice(0, 20000);
  return { res, body, headers: headersToObject(res) };
}

// Does the server still accept TLS 1.0 / 1.1?
function acceptsLegacyTls(hostname) {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: hostname,
      port: 443,
      servername: hostname,
      minVersion: "TLSv1",
      maxVersion: "TLSv1.1",
      ciphers: "DEFAULT@SECLEVEL=0",
      rejectUnauthorized: false, // we only care whether the handshake happens
      timeout: TIMEOUT_MS,
    });
    socket.once("secureConnect", () => { socket.destroy(); resolve(true); });
    socket.once("error", () => resolve(false));
    socket.once("timeout", () => { socket.destroy(); resolve(false); });
  });
}

// Is the certificate actually trusted by browsers right now?
function certificateProblem(hostname) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: hostname, port: 443, servername: hostname, timeout: TIMEOUT_MS });
    socket.once("secureConnect", () => { socket.destroy(); resolve(null); });
    socket.once("error", (err) => resolve(err.code || err.message));
    socket.once("timeout", () => { socket.destroy(); resolve(null); });
  });
}

export async function scanWebExposure(hostname) {
  const findings = [];
  let tech = [];

  // 1. HTTPS home page
  let https = null;
  try {
    https = await fetchPage(`https://${hostname}/`);
  } catch (err) {
    findings.push(finding(
      "web:https-unreachable", "web", "medium",
      "HTTPS didn't respond",
      `Couldn't load https://${hostname}/ (${err.cause?.code || err.message}).`,
      "Make sure the site is served over HTTPS with a valid certificate."
    ));
  }

  if (https) {
    findings.push(...analyzeHeaders(https.headers, https.res.headers.getSetCookie?.() || []));
    tech = fingerprintTech(https.headers);

    if (/<title>\s*Index of \//i.test(https.body)) {
      findings.push(finding(
        "web:directory-listing", "web", "medium",
        "Directory listing is turned on",
        "The home page shows a raw file list, letting anyone browse the server's files.",
        "Disable directory indexes (Options -Indexes on Apache, autoindex off on nginx)."
      ));
    }
  }

  // 2. Plain HTTP should redirect to HTTPS
  try {
    const http = await fetchPage(`http://${hostname}/`, "manual");
    const location = http.res.headers.get("location") || "";
    const redirectsToHttps = http.res.status >= 300 && http.res.status < 400 && location.startsWith("https://");
    if (!redirectsToHttps && http.res.status < 400) {
      findings.push(finding(
        "web:no-https-redirect", "web", "medium",
        "HTTP doesn't redirect to HTTPS",
        "Visitors who type the bare domain get an unencrypted page.",
        "Redirect all http:// requests to https:// with a 301."
      ));
    }
  } catch {
    // Port 80 closed is fine.
  }

  // 3. TLS checks
  const certErr = await certificateProblem(hostname);
  if (certErr) {
    findings.push(finding(
      "web:cert-untrusted", "web", "high",
      "Certificate isn't trusted by browsers",
      `TLS error: ${certErr}. Visitors see a security warning, and users learn to click through warnings.`,
      "Install a certificate that matches the hostname and includes the full chain."
    ));
  }
  if (await acceptsLegacyTls(hostname)) {
    findings.push(finding(
      "web:legacy-tls", "web", "medium",
      "Old TLS 1.0/1.1 still accepted",
      "These versions have known weaknesses and are retired by all major browsers.",
      "Allow only TLS 1.2 and 1.3 in your server or CDN settings."
    ));
  }

  return { findings, tech };
}
