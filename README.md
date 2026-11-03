# Vigía Recon

A full-stack website monitoring and external attack-surface scanning tool: daily SSL, domain, and DNS checks plus an attacker's-view security scan (email spoofing defenses, exposed services, known CVEs, web hardening, leaked files). Built solo, end-to-end, as a hands-on learning project covering backend automation, security engineering, database design, authentication, and frontend development.

**Live at:** [vigiarecon.com](https://vigiarecon.com)

**Status:** Functional demo. Built to explore the full lifecycle of a SaaS product — not currently in commercial production.

## What it does

Vigía Recon watches a website's "vitals" and alerts the owner before something breaks, then scores what an attacker can see from the outside:

- **SSL certificate monitoring** — flags certificates expiring within 30/14/3 days
- **Domain expiration monitoring** — via RDAP (with a WHOIS API fallback for domains RDAP doesn't cover)
- **Certificate Transparency monitoring** — detects new certificates issued for a domain via crt.sh, a signal that can indicate compromise
- **DNS change detection** — snapshots MX/TXT records and flags unexpected changes (a common sign of email hijacking)
- **Uptime monitoring** — checks every ~15 minutes, alerts only on actual state changes (down / back up)
- **Subdomain takeover detection** — checks subdomains found in CT logs for dangling CNAMEs to unclaimed cloud resources
- **Email alerts** — via Resend, with de-duplication logic so the same issue doesn't re-alert every run

## Outside-in security scan ("attacker's view")

Each domain gets a daily 0–100 score and letter grade, built from what an attacker can learn without any access:

| Tier | Runs on | Checks |
|---|---|---|
| **Email** (`email-security.mjs`) | every domain | SPF (missing, `+all`/`?all`, 10-lookup limit), DMARC policy and reporting, DKIM keys on common selectors, MTA-STS, TLS-RPT |
| **Web** (`web-exposure.mjs`) | every domain | Security headers (HSTS, CSP, clickjacking, nosniff), leaked software versions, cookie flags, HTTP→HTTPS redirect, untrusted certificates, legacy TLS 1.0/1.1, directory listing |
| **Vulnerability intel** (`vuln-intel.mjs`) | every domain | Open risky ports and known CVEs per IP from Shodan InternetDB; CVE severity, CISA KEV status, and EPSS from Shodan CVEDB; version-based CVE matches for software seen in headers |
| **Active** (`active-scan.mjs`) | **verified domains only** | ~15 polite requests for leaked `.git`, `.env`, SQL dumps, config backups, `.htpasswd`, server-status, phpinfo, Spring actuator, phpMyAdmin; security.txt presence |

**Ownership gate:** active checks only run after the customer adds a `vigiarecon-verify=<token>` DNS TXT record (pre-rename `certwatch-verify=` records still count), re-checked every run. The database ignores any attempt to self-mark a domain verified, and the scanner refuses hostnames that resolve to private or internal addresses (SSRF protection).

Try it on one domain locally: `npm run scan -- example.com` (passive only), or add `--token <token>` for active checks on a domain you've verified. Tests: `npm test`.

*Shodan InternetDB/CVEDB are free for non-commercial use, which fits this portfolio project; a commercial launch would need a Shodan license.*

## How it's built

- **Monitoring engine** (`check.js`, `uptime.js`): Node.js scripts run on a schedule via **GitHub Actions** — no server to maintain, runs entirely on free-tier infrastructure
- **Database**: **Supabase** (Postgres) with Row Level Security, storing accounts, domains, and per-domain alert state
- **Auth & customer dashboard** (`dashboard.html`): a single-file app using Supabase Auth (signup/login/password reset) and Supabase Storage (avatar uploads) — no build tooling required
- **Alerting**: Resend API for transactional email
- **Landing page** (`index.html`): a from-scratch design built around a "live vitals monitor" concept

## Why these choices

Every piece was chosen to run on a genuinely free tier with minimal ongoing maintenance: GitHub Actions instead of a paid server, RDAP before falling back to a paid WHOIS API, Supabase's free Postgres tier, Resend's free email tier. The goal was proving out a real product end-to-end without any recurring cost.

## What this project demonstrates

- Designing and enforcing a relational schema with Row Level Security policies
- Building real authentication flows (signup, login, password recovery, account deletion) from scratch
- Building an external attack surface scanner with an ownership-verification gate, SSRF protection, and severity-based scoring
- Working with third-party APIs (RDAP, WHOIS, crt.sh, Shodan InternetDB/CVEDB, Resend) including handling their real-world quirks — rate limits, outages, and inconsistent documentation
- Scheduling and running background jobs without a dedicated server
- Iterative debugging of a live, deployed system

## Notably *not* built (by design)

- Payment processing / Stripe integration
- SMS alerts, PDF reports, white-label reporting (planned features for a "Pro" tier that were scoped but not built)
- A public production launch

---

*Built by Chad Williamson.*
