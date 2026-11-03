-- Adds the outside-in security scan: domain ownership verification,
-- scan results storage, and the rules that let each customer read
-- ONLY their own results.
--
-- Paste this whole thing into Supabase's SQL Editor and click Run.
-- Safe to run more than once.

-- ---- 1. Domain ownership verification ----------------------------

-- Each domain gets a random token. The customer proves ownership by
-- adding it as a DNS TXT record: vigiarecon-verify=<token>
alter table domains add column if not exists verify_token text
  not null default replace(gen_random_uuid()::text, '-', '');
alter table domains add column if not exists verified_at timestamptz;

-- Customers add domains straight from the browser, so they could try
-- to insert a row that already says "verified". This trigger throws
-- away whatever they send for those two fields and sets safe values.
-- Only check.js (using the service key) ever marks a domain verified.
create or replace function reset_domain_verification()
returns trigger
language plpgsql
as $$
begin
  new.verify_token := replace(gen_random_uuid()::text, '-', '');
  new.verified_at := null;
  return new;
end;
$$;

drop trigger if exists domain_verification_defaults on domains;
create trigger domain_verification_defaults
  before insert on domains
  for each row
  execute function reset_domain_verification();

-- Only accept real public hostnames (example.com, shop.example.co.uk).
-- Blocks IP addresses, "localhost", and other internal names so the
-- scanner can't be pointed at private networks. NOT VALID means
-- existing rows aren't re-checked, only new ones.
alter table domains drop constraint if exists hostname_is_public_domain;
alter table domains add constraint hostname_is_public_domain
  check (hostname ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
  not valid;

-- ---- 2. Where scan results live ----------------------------------

-- flagged_takeover_hostnames is used by check.js already but wasn't
-- in any earlier SQL file — added here so a fresh setup works.
alter table alert_state add column if not exists flagged_takeover_hostnames jsonb not null default '[]';
alter table alert_state add column if not exists security_findings jsonb not null default '[]';
alter table alert_state add column if not exists security_score integer;
alter table alert_state add column if not exists security_alerted_keys jsonb not null default '[]';
alter table alert_state add column if not exists last_security_scan_at timestamptz;

-- ---- 3. Row Level Security ---------------------------------------

-- Policies only take effect when RLS is switched on for the table.
-- These lines make sure it is (harmless if it already was).
alter table accounts enable row level security;
alter table domains enable row level security;
alter table alert_state enable row level security;

-- A logged-in person can READ scan results for their own domains.
-- There is deliberately no insert/update/delete rule: only check.js
-- (service key, which bypasses RLS) writes results, so customers
-- can't fake a clean score.
drop policy if exists "Users can view their own scan results" on alert_state;
create policy "Users can view their own scan results"
  on alert_state for select
  using (
    domain_id in (
      select d.id from domains d
      join accounts a on a.id = d.account_id
      where a.user_id = auth.uid()
    )
  );
