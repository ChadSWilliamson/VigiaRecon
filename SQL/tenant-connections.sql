-- Microsoft 365 / Google Workspace account connections.
-- Paste this whole thing into Supabase's SQL Editor and click Run.
-- Safe to run more than once.
--
-- One row per connected tenant. The daily scan (check.js, service key)
-- writes the results; customers can only READ and REMOVE their own rows.

create table if not exists tenant_connections (
  id uuid primary key default gen_random_uuid(),
  account_id uuid not null references accounts(id) on delete cascade,
  provider text not null check (provider in ('microsoft')),
  tenant_id text not null check (tenant_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  display_name text,
  connected_at timestamptz not null default now(),

  -- written by the daily scan only
  last_scan_at timestamptz,
  last_error text,
  account_score integer,
  account_findings jsonb not null default '[]',
  alerted_keys jsonb not null default '[]',
  billable_users integer,
  summary jsonb,

  -- A tenant can belong to only one Vigía Recon account, so nobody can
  -- attach someone else's tenant to their own login and read its results.
  unique (provider, tenant_id)
);

alter table tenant_connections enable row level security;

-- Customers can see their own connections and results...
drop policy if exists "Users can view their own tenant connections" on tenant_connections;
create policy "Users can view their own tenant connections"
  on tenant_connections for select
  using (account_id in (select id from accounts where user_id = auth.uid()));

-- ...and disconnect them.
drop policy if exists "Users can remove their own tenant connections" on tenant_connections;
create policy "Users can remove their own tenant connections"
  on tenant_connections for delete
  using (account_id in (select id from accounts where user_id = auth.uid()));

-- Deliberately NO insert or update policy for customers. A connection is
-- only created after Microsoft confirms an admin consented (later: the
-- Connect button's server-side callback). Otherwise anyone could type in
-- another company's tenant ID and see that company's account findings.
