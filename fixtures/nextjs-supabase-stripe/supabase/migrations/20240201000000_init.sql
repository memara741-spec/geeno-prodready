create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  email text
);
alter table public.profiles enable row level security;
create policy "profiles_select_own" on public.profiles for select to authenticated using ((select auth.uid()) = id);
create policy "profiles_update_own" on public.profiles for update to authenticated using ((select auth.uid()) = id) with check ((select auth.uid()) = id);

create table public.boards (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  created_at timestamptz not null default now()
);
create index boards_user_id_idx on public.boards (user_id);
alter table public.boards enable row level security;
create policy "boards_all_own" on public.boards for all to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);

create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  amount_cents integer not null,
  stripe_invoice_id text
);
create index invoices_user_id_idx on public.invoices (user_id);
alter table public.invoices enable row level security;
create policy "invoices_select_own" on public.invoices for select to authenticated using ((select auth.uid()) = user_id);

create table public.events (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users(id) on delete cascade,
  name text not null,
  created_at timestamptz not null default now()
);
create index events_user_id_idx on public.events (user_id);
alter table public.events enable row level security;
create policy "events_select_own" on public.events for select to authenticated using ((select auth.uid()) = user_id);
