create table public.boards (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 120),
  created_at timestamptz not null default now()
);
create index boards_user_id_idx on public.boards (user_id);
alter table public.boards enable row level security;

create policy "boards_select_own" on public.boards for select to authenticated
  using ((select auth.uid()) = user_id);
create policy "boards_insert_own" on public.boards for insert to authenticated
  with check ((select auth.uid()) = user_id);
create policy "boards_update_own" on public.boards for update to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "boards_delete_own" on public.boards for delete to authenticated
  using ((select auth.uid()) = user_id);

-- Written only by the verified Stripe webhook (service role). Users can read their own row.
create table public.subscriptions (
  user_id uuid primary key references auth.users(id) on delete cascade,
  stripe_customer_id text not null,
  stripe_subscription_id text not null unique,
  status text not null,
  updated_at timestamptz not null default now()
);
alter table public.subscriptions enable row level security;
create policy "subscriptions_select_own" on public.subscriptions for select to authenticated
  using ((select auth.uid()) = user_id);

-- No policies on purpose: with RLS enabled and no policy, only the service role can read or write.
create table public.stripe_events (
  id text primary key,
  type text not null,
  received_at timestamptz not null default now()
);
alter table public.stripe_events enable row level security;

create schema if not exists private;

create table private.rate_limits (
  key text not null,
  window_start timestamptz not null,
  hits integer not null default 1,
  primary key (key, window_start)
);

create function public.hit_rate_limit(p_key text, p_limit integer, p_window_seconds integer)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_window timestamptz := to_timestamp(floor(extract(epoch from now()) / p_window_seconds) * p_window_seconds);
  v_hits integer;
begin
  insert into private.rate_limits (key, window_start) values (p_key, v_window)
  on conflict (key, window_start) do update set hits = private.rate_limits.hits + 1
  returning hits into v_hits;
  return v_hits <= p_limit;
end;
$$;

revoke execute on function public.hit_rate_limit(text, integer, integer) from public, anon, authenticated;
grant execute on function public.hit_rate_limit(text, integer, integer) to service_role;
