create table public.accounts (
  user_id uuid primary key references auth.users(id),
  plan text default 'free',
  is_admin boolean default false,
  credits integer default 0
);
alter table public.accounts enable row level security;
create policy "Users can view own account" on public.accounts for select using (auth.uid() = user_id);
create policy "Users can update own account" on public.accounts for update using (auth.uid() = user_id);

create table public.reviews (
  id uuid primary key default gen_random_uuid(),
  listing_id uuid references public.listings(id),
  author_id uuid references auth.users(id),
  rating integer,
  body text
);
alter table public.reviews enable row level security;
create policy "Verified sellers can moderate reviews" on public.reviews
  for delete using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'moderator');
create policy "Authors manage their reviews" on public.reviews
  for all using (auth.uid() = author_id) with check (auth.uid() = author_id);

create or replace function public.promote_to_admin(target uuid)
returns void
language sql
security definer
as $$
  update public.accounts set is_admin = true where user_id = target;
$$;

create view public.order_summaries as
  select o.id, o.total, o.shipping_address, p.email
  from public.orders o join public.profiles p on p.id = o.buyer_id;

grant all on all tables in schema public to anon;
