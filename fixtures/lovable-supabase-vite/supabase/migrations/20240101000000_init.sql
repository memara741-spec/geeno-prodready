-- Marketplace schema

create table public.profiles (
  id uuid primary key references auth.users(id),
  full_name text,
  email text,
  phone text,
  role text default 'user',
  created_at timestamp default now()
);

create table public.listings (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id),
  title text not null,
  description text,
  price real not null,
  created_at timestamp default now()
);
alter table public.listings enable row level security;
create policy "Anyone can view listings" on public.listings for select using (true);
create policy "Users can create listings" on public.listings for insert to authenticated with check (true);
create policy "Owners can update listings" on public.listings for update to authenticated using ((select auth.uid()) = user_id);

create table public.orders (
  id uuid primary key default gen_random_uuid(),
  buyer_id uuid references auth.users(id),
  listing_id uuid references public.listings(id),
  total numeric(10,2) not null,
  shipping_address text,
  status text default 'pending',
  created_at timestamptz default now()
);
alter table public.orders enable row level security;
create policy "Enable all" on public.orders for all using (true);

create table public.messages (
  id uuid primary key default gen_random_uuid(),
  sender_id uuid references auth.users(id),
  recipient_id uuid references auth.users(id),
  body text not null,
  created_at timestamptz default now()
);
alter table public.messages enable row level security;
create policy "Authenticated users can read messages" on public.messages
  for select using (auth.role() = 'authenticated');
create policy "Users can send messages" on public.messages
  for insert to authenticated with check ((select auth.uid()) = sender_id);

alter publication supabase_realtime add table public.messages;
