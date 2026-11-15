create table public.checkins (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id),
  trail text not null,
  lat double precision,
  lng double precision,
  created_at timestamptz default now()
);
