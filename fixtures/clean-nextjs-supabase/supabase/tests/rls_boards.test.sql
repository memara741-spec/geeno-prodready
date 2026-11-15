begin;
select plan(4);

insert into auth.users (id, email) values
  ('00000000-0000-0000-0000-00000000000a', 'a@test.invalid'),
  ('00000000-0000-0000-0000-00000000000b', 'b@test.invalid');
insert into public.boards (user_id, name) values
  ('00000000-0000-0000-0000-00000000000a', 'A board'),
  ('00000000-0000-0000-0000-00000000000b', 'B board');

set local role authenticated;
set local request.jwt.claims to '{"sub": "00000000-0000-0000-0000-00000000000a", "role": "authenticated"}';

select is((select count(*) from public.boards), 1::bigint, 'user A sees only their own board');
select is_empty($$ update public.boards set name = 'hacked' where user_id = '00000000-0000-0000-0000-00000000000b' returning id $$, 'user A cannot update user B''s board');
select throws_ok($$ insert into public.boards (user_id, name) values ('00000000-0000-0000-0000-00000000000b', 'x') $$, '42501', null, 'user A cannot insert a board for user B');

set local role anon;
select is((select count(*) from public.boards), 0::bigint, 'anonymous visitors see no boards');

select * from finish();
rollback;
