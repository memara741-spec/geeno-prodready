import { isPro } from "@/lib/plan";
import { createClient } from "@/lib/supabase/server";

export default async function Dashboard() {
  const supabase = await createClient();
  const { data: boards } = await supabase.from("boards").select("id, name").limit(50);
  const pro = await isPro();
  return (
    <main>
      <h1>Your boards</h1>
      {pro ? <p>Pro plan: unlimited boards</p> : <p>Free plan: 3 boards</p>}
      <ul>{(boards ?? []).map((b) => <li key={b.id}>{b.name}</li>)}</ul>
    </main>
  );
}
