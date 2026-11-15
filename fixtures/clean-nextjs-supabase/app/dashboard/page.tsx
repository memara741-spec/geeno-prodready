import { redirect } from "next/navigation";
import { createClient, getVerifiedUser } from "@/lib/supabase/server";

export default async function Dashboard() {
  const user = await getVerifiedUser();
  if (!user) redirect("/login");

  const supabase = await createClient();
  const { data: boards, error } = await supabase.from("boards").select("id, name").order("created_at").limit(50);
  if (error) throw new Error("Could not load boards");

  return (
    <main>
      <h1>Your boards</h1>
      {boards.length === 0 ? <p>No boards yet. Create your first one.</p> : <ul>{boards.map((b) => <li key={b.id}>{b.name}</li>)}</ul>}
      <form action="/api/account" method="post">
        <button type="submit">Delete my account and data</button>
      </form>
    </main>
  );
}
