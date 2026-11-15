import Link from "next/link";

export const dynamic = "force-dynamic";

export default function Home() {
  return (
    <main>
      <h1>FocusBoard</h1>
      <p>Plan your week in five minutes.</p>
      <Link href="/pricing">See pricing</Link>
    </main>
  );
}
