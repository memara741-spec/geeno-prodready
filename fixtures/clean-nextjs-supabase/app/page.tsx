import Link from "next/link";

export default function Home() {
  return (
    <main>
      <h1>FocusBoard</h1>
      <p>Plan your week in five minutes.</p>
      <Link href="/dashboard">Open your board</Link>
    </main>
  );
}
