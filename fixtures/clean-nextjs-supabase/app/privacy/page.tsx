export const metadata = { title: "Privacy policy · FocusBoard" };

export default function Privacy() {
  return (
    <main>
      <h1>Privacy policy</h1>
      <p>We collect your email address and the boards you create, to provide the service.</p>
      <h2>Subprocessors</h2>
      <ul>
        <li>Supabase: authentication and database</li>
        <li>Stripe: payments</li>
        <li>Vercel: hosting</li>
      </ul>
      <p>You can delete your account and all of its data from the dashboard at any time.</p>
    </main>
  );
}
