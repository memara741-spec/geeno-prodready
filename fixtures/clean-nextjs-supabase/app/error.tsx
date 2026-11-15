"use client";

export default function ErrorPage({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <main>
      <h1>Something went wrong</h1>
      <p>We have been notified. You can try again.</p>
      <button type="button" onClick={reset}>Try again</button>
    </main>
  );
}
