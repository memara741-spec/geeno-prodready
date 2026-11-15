import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "FocusBoard: plan your week in five minutes",
  description: "A calm weekly planning board for people who run their own business.",
  openGraph: { title: "FocusBoard", description: "Plan your week in five minutes.", images: ["/og.png"] },
  twitter: { card: "summary_large_image" },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        {children}
        <footer>
          <Link href="/privacy">Privacy</Link> · <Link href="/terms">Terms</Link> ·{" "}
          <a href="mailto:support@focusboard.example">Contact support</a>
        </footer>
      </body>
    </html>
  );
}
