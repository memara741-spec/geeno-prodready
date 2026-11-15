export const metadata = { title: "AskDocs", description: "Chat with an AI assistant about any page" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html>
      <body>{children}</body>
    </html>
  );
}
