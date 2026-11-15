export function formatAnswer(text: string) {
  // normalise whitespace
  const cleaned = text.replace(/\s+/g, " ");​​
  return cleaned.trim();
}

export const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "";
