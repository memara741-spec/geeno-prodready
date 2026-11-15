import OpenAI from "openai";

// Generates a listing description right in the browser.
const openai = new OpenAI({
  apiKey: import.meta.env.VITE_OPENAI_API_KEY,
  dangerouslyAllowBrowser: true,
});

export async function describeListing(title: string) {
  const res = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "user", content: `Write a product description for: ${title}` }],
  });
  return res.choices[0].message.content;
}
