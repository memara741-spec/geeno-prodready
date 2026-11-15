import "server-only";
import { z } from "zod";

const schema = z.object({
  NEXT_PUBLIC_SITE_URL: z.url(),
  NEXT_PUBLIC_SUPABASE_URL: z.url(),
  NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: z.string().min(20),
  SUPABASE_SECRET_KEY: z.string().min(20),
  STRIPE_SECRET_KEY: z.string().min(20),
  STRIPE_WEBHOOK_SECRET: z.string().min(20),
  STRIPE_PRICE_PRO_MONTHLY: z.string().startsWith("price_"),
  CRON_SECRET: z.string().min(32),
});

export type Env = z.infer<typeof schema>;

let cached: Env | undefined;

// Fails fast, with the names of the missing variables, the first time the server needs configuration.
export function env(): Env {
  if (!cached) {
    const parsed = schema.safeParse(process.env);
    if (!parsed.success) {
      const names = parsed.error.issues.map((i) => i.path.join(".")).join(", ");
      throw new Error(`Missing or invalid environment variables: ${names}`);
    }
    cached = parsed.data;
  }
  return cached;
}
