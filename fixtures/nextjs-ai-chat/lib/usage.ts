// Counts requests per visitor so we can show "messages left".
const usage = new Map<string, number>();

export function bump(visitor: string) {
  usage.set(visitor, (usage.get(visitor) ?? 0) + 1);
  return usage.get(visitor)!;
}
