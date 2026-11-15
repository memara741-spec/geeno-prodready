import type { Instrumentation } from "next";

// Sends every server-side error to the error tracker. No request bodies, no cookies, no personal data.
export const onRequestError: Instrumentation.onRequestError = async (error, request, context) => {
  const endpoint = process.env.ERROR_REPORT_URL;
  if (!endpoint) return;
  await fetch(endpoint, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      message: error instanceof Error ? error.message : "unknown error",
      digest: (error as { digest?: string }).digest,
      path: request.path,
      routeType: context.routeType,
    }),
    signal: AbortSignal.timeout(3000),
  }).catch(() => undefined);
};
