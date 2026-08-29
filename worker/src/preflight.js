// Provider-key liveness, checked before a sandbox boots so a revoked key is reported as such.
// Only fixed per-provider listing endpoints are called; URL-shaped env values are never fetched
// (they can name metadata/loopback/internal hosts, making a preflight that follows them an SSRF).

const PROVIDER_PROBE = {
  OPENAI_API_KEY: "https://api.openai.com/v1/models",
  GROQ_API_KEY: "https://api.groq.com/openai/v1/models",
  FIREWORKS_API_KEY: "https://api.fireworks.ai/inference/v1/models",
  DEEPINFRA_API_KEY: "https://api.deepinfra.com/v1/openai/models",
  TOGETHER_API_KEY: "https://api.together.xyz/v1/models",
  MISTRAL_API_KEY: "https://api.mistral.ai/v1/models",
  DEEPSEEK_API_KEY: "https://api.deepseek.com/models",
  OPENROUTER_API_KEY: "https://openrouter.ai/api/v1/models",
  XAI_API_KEY: "https://api.x.ai/v1/models",
};

// 401/402/403/412 is the provider refusing the credential -- the customer's problem. Reported as
// a status and the provider's name, never the response body: a provider's rejection text commonly
// reflects a partial or masked form of the key back, and this result crosses to the control plane.
export async function preflight(accepted, fetcher = fetch) {
  const checks = accepted.flatMap(([name, value]) => {
    const url = PROVIDER_PROBE[name];
    if (!url) return [];
    const host = new URL(url).host;
    return [
      fetcher(url, { headers: { Authorization: `Bearer ${value}` }, signal: AbortSignal.timeout(15_000) })
        .then((res) => ({
          name,
          host,
          status: res.status,
          // Only the provider REFUSING the credential is the customer's problem. A timeout or a
          // network error is our probe's failure, not a verdict on their key, so it carries no
          // `dead` -- an unverifiable probe must never be reported as a dead credential.
          ...([401, 402, 403, 412].includes(res.status) ? { dead: `${host} rejected this key (${res.status})` } : {}),
        }))
        .catch(() => ({ name, host, status: 0 })),
    ];
  });
  return Promise.all(checks);
}
