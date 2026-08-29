// Exact-value scrubbing for sandbox output before it leaves the Durable Object, so logs, error
// tails, and job events never carry a sealed value. A masked value reads as ${NAME}.
// Vendored into the runner service from this repo, the source of truth for these lines.

// Longest value first: one value is often a prefix of another, and replacing the short one
// first would leave the tail of the long one behind.
export function makeMask(pairs) {
  const sorted = (pairs ?? [])
    .filter(([name, value]) => typeof name === "string" && typeof value === "string" && value.length >= 8)
    .sort((a, b) => b[1].length - a[1].length);
  if (sorted.length === 0) return (text) => text;
  return (text) => {
    let out = String(text ?? "");
    for (const [name, value] of sorted) out = out.split(value).join(`\${${name}}`);
    return out;
  };
}
