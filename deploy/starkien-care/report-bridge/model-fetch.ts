import { readFile } from "node:fs/promises";
import { request as httpsRequest } from "node:https";

const relayUrl = "https://care-connect-relay.care-connect.svc/v1/chat/completions";
const tokenFile = "/var/run/secrets/openclaw/service-principal/token";
const caFile = "/var/run/secrets/care-connect/ca.crt";
const maxRequest = 262_144;
const maxResponse = 1_048_576;

async function boundedBytes(source: AsyncIterable<Uint8Array>, limit: number): Promise<Buffer> {
  const parts: Uint8Array[] = [];
  let size = 0;
  for await (const part of source) {
    size += part.length;
    if (size > limit) {
      throw new Error("Care Connect message exceeds its size limit.");
    }
    parts.push(part);
  }
  return Buffer.concat(parts, size);
}

// Only the pinned runtime caller uses the defaults. Tests use a local TLS listener.
export function createReportFetch(endpoint = relayUrl, projection = tokenFile, trust = caFile): typeof fetch {
  return async (input, init) => {
    const req = new Request(input, init);
    if (req.url !== endpoint || req.method !== "POST" || !req.body ||
        req.headers.get("content-type")?.split(";")[0]?.trim() !== "application/json" ||
        req.headers.has("content-encoding") ||
        req.headers.get("authorization") !== "Bearer care-connect-workload") {
      throw new Error("Care Connect model request refused.");
    }
    const reader = req.body.getReader();
    async function* chunks() {
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) return;
          yield value;
        }
      } finally {
        await reader.cancel();
        reader.releaseLock();
      }
    }
    const body = await boundedBytes(chunks(), maxRequest);
    const [rawToken, ca] = await Promise.all([readFile(projection, "utf8"), readFile(trust)]);
    const token = rawToken.trimEnd();
    if (token.length > 8192 || !/^[\w-]+\.[\w-]+\.[\w-]+$/.test(token)) {
      throw new Error("Care Connect workload identity unavailable.");
    }
    const signal = AbortSignal.any([req.signal, AbortSignal.timeout(600_000)]);
    signal.throwIfAborted();
    // A fresh TLS connection uses the installed CA and hostname. This client does
    // not consume proxy settings, caller headers, redirects or provider keys.
    return new Promise<Response>((resolve, reject) => {
      const upstream = httpsRequest(endpoint, {
        method: "POST", agent: false, ca, rejectUnauthorized: true, signal,
        headers: {
          "content-type": "application/json",
          "content-length": body.length,
          accept: "application/json, text/event-stream",
          "x-care-connect-workload-token": token,
        },
      }, async (res) => {
        try {
          const status = res.statusCode ?? 0;
          if (status < 200 || status >= 300) {
            throw new Error("Care Connect relay refused the request.");
          }
          const contentType = res.headers["content-type"]?.split(";")[0]?.trim();
          if (contentType !== "text/event-stream" && contentType !== "application/json") {
            throw new Error("Invalid Care Connect reply.");
          }
          const bytes = await boundedBytes(res, maxResponse);
          resolve(new Response(new Uint8Array(bytes), {
            status, headers: { "Content-Type": contentType, "Cache-Control": "no-store" },
          }));
        } catch (error) {
          res.destroy();
          reject(error);
        }
      });
      upstream.on("error", reject);
      upstream.end(body);
    });
  };
}
