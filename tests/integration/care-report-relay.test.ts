import assert from "node:assert/strict";
import { once } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createReportFetch } from "../../deploy/starkien-care/report-bridge/model-fetch.ts";
import { selfSigned } from "../helpers/certificates.ts";

test("report transport verifies the private endpoint and reads the current workload projection", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "report-transport-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const tls = await selfSigned(directory);
  const other = await selfSigned(directory, { name: "other" });
  const tokenPath = join(directory, "token");
  const delivered: unknown[] = [];
  let redirect = false;
  const server = createServer({ key: tls.key, cert: tls.cert }, async (req, res) => {
    const bytes = [];
    for await (const part of req) bytes.push(part);
    delivered.push({
      path: req.url, body: Buffer.concat(bytes).toString(),
      token: req.headers["x-care-connect-workload-token"],
      authorization: req.headers.authorization, cookie: req.headers.cookie,
    });
    if (redirect) {
      res.writeHead(307, { location: "/unexpected" }).end();
    } else {
      res.writeHead(200, { "content-type": "text/event-stream" }).end("data: [DONE]\n\n");
    }
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const path = "/v1/chat/completions";
  const endpoint = `https://127.0.0.1:${address.port}${path}`;
  const fetchReport = createReportFetch(endpoint, tokenPath, tls.certPath);
  const headers = {
    authorization: "Bearer care-connect-workload", "content-type": "application/json",
    "x-care-connect-workload-token": "caller-forgery", cookie: "unrelated",
  };
  const body = JSON.stringify({ model: "test-model", messages: [{ role: "user", content: "abc" }] });
  const options = { method: "POST", headers, body };
  for (const token of ["first.value.sig", "second.value.sig"]) {
    await writeFile(tokenPath, token + "\n");
    assert.equal(await (await fetchReport(endpoint, options)).text(), "data: [DONE]\n\n");
    assert.deepEqual(delivered.at(-1), { path, body, token, authorization: undefined, cookie: undefined });
  }
  await assert.rejects(createReportFetch(endpoint, tokenPath, other.certPath)(endpoint, options));
  await assert.rejects(fetchReport(endpoint + "?other", options));
  await assert.rejects(fetchReport(endpoint, {
    ...options, headers: { ...headers, authorization: "Bearer unintended-provider-key" },
  }));
  await assert.rejects(fetchReport(endpoint, { ...options, body: "a".repeat(262_145) }));
  assert.equal(delivered.length, 2);
  redirect = true;
  await assert.rejects(fetchReport(endpoint, options));
  assert.equal(delivered.length, 3);
});
