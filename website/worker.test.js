import assert from "node:assert/strict";
import test from "node:test";

import worker from "./worker.js";

test("redirects the alias and preserves the request target", async () => {
  const response = await worker.fetch(
    new Request("http://license-audit.tylerbutler.com/docs/check/?strict=true"),
    { ASSETS: { fetch: assert.fail } },
  );

  assert.equal(response.status, 301);
  assert.equal(
    response.headers.get("location"),
    "https://licence-audit.tylerbutler.com/docs/check/?strict=true",
  );
});

for (const host of [
  "licence-audit.tylerbutler.com",
  "branch-preview.example.workers.dev",
]) {
  test(`serves assets on ${host}`, async () => {
    const request = new Request(`https://${host}/docs/check/`);
    const response = await worker.fetch(request, {
      ASSETS: { fetch: (assetRequest) => new Response(assetRequest.url) },
    });

    assert.equal(await response.text(), request.url);
  });
}
