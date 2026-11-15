import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { renderOpenGraphImage } from "./build-og-image.js";

test("renders a repeatable 1200 x 630 PNG without system fonts", () => {
  const png = renderOpenGraphImage();
  assert.deepEqual(png.subarray(0, 8), Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
  assert.equal(png.readUInt32BE(16), 1200);
  assert.equal(png.readUInt32BE(20), 630);
  assert.ok(png.length > 10_000, "The image must contain rendered content");
  assert.ok(png.length < 1_000_000, "Keep the share image below 1 MB");
  assert.deepEqual(renderOpenGraphImage(), png);
});

test("the builder writes the public asset from any working directory", () => {
  execFileSync(process.execPath, [
    fileURLToPath(new URL("./build-og-image.js", import.meta.url)),
  ], { cwd: tmpdir() });
  assert.deepEqual(
    readFileSync(new URL("../public/og.png", import.meta.url)),
    renderOpenGraphImage(),
  );
});
