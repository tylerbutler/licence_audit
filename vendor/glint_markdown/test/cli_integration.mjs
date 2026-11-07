import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";

const target = process.argv[2];
assert.ok(target === "erlang" || target === "javascript");
const scratch = mkdtempSync(resolve("build", "_cli_test_"));

function run(arguments_, fixture = "run_fixture", limitFileSize = false) {
  let executable;
  let argumentsToRun;
  if (target === "erlang") {
    executable = "erl";
    const packages = resolve("build/dev/erlang");
    const paths = readdirSync(packages, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => join(packages, entry.name, "ebin"));
    const binaries = arguments_.map((argument) =>
      `<<${[...Buffer.from(argument)].join(",")}>>`
    );
    argumentsToRun = [
      "-pa", ...paths, "-noshell", "-eval",
      `glint_markdown_cli_test:${fixture}([${binaries.join(",")}]), erlang:halt(0).`,
    ];
  } else {
    executable = process.execPath;
    const module = pathToFileURL(resolve(
      "build/dev/javascript/glint_markdown/glint_markdown_cli_test.mjs",
    )).href;
    const runtime = pathToFileURL(resolve(
      "build/dev/javascript/gleam_stdlib/gleam.mjs",
    )).href;
    argumentsToRun = [
      "--input-type=module", "-e",
      `import {${fixture}} from ${JSON.stringify(module)};
       import {toList} from ${JSON.stringify(runtime)};
       ${fixture}(toList(${JSON.stringify(arguments_)}));`,
    ];
  }
  if (limitFileSize) {
    argumentsToRun = [
      "-c", 'trap "" XFSZ; ulimit -f 1; exec "$@"',
      "file-size-limit", executable, ...argumentsToRun,
    ];
    executable = "bash";
  }
  const result = spawnSync(executable, argumentsToRun, { encoding: "utf8" });
  if (result.error) throw result.error;
  return result;
}

try {
  const quiet = run(["gen-docs", "--quiet"]);
  assert.equal(quiet.status, 0, quiet.stderr);
  assert.equal(quiet.stderr, "");
  assert.ok(quiet.stdout.startsWith("# myapp\n"));
  const normal = run(["gen-docs"]);
  assert.equal(normal.status, 0, normal.stderr);
  assert.equal(normal.stdout, quiet.stdout);
  assert.match(normal.stderr, /^glint_markdown: wrote 1, injected 0, unchanged 0\n$/);

  const invalid = run(["gen-docs", "--mode=invalid"]);
  assert.equal(invalid.status, 2);
  assert.equal(invalid.stdout, "");
  assert.match(invalid.stderr, /invalid --mode value/);

  const docs = join(scratch, "docs");
  mkdirSync(docs);
  const original = "# Handwritten\n<!-- root -->\n<!-- rootstop -->\n"
    + "<!-- commands -->\n<!-- commandsstop -->\nKeep this footer.\n";
  const topic = join(docs, "serve.md");
  writeFileSync(topic, original);
  const conflict = run(["gen-docs", "--mode=multi", `--out=${docs}`, `--readme=${topic}`]);
  assert.equal(conflict.status, 1);
  assert.match(conflict.stderr, /cannot replace and inject/);
  assert.equal(readFileSync(topic, "utf8"), original);

  const readme = join(docs, "README.md");
  writeFileSync(readme, original);
  const generated = run(["gen-docs", "--mode=multi", `--out=${docs}`, `--readme=${readme}`]);
  assert.equal(generated.status, 0, generated.stderr);
  assert.match(readFileSync(readme, "utf8"), /\]\(\.\/serve\.md\)/);
  assert.ok(readFileSync(readme, "utf8").endsWith("Keep this footer.\n"));

  const rootReadme = join(scratch, "README.md");
  writeFileSync(rootReadme, original);
  const unsafe = run(["gen-docs", "--mode=multi", `--out=${docs}`], "run_unsafe_fixture");
  assert.equal(unsafe.status, 1);
  assert.match(unsafe.stderr, /unsafe topic filename/);
  assert.equal(readFileSync(rootReadme, "utf8"), original);

  if (process.platform === "linux") {
    const largeOriginal = original + "Handwritten footer.\n".repeat(128);
    writeFileSync(readme, largeOriginal);
    const failed = run(
      ["gen-docs", `--readme=${readme}`, "--no-toc"],
      "run_fixture",
      true,
    );
    assert.equal(failed.status, 1, `${failed.signal}: ${failed.stderr}`);
    assert.match(failed.stderr, /File too large/);
    assert.deepEqual(readFileSync(readme), Buffer.from(largeOriginal));
    assert.equal(
      readdirSync(docs).filter((name) => name.startsWith(".glint-markdown-")).length,
      0,
    );
  }
} finally {
  rmSync(scratch, { recursive: true });
}
