import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import { requireMcpOperationResult } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";
import { riscvRawFixture } from "../tests/conformance/ghidra/riscv-raw-fixture.mjs";

assert.ok(
  ["linux", "darwin", "win32"].includes(process.platform),
  "Requires a supported Ghidra host",
);
assert.ok(
  process.env.GHIDRA_INSTALL_DIR,
  "Set GHIDRA_INSTALL_DIR to BYO Ghidra",
);
const run = createVerifierRun();
const root = await mkdtemp(join(tmpdir(), "rea-riscv-raw-"));
const runtime = join(root, "runtime");
await mkdir(runtime);
const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const env = {
  ...process.env,
  TMPDIR: runtime,
  TMP: runtime,
  TEMP: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
};
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env,
  stderr: "pipe",
});
const client = new Client({ name: "riscv-raw-verifier", version: "1" });
let diagnostics = "";
transport.stderr?.on("data", (chunk) => {
  diagnostics = (diagnostics + chunk.toString()).slice(-65536);
});
const reports = [];
try {
  await client.connect(transport);
  for (const bits of [32, 64]) {
    const bytes = riscvRawFixture(bits);
    const path = join(root, `rv${bits}.bin`);
    await writeFile(path, bytes);
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    const args = {
      path,
      format: "raw-binary",
      architecture: "riscv",
      bit_width: bits,
      base_address: "0x9ffff000",
      entry_point: "0xa0000000",
    };
    await call("open_binary", args);
    const image = await call("inspect_native_load_image");
    assert.equal(image.status, "verified", JSON.stringify(image));
    assert.equal(image.observations.language_id, `RISCV:LE:${bits}:default`);
    assert.equal(image.observations.compiler_spec_id, "gcc");
    assert.equal(image.base_address, args.base_address);
    assert.deepEqual(image.entry, {
      address: args.entry_point,
      file_offset: 0x1000,
    });
    const instruction = await call("inspect_native_instruction", {
      address: args.entry_point,
    });
    assert.equal(instruction.status, "decoded");
    const callees = await call("procedure_callees", {
      procedure: args.entry_point,
    });
    assert.ok(
      JSON.stringify(callees).includes("0xa0000020"),
      JSON.stringify(callees),
    );
    const code = await call("procedure_pseudo_code", {
      procedure: args.entry_point,
    });
    assert.ok(typeof code === "string" && code.trim().length > 0);
    const global = await call("read_bytes", {
      address: "0xa0000030",
      length: 4,
    });
    assert.equal(global.bytes_hex, "07000000");
    const references = await call("inspect_native_instruction", {
      address: "0xa0000024",
    });
    assert.ok(
      JSON.stringify(references).includes("0xa0000030"),
      JSON.stringify(references),
    );
    const status = await call("binary_session");
    await call("open_binary", {
      ...args,
      base_address: "0x09ffff000",
      entry_point: "0x0a0000000",
    });
    assert.equal(
      (await call("binary_session")).analysis_run.run_id,
      status.analysis_run.run_id,
    );
    await call("close_binary");
    const { stdout } = await promisify(execFile)(
      process.execPath,
      [
        entrypoint,
        "inspect-native-load-image",
        path,
        "--target-format",
        "raw-binary",
        "--architecture",
        "riscv",
        "--bit-width",
        String(bits),
        "--base-address",
        args.base_address,
        "--entry-point",
        args.entry_point,
        "--provider",
        "ghidra",
        "--json",
      ],
      { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
    );
    const cli = parseEvidence(JSON.parse(stdout));
    assert.equal(cli.subject.digest.sha256, sha256);
    assert.equal(cli.normalized_result.status, "verified");
    assert.equal(cli.analysis_profile.parameters.bit_width, bits);
    assert.deepEqual(await readFile(path), bytes);
    reports.push({
      bits,
      sha256,
      language: image.observations.language_id,
      base: image.base_address,
      entry: image.entry,
      cli: true,
      mcp: true,
      direct_call: true,
      global_reference: true,
      pseudocode: true,
      canonical_reuse: true,
    });
  }
} catch (error) {
  if (diagnostics) process.stderr.write(diagnostics);
  throw error;
} finally {
  await client.close();
  await transport.close();
  const leftovers = await readdir(runtime);
  assert.deepEqual(leftovers, [], "Owned runtime roots must be cleaned");
  assert.equal(dirname(resolve(root)), resolve(tmpdir()));
  assert.ok(root.includes("rea-riscv-raw-"));
  await rm(root, { recursive: true, force: true });
}
const completed = await completeVerifierRun(run);
if (process.platform !== "win32") {
  assert.equal(completed.process_lineage.status, "verified");
  assert.deepEqual(completed.process_lineage.descendants, []);
}
process.stdout.write(
  JSON.stringify({
    host: process.platform,
    verifier_run: completed,
    reports,
    cleanup: "complete",
  }) + "\n",
);
async function call(name, args = {}) {
  return requireMcpOperationResult(
    await client.callTool({ name, arguments: args }, { timeout: 240000 }),
    name,
  );
}
