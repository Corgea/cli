#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { unzipSync } = require("fflate");

const TARGETS = [
  { triple: "x86_64-unknown-linux-gnu",  binary: "corgea" },
  { triple: "aarch64-unknown-linux-gnu", binary: "corgea" },
  { triple: "x86_64-apple-darwin",       binary: "corgea" },
  { triple: "aarch64-apple-darwin",      binary: "corgea" },
  { triple: "x86_64-pc-windows-msvc",    binary: "corgea.exe" },
];

function fail(message) {
  console.error(`[bundle-binaries] ${message}`);
  process.exit(1);
}

const [assetsDirArg] = process.argv.slice(2);
if (!assetsDirArg) {
  fail("usage: bundle-binaries <assets-dir>");
}

const repoRoot = path.resolve(__dirname, "..", "..");
const assetsDir = path.resolve(assetsDirArg);
const vendorRoot = path.join(repoRoot, "vendor");

fs.rmSync(vendorRoot, { recursive: true, force: true });

for (const { triple, binary } of TARGETS) {
  const archiveName = `corgea-${triple}.zip`;
  const archivePath = path.join(assetsDir, archiveName);

  if (!fs.existsSync(archivePath)) {
    fail(`missing release asset: ${archivePath}`);
  }

  const destDir = path.join(vendorRoot, triple, "corgea");
  fs.mkdirSync(destDir, { recursive: true });

  const zipBuffer = fs.readFileSync(archivePath);
  const entries = unzipSync(new Uint8Array(zipBuffer));

  const entry = Object.entries(entries).find(([name]) => path.basename(name) === binary);
  if (!entry) {
    fail(`binary "${binary}" not found inside ${archiveName}`);
  }

  const binaryPath = path.join(destDir, binary);
  fs.writeFileSync(binaryPath, entry[1]);

  if (!binary.endsWith(".exe")) {
    fs.chmodSync(binaryPath, 0o755);
  }

  console.log(`Bundled ${triple}: ${binaryPath}`);
}
