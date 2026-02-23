#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");

function fail(message) {
  console.error(`[prepare-platform-package] ${message}`);
  process.exit(1);
}

const [packageDirArg, targetTriple, binaryName, version] = process.argv.slice(2);

if (!packageDirArg || !targetTriple || !binaryName || !version) {
  fail("usage: prepare-platform-package <package-dir> <target-triple> <binary-name> <version>");
}

const repoRoot = path.resolve(__dirname, "..", "..");
const packageDir = path.resolve(repoRoot, packageDirArg);
const packageJsonPath = path.join(packageDir, "package.json");
const sourceBinaryPath = path.join(repoRoot, "target", targetTriple, "release", binaryName);
const vendorRoot = path.join(packageDir, "vendor");
const destinationDir = path.join(vendorRoot, targetTriple, "corgea");
const destinationBinaryPath = path.join(destinationDir, binaryName);

if (!fs.existsSync(packageDir)) {
  fail(`package directory not found: ${packageDir}`);
}

if (!fs.existsSync(packageJsonPath)) {
  fail(`package.json not found: ${packageJsonPath}`);
}

if (!fs.existsSync(sourceBinaryPath)) {
  fail(`compiled binary not found: ${sourceBinaryPath}`);
}

const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"));
packageJson.version = version;
fs.writeFileSync(packageJsonPath, `${JSON.stringify(packageJson, null, 2)}\n`);

fs.rmSync(vendorRoot, { recursive: true, force: true });
fs.mkdirSync(destinationDir, { recursive: true });
fs.copyFileSync(sourceBinaryPath, destinationBinaryPath);

if (binaryName !== "corgea.exe") {
  fs.chmodSync(destinationBinaryPath, 0o755);
}

console.log(`Prepared ${packageJson.name}@${version}`);
console.log(`Binary: ${sourceBinaryPath}`);
console.log(`Output: ${destinationBinaryPath}`);
