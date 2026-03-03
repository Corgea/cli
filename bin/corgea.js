#!/usr/bin/env node
"use strict";

const { spawn } = require("node:child_process");
const { existsSync } = require("node:fs");
const path = require("node:path");

function resolveTargetTriple() {
  switch (process.platform) {
    case "linux":
    case "android":
      if (process.arch === "x64") return "x86_64-unknown-linux-gnu";
      if (process.arch === "arm64") return "aarch64-unknown-linux-gnu";
      return null;
    case "darwin":
      if (process.arch === "x64") return "x86_64-apple-darwin";
      if (process.arch === "arm64") return "aarch64-apple-darwin";
      return null;
    case "win32":
      if (process.arch === "x64") return "x86_64-pc-windows-msvc";
      return null;
    default:
      return null;
  }
}

const targetTriple = resolveTargetTriple();
if (!targetTriple) {
  throw new Error(`Unsupported platform: ${process.platform} (${process.arch})`);
}

const binaryName = process.platform === "win32" ? "corgea.exe" : "corgea";
const vendorRoot = path.join(__dirname, "..", "vendor");
const binaryPath = path.join(vendorRoot, targetTriple, "corgea", binaryName);

if (!existsSync(binaryPath)) {
  throw new Error(
    `Corgea binary not found at ${binaryPath}.\n` +
    `Try reinstalling: npm install -g corgea-cli@latest`
  );
}

const child = spawn(binaryPath, process.argv.slice(2), {
  stdio: "inherit",
  env: process.env,
});

child.on("error", (error) => {
  console.error(error);
  process.exit(1);
});

const forwardSignal = (signal) => {
  if (child.killed) return;
  try {
    child.kill(signal);
  } catch {
    // Ignore signal forwarding errors.
  }
};

["SIGINT", "SIGTERM", "SIGHUP"].forEach((signal) => {
  process.on(signal, () => forwardSignal(signal));
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }

  process.exit(code === null ? 1 : code);
});
