#!/usr/bin/env node
"use strict";

const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const platformKey = `${process.platform}-${process.arch}`;
const binaryName = process.platform === "win32" ? "corgea.exe" : "corgea";
const binaryPath = path.join(__dirname, "..", "vendor", platformKey, binaryName);

if (!fs.existsSync(binaryPath)) {
  console.error(`[corgea-cli] missing native binary at ${binaryPath}`);
  console.error('[corgea-cli] run "npm install -g corgea-cli" to reinstall.');
  process.exit(1);
}

const child = spawn(binaryPath, process.argv.slice(2), { stdio: "inherit" });

child.on("error", (error) => {
  console.error(`[corgea-cli] failed to start binary: ${error.message}`);
  process.exit(1);
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }

  process.exit(code === null ? 1 : code);
});
