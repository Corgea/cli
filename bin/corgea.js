#!/usr/bin/env node
"use strict";

const { spawn } = require("node:child_process");
const { existsSync } = require("node:fs");
const path = require("node:path");

const PLATFORM_PACKAGE_BY_TARGET = {
  "x86_64-unknown-linux-gnu": "corgea-cli-linux-x64",
  "aarch64-unknown-linux-gnu": "corgea-cli-linux-arm64",
  "x86_64-apple-darwin": "corgea-cli-darwin-x64",
  "aarch64-apple-darwin": "corgea-cli-darwin-arm64",
  "x86_64-pc-windows-msvc": "corgea-cli-win32-x64"
};

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

function detectPackageManager() {
  const userAgent = process.env.npm_config_user_agent || "";
  if (/\bbun\//.test(userAgent)) return "bun";

  const execPath = process.env.npm_execpath || "";
  if (execPath.includes("bun")) return "bun";

  if (__dirname.includes(".bun/install/global") || __dirname.includes(".bun\\install\\global")) {
    return "bun";
  }

  if (/\bpnpm\//.test(userAgent) || execPath.includes("pnpm")) return "pnpm";
  if (/\byarn\//.test(userAgent) || execPath.includes("yarn")) return "yarn";
  return userAgent ? "npm" : null;
}

function getReinstallCommand() {
  const manager = detectPackageManager();
  if (manager === "bun") return "bun install -g corgea-cli@latest";
  if (manager === "pnpm") return "pnpm add -g corgea-cli@latest";
  if (manager === "yarn") return "yarn global add corgea-cli@latest";
  return "npm install -g corgea-cli@latest";
}

function getUpdatedPath(newDirs) {
  const pathSep = process.platform === "win32" ? ";" : ":";
  const existingPath = process.env.PATH || "";
  return [...newDirs, ...existingPath.split(pathSep).filter(Boolean)].join(pathSep);
}

const targetTriple = resolveTargetTriple();
if (!targetTriple) {
  throw new Error(`Unsupported platform: ${process.platform} (${process.arch})`);
}

const platformPackage = PLATFORM_PACKAGE_BY_TARGET[targetTriple];
if (!platformPackage) {
  throw new Error(`Unsupported target triple: ${targetTriple}`);
}

const binaryName = process.platform === "win32" ? "corgea.exe" : "corgea";
const localVendorRoot = path.join(__dirname, "..", "vendor");
const localBinaryPath = path.join(localVendorRoot, targetTriple, "corgea", binaryName);

let vendorRoot = null;
try {
  const packageJsonPath = require.resolve(`${platformPackage}/package.json`);
  vendorRoot = path.join(path.dirname(packageJsonPath), "vendor");
} catch (error) {
  if (existsSync(localBinaryPath)) {
    vendorRoot = localVendorRoot;
  } else {
    throw new Error(`Missing optional dependency ${platformPackage}. Reinstall Corgea CLI: ${getReinstallCommand()}`);
  }
}

const archRoot = path.join(vendorRoot, targetTriple);
const binaryPath = path.join(archRoot, "corgea", binaryName);

if (!existsSync(binaryPath)) {
  throw new Error(`Corgea binary not found at ${binaryPath}`);
}

const additionalDirs = [];
const pathDir = path.join(archRoot, "path");
if (existsSync(pathDir)) {
  additionalDirs.push(pathDir);
}

const env = { ...process.env, PATH: getUpdatedPath(additionalDirs) };
const packageManagerEnvVar = detectPackageManager() === "bun" ? "CORGEA_MANAGED_BY_BUN" : "CORGEA_MANAGED_BY_NPM";
env[packageManagerEnvVar] = "1";

const child = spawn(binaryPath, process.argv.slice(2), { stdio: "inherit", env });

child.on("error", (error) => {
  console.error(error);
  process.exit(1);
});

const forwardSignal = (signal) => {
  if (child.killed) return;
  try {
    child.kill(signal);
  } catch (error) {
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
