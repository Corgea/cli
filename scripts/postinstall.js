#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const https = require("node:https");
const path = require("node:path");

const { version } = require("../package.json");

const PLATFORM_MAP = {
  "darwin-arm64": { target: "aarch64-apple-darwin", binaryName: "corgea" },
  "darwin-x64": { target: "x86_64-apple-darwin", binaryName: "corgea" },
  "linux-arm64": { target: "aarch64-unknown-linux-gnu", binaryName: "corgea" },
  "linux-x64": { target: "x86_64-unknown-linux-gnu", binaryName: "corgea" },
  "win32-x64": { target: "x86_64-pc-windows-gnu", binaryName: "corgea.exe" }
};

async function fetchBuffer(url, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    const req = https.get(
      url,
      {
        headers: {
          "User-Agent": "corgea-cli-installer",
          Accept: "application/octet-stream"
        }
      },
      (res) => {
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          if (redirectsLeft <= 0) {
            reject(new Error(`too many redirects for ${url}`));
            return;
          }
          resolve(fetchBuffer(res.headers.location, redirectsLeft - 1));
          return;
        }

        if (res.statusCode !== 200) {
          res.resume();
          reject(new Error(`HTTP ${res.statusCode} for ${url}`));
          return;
        }

        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => resolve(Buffer.concat(chunks)));
      }
    );

    req.on("error", reject);
  });
}

function buildAssetUrls(target, binaryName) {
  const tags = [`v${version}`, version];
  const assetNames = [`corgea-${target}.zip`];
  if (binaryName.endsWith(".exe")) {
    assetNames.unshift(`corgea.exe-${target}.zip`);
  }

  const urls = [];
  for (const tag of tags) {
    for (const assetName of assetNames) {
      urls.push(`https://github.com/Corgea/cli/releases/download/${tag}/${assetName}`);
    }
  }
  return urls;
}

async function downloadFirstAvailable(urls) {
  const errors = [];

  for (const url of urls) {
    try {
      return await fetchBuffer(url);
    } catch (error) {
      errors.push(`${url}: ${error.message}`);
    }
  }

  throw new Error(`unable to download release artifact:\n${errors.join("\n")}`);
}

function extractBinary(zipBytes, binaryName, outputPath) {
  let AdmZip;
  try {
    AdmZip = require("adm-zip");
  } catch (error) {
    throw new Error(`missing dependency "adm-zip": ${error.message}`);
  }

  const zip = new AdmZip(zipBytes);
  const entry = zip
    .getEntries()
    .find((candidate) => !candidate.isDirectory && path.basename(candidate.entryName).toLowerCase() === binaryName.toLowerCase());

  if (!entry) {
    throw new Error(`archive did not include expected binary "${binaryName}"`);
  }

  fs.writeFileSync(outputPath, entry.getData());
}

async function main() {
  if (process.env.CORGEA_SKIP_POSTINSTALL === "1") {
    console.log("Skipping Corgea binary installation (CORGEA_SKIP_POSTINSTALL=1).");
    return;
  }

  const platformKey = `${process.platform}-${process.arch}`;
  const platformConfig = PLATFORM_MAP[platformKey];

  if (!platformConfig) {
    throw new Error(`unsupported platform ${platformKey}. Supported: ${Object.keys(PLATFORM_MAP).join(", ")}`);
  }

  const installDir = path.join(__dirname, "..", "vendor", platformKey);
  const binaryPath = path.join(installDir, platformConfig.binaryName);

  if (fs.existsSync(binaryPath)) {
    return;
  }

  fs.mkdirSync(installDir, { recursive: true });

  const urls = buildAssetUrls(platformConfig.target, platformConfig.binaryName);
  const archiveBytes = await downloadFirstAvailable(urls);
  extractBinary(archiveBytes, platformConfig.binaryName, binaryPath);

  if (process.platform !== "win32") {
    fs.chmodSync(binaryPath, 0o755);
  }

  console.log(`Installed Corgea ${version} binary for ${platformKey}.`);
}

main().catch((error) => {
  console.error(`[corgea-cli] ${error.message}`);
  process.exit(1);
});
