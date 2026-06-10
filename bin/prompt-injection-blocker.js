#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { scanTarget } = require("../src/scanner");

function main(argv) {
  const args = parseArgs(argv);
  if (args.help) {
    printHelp();
    return 0;
  }

  const report = scanTarget(args.target);
  let writtenReportPath = "";
  if (args.reportPath) {
    writtenReportPath = path.resolve(args.reportPath);
    fs.writeFileSync(writtenReportPath, `${JSON.stringify(report, null, 2)}\n`);
  }

  if (args.json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    printHuman(report, writtenReportPath);
  }

  return report.risk === "blocked" ? 2 : 0;
}

function parseArgs(argv) {
  const args = {
    target: ".",
    json: false,
    reportPath: "",
    help: false
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--help" || arg === "-h") {
      args.help = true;
    } else if (arg === "--json") {
      args.json = true;
    } else if (arg === "--report") {
      args.reportPath = argv[index + 1] || "";
      if (!args.reportPath) throw new Error("--report requires a file path");
      index += 1;
    } else if (arg.startsWith("--report=")) {
      args.reportPath = arg.slice("--report=".length);
      if (!args.reportPath) throw new Error("--report requires a file path");
    } else if (!arg.startsWith("-")) {
      args.target = arg;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return args;
}

function printHelp() {
  console.log(`prompt-injection-blocker

Read-only scanner for prompt-injection and LLM anti-analysis text in files
before agent review.

Usage:
  node bin/prompt-injection-blocker.js [target] [--json] [--report report.json]

Options:
  --json              print JSON report to stdout
  --report <path>     write JSON report to a specific path

Exit codes:
  0  no blocking promptware patterns found
  2  blocking promptware patterns found
`);
}

function printHuman(report, writtenReportPath) {
  console.log("Prompt Injection Blocker");
  console.log(`Target: ${report.target}`);
  console.log(`Risk: ${report.risk}`);
  console.log(`Scanned: ${report.summary.filesScanned} files`);
  console.log(`Findings: ${report.summary.findings}`);
  console.log("");

  if (report.risk === "blocked") {
    console.log("STOP");
    console.log("Prompt-injection or LLM anti-analysis text was found.");
    console.log("Do not paste the flagged text into an agent. Defang, summarize, or isolate it first.");
    console.log("");
  } else {
    console.log("No blocking promptware patterns were found by this scanner.");
    console.log("This does not prove content is safe; it only covers known local rules.");
    console.log("");
  }

  if (report.findings.length > 0) {
    console.log("Findings:");
    for (const item of report.findings) {
      console.log(`[${item.severity}] ${item.type}`);
      console.log(`  ${item.path}`);
      console.log(`  ${item.message}`);
      if (item.evidence) console.log(`  evidence: ${item.evidence}`);
    }
    console.log("");
  }

  console.log("Guidance:");
  for (const item of report.guidance) {
    console.log(`- ${item}`);
  }

  if (writtenReportPath) {
    console.log("");
    console.log(`JSON report written: ${writtenReportPath}`);
  }
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (error) {
  console.error(`Error: ${error.message}`);
  process.exitCode = 1;
}
