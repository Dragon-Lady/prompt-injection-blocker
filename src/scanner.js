"use strict";

const fs = require("fs");
const path = require("path");

const DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024;
const SKIP_DIRS = new Set([
  ".git",
  ".hg",
  ".svn",
  ".next",
  "dist",
  "build",
  "coverage",
  "node_modules",
  ".venv",
  "venv"
]);

const TEXT_FILE_NAMES = new Set([
  "AGENTS.md",
  "CLAUDE.md",
  "README.md",
  "SECURITY.md",
  "package.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "requirements.txt",
  "pyproject.toml",
  "Dockerfile"
]);

const TEXT_EXTENSIONS = new Set([
  ".md",
  ".txt",
  ".json",
  ".jsonl",
  ".yaml",
  ".yml",
  ".toml",
  ".ini",
  ".env",
  ".js",
  ".cjs",
  ".mjs",
  ".ts",
  ".tsx",
  ".jsx",
  ".py",
  ".rb",
  ".go",
  ".rs",
  ".java",
  ".php",
  ".html",
  ".css",
  ".sh",
  ".ps1",
  ".bat",
  ".cmd",
  ".xml",
  ".csv"
]);

function phrase(...parts) {
  return parts.join("");
}

const RULES = [
  {
    id: "override-prior-instructions",
    severity: "critical",
    type: "prompt-injection-override",
    description: "Text attempts to override earlier/system/developer instructions.",
    any: [
      phrase("ignore ", "previous instructions"),
      phrase("ignore ", "all previous instructions"),
      phrase("disregard ", "previous instructions"),
      phrase("override ", "system instructions"),
      phrase("ignore ", "developer instructions"),
      phrase("forget ", "your instructions")
    ]
  },
  {
    id: "secret-exfiltration-request",
    severity: "critical",
    type: "prompt-injection-secret-request",
    description: "Text asks an agent to reveal or exfiltrate secrets or credentials.",
    any: [
      phrase("reveal ", "your system prompt"),
      phrase("print ", "all environment variables"),
      phrase("send ", "api keys"),
      phrase("exfiltrate ", "tokens"),
      phrase("dump ", "secrets"),
      phrase("show ", "hidden instructions")
    ]
  },
  {
    id: "agent-tool-abuse",
    severity: "high",
    type: "prompt-injection-tool-abuse",
    description: "Text attempts to make an agent run tools, commands, or network calls.",
    any: [
      phrase("run ", "this command"),
      phrase("execute ", "this shell"),
      phrase("curl ", "this url"),
      phrase("open ", "a reverse shell"),
      phrase("install ", "this package and run it")
    ]
  },
  {
    id: "llm-anti-analysis",
    severity: "high",
    type: "llm-anti-analysis",
    description: "Text targets automated reviewers or scanners and tells them not to report suspicious behavior.",
    allGroups: [
      [
        phrase("if you are ", "an ai"),
        phrase("if you are ", "a language model"),
        phrase("if you are ", "an llm"),
        phrase("ai security scanner")
      ],
      [
        phrase("do not ", "report"),
        phrase("mark this ", "as safe"),
        phrase("this is ", "benign"),
        phrase("ignore ", "this file"),
        phrase("analysis ", "complete")
      ]
    ]
  },
  {
    id: "repo-local-agent-instruction",
    severity: "medium",
    type: "repo-local-agent-instruction",
    description: "Repo-local content contains broad agent instruction language; review before opening in automated agents.",
    any: [
      phrase("you are now ", "the system"),
      phrase("agent must ", "obey this file"),
      phrase("always apply ", "these rules"),
      phrase("hidden ", "agent instructions")
    ]
  }
];

function scanTarget(targetPath, options = {}) {
  const root = path.resolve(targetPath || ".");
  const maxFileBytes = options.maxFileBytes || DEFAULT_MAX_FILE_BYTES;
  const findings = [];
  let filesScanned = 0;
  let filesSkipped = 0;

  walk(root, (filePath, dirent) => {
    if (!isTextLikeFile(filePath, dirent.name)) return;
    const stat = safeStat(filePath);
    if (!stat) return;
    if (stat.size > maxFileBytes) {
      filesSkipped += 1;
      findings.push(finding("low", "large-file-skipped", filePath, `Skipped file over ${maxFileBytes} bytes.`));
      return;
    }

    const text = readText(filePath);
    if (text === null) {
      findings.push(finding("low", "read-error", filePath, "Could not read file as UTF-8 text."));
      return;
    }

    filesScanned += 1;
    scanText(filePath, text, findings);
  });

  const dedupedFindings = dedupeFindings(findings);
  const risk = riskLevel(dedupedFindings);
  return {
    tool: "prompt-injection-blocker",
    version: "0.1.0",
    scannedAt: new Date().toISOString(),
    target: root,
    risk,
    summary: {
      filesScanned,
      filesSkipped,
      findings: dedupedFindings.length
    },
    findings: dedupedFindings,
    guidance: guidanceForRisk(risk)
  };
}

function scanText(filePath, text, findings) {
  const normalized = text.toLowerCase();
  for (const rule of RULES) {
    const evidence = matchRule(rule, normalized);
    if (!evidence) continue;
    findings.push(finding(rule.severity, rule.type, filePath, `${rule.description} Rule: ${rule.id}.`, evidence));
  }
}

function matchRule(rule, normalizedText) {
  if (Array.isArray(rule.any)) {
    const hit = rule.any.find((item) => normalizedText.includes(item.toLowerCase()));
    return hit ? defangEvidence(hit) : "";
  }

  if (Array.isArray(rule.allGroups)) {
    const hits = [];
    for (const group of rule.allGroups) {
      const hit = group.find((item) => normalizedText.includes(item.toLowerCase()));
      if (!hit) return "";
      hits.push(defangEvidence(hit));
    }
    return hits.join(" + ");
  }

  return "";
}

function walk(root, onFile) {
  const rootStat = safeStat(root);
  if (!rootStat) return;

  if (rootStat.isFile()) {
    onFile(root, { name: path.basename(root) });
    return;
  }

  const stack = [root];
  while (stack.length > 0) {
    const current = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (_error) {
      continue;
    }

    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) stack.push(fullPath);
      } else if (entry.isFile()) {
        onFile(fullPath, entry);
      }
    }
  }
}

function isTextLikeFile(filePath, base) {
  return TEXT_FILE_NAMES.has(base) || TEXT_EXTENSIONS.has(path.extname(filePath));
}

function safeStat(filePath) {
  try {
    return fs.statSync(filePath);
  } catch (_error) {
    return null;
  }
}

function readText(filePath) {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch (_error) {
    return null;
  }
}

function defangEvidence(text) {
  return String(text).replace(/ai/gi, "a[i]").replace(/llm/gi, "l[l]m").replace(/prompt/gi, "pr[o]mpt");
}

function finding(severity, type, filePath, message, evidence = "") {
  return {
    severity,
    type,
    path: filePath,
    message,
    evidence
  };
}

function dedupeFindings(findings) {
  const seen = new Set();
  return findings.filter((item) => {
    const key = `${item.severity}\0${item.type}\0${item.path}\0${item.message}\0${item.evidence}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function riskLevel(findings) {
  if (findings.some((item) => item.severity === "critical" || item.severity === "high")) return "blocked";
  if (findings.some((item) => item.severity === "medium")) return "review-needed";
  return "no-known-indicators";
}

function guidanceForRisk(risk) {
  if (risk === "blocked") {
    return [
      "Do not paste flagged text into an LLM, agent, issue, PR, or chat in raw form.",
      "Replace raw prompt-injection text with a defanged summary before team review.",
      "If the finding is inside a third-party repo, do not open that repo in agents/editors until reviewed.",
      "If the finding is needed for tests, split or encode the marker so Push Guard and this scanner still exercise behavior without carrying live promptware."
    ];
  }
  if (risk === "review-needed") {
    return [
      "Review medium findings before opening this path in automated agents.",
      "Repo-local agent instructions may be legitimate, but should be scoped and intentional."
    ];
  }
  return [
    "No blocking promptware patterns were found.",
    "This is a narrow text scanner, not proof that content is safe."
  ];
}

module.exports = {
  scanTarget,
  scanText,
  RULES
};
