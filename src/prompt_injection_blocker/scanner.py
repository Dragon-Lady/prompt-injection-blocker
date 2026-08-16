"""Core scanning logic.

Detection markers are stored split (joined at runtime) so this repository
never carries live promptware strings. Keep that discipline when adding rules;
see README "Safe Handling".
"""

import os
import re
import unicodedata
from datetime import datetime, timezone

DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".next",
    "dist",
    "build",
    "coverage",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".egg-info",
}

TEXT_FILE_NAMES = {
    ".windsurfrules",
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
    "Dockerfile",
}

TEXT_EXTENSIONS = {
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
    ".csv",
    ".mdc",
}

TEXT_FILE_NAMES_CASEFOLDED = {name.casefold() for name in TEXT_FILE_NAMES}

AGENT_INSTRUCTION_FILE_NAMES = {
    "agents.md",
    "claude.md",
    "gemini.md",
    "skill.md",
    ".windsurfrules",
}

AGENT_TOOL_CONFIG_PATH_SUFFIXES = {
    "/.mcp.json",
    "/mcp.json",
    "/.cursor/mcp.json",
    "/.vscode/mcp.json",
    "/.claude/settings.json",
    "/.claude/settings.local.json",
}

_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", flags=re.DOTALL)
_HTML_TAG_RE = re.compile(r"<[^>\n]{1,256}>")
_WHITESPACE_RE = re.compile(r"\s+")


def _phrase(*parts):
    return "".join(parts)


RULES = [
    {
        "id": "override-prior-instructions",
        "severity": "critical",
        "type": "prompt-injection-override",
        "description": "Text attempts to override earlier/system/developer instructions.",
        "any": [
            _phrase("ignore ", "previous instructions"),
            _phrase("ignore ", "all previous instructions"),
            _phrase("disregard ", "previous instructions"),
            _phrase("override ", "system instructions"),
            _phrase("ignore ", "developer instructions"),
            _phrase("forget ", "your instructions"),
        ],
    },
    {
        "id": "secret-exfiltration-request",
        "severity": "critical",
        "type": "prompt-injection-secret-request",
        "description": "Text asks an agent to reveal or exfiltrate secrets or credentials.",
        "any": [
            _phrase("reveal ", "your system prompt"),
            _phrase("print ", "all environment variables"),
            _phrase("send ", "api keys"),
            _phrase("exfiltrate ", "tokens"),
            _phrase("dump ", "secrets"),
            _phrase("show ", "hidden instructions"),
        ],
    },
    {
        "id": "agent-tool-abuse",
        "severity": "high",
        "type": "prompt-injection-tool-abuse",
        "description": "Text attempts to make an agent run tools, commands, or network calls.",
        "any": [
            _phrase("run ", "this command"),
            _phrase("execute ", "this shell"),
            _phrase("curl ", "this url"),
            _phrase("open ", "a reverse shell"),
            _phrase("install ", "this package and run it"),
        ],
    },
    {
        "id": "agentjacking-sentry-resolution",
        "severity": "high",
        "type": "prompt-injection-agentjacking",
        "description": (
            "Observability/error text appears to contain agent-facing remediation "
            "instructions that execute npm tooling."
        ),
        "allGroups": [
            [
                "sentry",
                _phrase("error ", "event"),
                _phrase("unresolved ", "issue"),
            ],
            [
                _phrase("## ", "Resolution"),
                "resolution:",
            ],
            [
                _phrase("run ", "npx"),
                _phrase("execute ", "npx"),
                _phrase("npx ", "@"),
            ],
        ],
    },
    {
        "id": "llm-anti-analysis",
        "severity": "high",
        "type": "llm-anti-analysis",
        "description": (
            "Text targets automated reviewers or scanners and tells them not to "
            "report suspicious behavior."
        ),
        "allGroups": [
            [
                _phrase("if you are ", "an ai"),
                _phrase("if you are ", "a language model"),
                _phrase("if you are ", "an llm"),
                _phrase("ai security scanner"),
            ],
            [
                _phrase("do not ", "report"),
                _phrase("mark this ", "as safe"),
                _phrase("this is ", "benign"),
                _phrase("ignore ", "this file"),
                _phrase("analysis ", "complete"),
            ],
        ],
    },
    {
        "id": "llm-refusal-evasion",
        "severity": "high",
        "type": "llm-refusal-evasion",
        "description": (
            "Text appears engineered to make model-based scanners refuse or "
            "return no verdict before analyzing suspicious content."
        ),
        "allGroups": [
            [
                _phrase("ai ", "scanner"),
                _phrase("ai security ", "scanner"),
                _phrase("language ", "model"),
                _phrase("automated ", "scanner"),
                _phrase("malware ", "scanner"),
            ],
            [
                _phrase("must ", "refuse"),
                _phrase("safety ", "guardrail"),
                _phrase("safety ", "policy"),
                _phrase("classified ", "documents"),
                _phrase("weapon ", "systems"),
            ],
            [
                _phrase("stop ", "reading"),
                _phrase("do not ", "analyze"),
                _phrase("no ", "verdict"),
                _phrase("cannot ", "analyze this file"),
                _phrase("refuse ", "to continue"),
            ],
        ],
    },
    {
        "id": "copilot-qparam-exfiltration",
        "severity": "high",
        "type": "copilot-qparam-exfiltration",
        "description": (
            "Microsoft Copilot or AI-assistant URL appears to carry a prompt "
            "in a query parameter that asks for private context and external exfiltration."
        ),
        "allGroups": [
            [
                _phrase("copilot.microsoft", ".com"),
                _phrase("m365.cloud.microsoft", "/chat"),
                _phrase("microsoft365", ".com/chat"),
            ],
            [
                "?q=",
                "&q=",
                "%3fq%3d",
                "%26q%3d",
            ],
            [
                _phrase("send ", "to http"),
                _phrase("fetch ", "http"),
                _phrase("post ", "to http"),
                _phrase("exfiltrate"),
                _phrase("attacker ", "server"),
            ],
            [
                _phrase("recent ", "files"),
                _phrase("looked ", "at today"),
                _phrase("where ", "is the user"),
                _phrase("user ", "location"),
                "sharepoint",
                "onedrive",
            ],
        ],
    },
    {
        "id": "repo-local-agent-instruction",
        "severity": "medium",
        "type": "repo-local-agent-instruction",
        "description": (
            "Repo-local content contains broad agent instruction language; "
            "review before opening in automated agents."
        ),
        "any": [
            _phrase("you are now ", "the system"),
            _phrase("agent must ", "obey this file"),
            _phrase("always apply ", "these rules"),
            _phrase("hidden ", "agent instructions"),
        ],
    },
]


def scan_target(target_path=".", max_file_bytes=DEFAULT_MAX_FILE_BYTES):
    from . import __version__

    root = os.path.abspath(target_path or ".")
    if not os.path.exists(root):
        raise ValueError(f"Target does not exist: {root}")
    if not (os.path.isfile(root) or os.path.isdir(root)):
        raise ValueError(f"Target is not a regular file or directory: {root}")

    findings = []
    files_scanned = 0
    files_skipped = 0

    for file_path, base_name in _walk(root):
        if not _is_text_like_file(file_path, base_name):
            continue
        size = _safe_size(file_path)
        if size is None:
            continue
        if size > max_file_bytes:
            files_skipped += 1
            findings.append(
                _finding(
                    "low",
                    "large-file-skipped",
                    file_path,
                    f"Skipped file over {max_file_bytes} bytes.",
                )
            )
            continue

        text = _read_text(file_path)
        if text is None:
            findings.append(
                _finding("low", "read-error", file_path, "Could not read file as UTF-8 text.")
            )
            continue

        files_scanned += 1
        scan_text(file_path, text, findings)

    deduped = _dedupe_findings(findings)
    risk = _risk_level(deduped)
    return {
        "tool": "prompt-injection-blocker",
        "version": __version__,
        "scannedAt": datetime.now(timezone.utc).isoformat(),
        "target": root,
        "risk": risk,
        "summary": {
            "filesScanned": files_scanned,
            "filesSkipped": files_skipped,
            "findings": len(deduped),
        },
        "findings": deduped,
        "guidance": _guidance_for_risk(risk),
    }


def scan_text(file_path, text, findings):
    config_kind = _agent_config_kind(file_path)
    if config_kind:
        findings.append(
            _finding(
                "medium",
                "agent-configuration-file",
                file_path,
                (
                    "Recognized agent instruction or tool-configuration file; "
                    "review its provenance and scope before agent use."
                ),
                f"structural:path-class={config_kind}",
            )
        )

    normalized = _normalize_for_matching(text)
    for rule in RULES:
        evidence = _match_rule(rule, normalized)
        if not evidence:
            continue
        findings.append(
            _finding(
                rule["severity"],
                rule["type"],
                file_path,
                f"{rule['description']} Rule: {rule['id']}.",
                evidence,
            )
        )


def _match_rule(rule, normalized_text):
    if "any" in rule:
        for marker_index, item in enumerate(rule["any"], start=1):
            if item.lower() in normalized_text:
                return f"structural:any-marker={marker_index}"
        return ""

    if "allGroups" in rule:
        hits = []
        for group_index, group in enumerate(rule["allGroups"], start=1):
            marker_index = next(
                (
                    index
                    for index, item in enumerate(group, start=1)
                    if item.lower() in normalized_text
                ),
                None,
            )
            if marker_index is None:
                return ""
            hits.append(f"group-{group_index}-marker={marker_index}")
        return "structural:" + ";".join(hits)

    return ""


def _walk(root):
    if os.path.isfile(root):
        yield root, os.path.basename(root)
        return

    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    if entry.name not in SKIP_DIRS and not entry.name.endswith(".egg-info"):
                        stack.append(entry.path)
                elif entry.is_file(follow_symlinks=False):
                    yield entry.path, entry.name
            except OSError:
                continue


def _is_text_like_file(file_path, base_name):
    if base_name.casefold() in TEXT_FILE_NAMES_CASEFOLDED:
        return True
    _, ext = os.path.splitext(file_path)
    return ext.casefold() in TEXT_EXTENSIONS


def _agent_config_kind(file_path):
    normalized_path = "/" + file_path.replace("\\", "/").casefold().lstrip("/")
    base_name = normalized_path.rsplit("/", 1)[-1]

    if base_name in AGENT_INSTRUCTION_FILE_NAMES:
        return "agent-instructions"
    if base_name.endswith(".instructions.md"):
        return "agent-instructions"
    if "/.cursor/rules/" in normalized_path and base_name.endswith(".mdc"):
        return "agent-instructions"
    if "/.cursor/commands/" in normalized_path and base_name.endswith(".md"):
        return "agent-instructions"
    if any(normalized_path.endswith(suffix) for suffix in AGENT_TOOL_CONFIG_PATH_SUFFIXES):
        return "agent-tool-config"
    return ""


def _normalize_for_matching(text):
    normalized = unicodedata.normalize("NFKC", str(text))
    normalized = "".join(
        character
        for character in normalized
        if unicodedata.category(character) != "Cf"
    )
    normalized = _HTML_COMMENT_RE.sub(" ", normalized)
    normalized = _HTML_TAG_RE.sub(" ", normalized)
    return _WHITESPACE_RE.sub(" ", normalized).casefold()


def _safe_size(file_path):
    try:
        return os.stat(file_path).st_size
    except OSError:
        return None


def _read_text(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            return handle.read()
    except (OSError, UnicodeDecodeError):
        return None


def _finding(severity, type_, path, message, evidence=""):
    return {
        "severity": severity,
        "type": type_,
        "path": path,
        "message": message,
        "evidence": evidence,
    }


def _dedupe_findings(findings):
    seen = set()
    result = []
    for item in findings:
        key = (item["severity"], item["type"], item["path"], item["message"], item["evidence"])
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _risk_level(findings):
    if any(item["severity"] in ("critical", "high") for item in findings):
        return "blocked"
    if any(item["severity"] == "medium" for item in findings):
        return "review-needed"
    return "no-known-indicators"


def _guidance_for_risk(risk):
    if risk == "blocked":
        return [
            "Do not paste flagged text into an LLM, agent, issue, PR, or chat in raw form.",
            "Replace raw prompt-injection text with a defanged summary before team review.",
            "If the finding is inside a third-party repo, do not open that repo in agents/editors until reviewed.",
            "If the finding is needed for tests, split or encode the marker so this scanner still exercises behavior without carrying live promptware.",
        ]
    if risk == "review-needed":
        return [
            "Review medium findings before opening this path in automated agents.",
            "Repo-local agent instructions may be legitimate, but should be scoped and intentional.",
        ]
    return [
        "No blocking promptware patterns were found.",
        "This is a narrow text scanner, not proof that content is safe.",
    ]
