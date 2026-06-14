# Prompt Injection Blocker

Read-only scanner for prompt-injection and LLM anti-analysis text in files
before agent review.

This tool is meant for defensive intake: copied advisories, incident notes,
third-party repositories, docs, issues, and fixtures that may contain text aimed
at overriding an AI assistant or suppressing analysis.

It does not remove files, modify content, execute code, contact registries, or
prove that content is safe.

## Install

```sh
pipx install prompt-injection-blocker
# or
pip install prompt-injection-blocker
```

Python 3.9+. No runtime dependencies.

## Usage

```sh
prompt-injection-blocker /path/to/project
prompt-injection-blocker /path/to/project --json
prompt-injection-blocker /path/to/project --report report.json
```

From a source checkout:

```sh
python -m prompt_injection_blocker /path/to/project
pip install -e ".[dev]" && pytest
```

Exit codes:

- `0`: no blocking promptware patterns found
- `1`: usage or runtime error
- `2`: blocking promptware patterns found

## What It Flags

- prompt-injection text that tries to override prior/system/developer
  instructions
- text asking an agent to reveal secrets, hidden instructions, environment
  variables, or tokens
- text trying to make an agent run commands or fetch external content
- observability/tool-output text, such as fake Sentry resolutions, that tries
  to make an agent run package-manager diagnostics
- LLM-targeted anti-analysis language that tells scanners not to report
  suspicious content
- broad repo-local agent instruction language that deserves review before
  opening a path in automated agents

The rules are intentionally conservative. A finding means "do not feed this raw
text into an agent," not "this file is malware."

## Safe Handling

- Do not paste flagged text into agents in raw form.
- Summarize or defang prompt-injection text before sharing with the team.
- If this appears in a third-party repository, do not open the repo in agents or
  editors until reviewed.
- If a test needs one of these markers, split or encode it so the test remains
  meaningful without carrying live promptware. This codebase stores all of its
  own detection markers split and joins them at runtime; keep that discipline
  when adding rules.

## Scope Limits

This scanner only checks text-like files and known phrase families. It will not
detect every possible prompt-injection attempt, encoded payload, image-only
instruction, or model-specific attack.
