# Sources

- Socket reporting on Miasma/Hades promptware and LLM anti-analysis behavior:
  https://socket.dev/blog/mini-shai-hulud-miasma-and-hades-worms-target-bioinformatics-and-mcp-developers-via-malicious
- JFrog Security Research on prompt-injection against model-based scanners:
  https://research.jfrog.com/post/prompt-injection-vs-scanners/
- BleepingComputer Microsoft 365 Copilot Reprompt / one-click data-theft
  coverage:
  https://www.bleepingcomputer.com/news/security/new-attack-turned-microsoft-365-copilot-into-1-click-data-theft-tool/
- Windows Central summary of Varonis Reprompt details:
  https://www.windowscentral.com/artificial-intelligence/microsoft-copilot/copilot-ai-reprompt-exploit-detailed-2026
- OpenAI on prompt injection as a source-to-sink and social-engineering risk:
  https://openai.com/index/designing-agents-to-resist-prompt-injection/
- Microsoft guidance on defense in depth for indirect prompt injection:
  https://learn.microsoft.com/en-us/security/zero-trust/sfi/defend-indirect-prompt-injection
- GitHub's agentic security principles, including invisible-context handling:
  https://github.blog/ai-and-ml/github-copilot/how-githubs-agentic-security-principles-make-our-ai-agents-as-secure-as-possible/
- GitHub's agent-skill provenance and pre-install inspection guidance:
  https://github.blog/changelog/2026-04-16-manage-agent-skills-with-github-cli/
- Anthropic on layered defenses and constrained tools/data for trustworthy agents:
  https://www.anthropic.com/research/trustworthy-agents
- OWASP's vendor-neutral prompt-injection prevention guidance:
  https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html
- 0DIN research on normal-looking repositories whose setup chains fetch
  runtime behavior that static repository scanning cannot establish:
  https://0din.ai/blog/clone-this-repo-and-i-own-your-machine

This project intentionally avoids storing raw prompt-injection text, raw malware
payloads, exploit reproduction steps, cleanup automation, token handling, or
secret disclosure. Detection markers in source and tests are stored split and
joined at runtime so the repository never carries live promptware strings.
