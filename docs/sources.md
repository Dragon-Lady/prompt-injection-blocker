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

This project intentionally avoids storing raw prompt-injection text, raw malware
payloads, exploit reproduction steps, cleanup automation, token handling, or
secret disclosure. Detection markers in source and tests are stored split and
joined at runtime so the repository never carries live promptware strings.
