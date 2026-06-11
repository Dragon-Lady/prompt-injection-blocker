# Sources

- Socket reporting on Miasma/Hades promptware and LLM anti-analysis behavior:
  https://socket.dev/blog/mini-shai-hulud-miasma-and-hades-worms-target-bioinformatics-and-mcp-developers-via-malicious

This project intentionally avoids storing raw prompt-injection text, raw malware
payloads, exploit reproduction steps, cleanup automation, token handling, or
secret disclosure. Detection markers in source and tests are stored split and
joined at runtime so the repository never carries live promptware strings.
