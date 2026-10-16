# v0.1.7

- Report file and directory read failures as incomplete scans.
- Refuse report destinations that already exist, including symlink and hardlink aliases.
- Create new report files with private permissions on POSIX.
- Preserve blocking findings (exit 2); incomplete scans without blocking findings exit 1.
- Add regression coverage and require full distribution scans before Trusted Publishing.
