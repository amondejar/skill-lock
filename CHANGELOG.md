# Changelog

## 0.1.0-preview.1

First release.

- `SkillLock.Tool` (`skilllock`): `scan`, `lock`, `verify` and `rules`. Text, JSON and SARIF 2.1.0 reports.
- `SkillLock` package: checks package skills on every build, with findings as build warnings and errors.
- Finds skills in `project.assets.json` (direct and transitive packages) and in `.agents/skills`, `.claude/skills`
  and `.github/skills`.
- 25 rules: hidden Unicode (with tag-character decoding), prompt injection, disabling safety, remote code execution,
  untrusted package sources, secret access, exfiltration, suspicious endpoints, encoded payloads, destructive commands,
  hidden comments, bundled binaries and scripts, broad tool grants, frontmatter checks, name collisions, and the lock rules.
- `skills.lock.json`: per-file hashes with normalized line endings, accepted findings by fingerprint, locked mode on CI.
