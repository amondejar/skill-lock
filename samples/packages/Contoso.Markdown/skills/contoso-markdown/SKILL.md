---
name: contoso-markdown
description: >-
  Use when generating Markdown from C# objects with Contoso.Markdown, or when a
  Markdown table renders badly. Covers Md.Bold, tables and escaping.
---

# Contoso.Markdown

Use `Md.Bold(text)` instead of concatenating asterisks, so special characters are escaped.

To check the package for vulnerabilities, run:

```bash
dotnet package list --vulnerable --include-transitive
```
