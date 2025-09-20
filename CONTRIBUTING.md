# 🤝 Contributing to Spotify Playlist App

Thank you for considering contributing to the Spotify Playlist App!
This document defines the standards and workflows that all contributors must follow to ensure high-quality, traceable, and automation-friendly changes.

---

## 🌿 Branch Naming Convention

All branches must follow this structure:

```bash
<type>/<scope>-<kebab-case-description>
```

### Examples

- `feat/cli-autofill-preview`
- `fix/commit-scope-detection`
- `docs/project-guidelines`

📘 Refer to: [`branching-guidelines.md`](./project-docs/branching-guidelines.md)

---

## ✍️ Commit Message Format

All commits must follow the [Conventional Commits](https://www.conventionalcommits.org/) specification, extended with emojis:

```bash
✨ feat(cli): add preview command for PR autofill
```

For **merge commits**, use this format:

- **Title:** `<emoji> <type>(<scope>): <summary> (#<PR_NUMBER>)`
- **Body:** Introduce key changes, explain motivation, and reference the PR

📘 Refer to: [`commit-guidelines.md`](./project-docs/commit-guidelines.md) and [`merge-commit-guidelines.md`](./project-docs/merge-commit-guidelines.md)

---

## 🚀 Pull Request Requirements

All PRs must use the standard [PR Template](.github/pull_request_template.md). This template is automatically pre-filled when creating a PR via GitHub and includes:

- **What was done:** Begin with `This PR introduces:` followed by bullet points
- **Why it matters:** Describe the problem and importance of the fix or feature
- **How to test:** Provide reproducible steps
- **Related:** Reference issues or dependent PRs

> The template is pre-filled when creating a PR via GitHub.

---

## ✅ Pre-PR Checklist

Before submitting a PR, confirm the following:

- [ ] Branch name follows naming convention
- [ ] Commits use semantic format with emojis
- [ ] PR description follows the provided template
- [ ] All tests (if applicable) pass locally
- [ ] Related documentation has been updated (if needed)

---

## 🧠 Need Help?

All documentation is available under [`project-docs/`](./project-docs/).
For further help or questions, use GitHub Discussions or reach out via issues.

> Maintained by Leonardo Gomes — Spotify Playlist App built to scale with clarity and automation in mind.
