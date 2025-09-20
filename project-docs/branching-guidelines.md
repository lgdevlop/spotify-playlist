# 🌿 Branch Naming Guidelines

This project is a Next.js web application focused on Spotify playlist management. These branching guidelines are adapted to fit the development workflows and team practices specific to this project, while following widely accepted best practices.

This document defines the official branch naming convention for this repository, with the goal of improving clarity, traceability, and compatibility with CI workflows, Pull Requests, and automation.

## ✅ General Structure

```bash
<type>/<scope>-<kebab-case-description>
```

| Element         | Description                                                                 |
| --------------- | --------------------------------------------------------------------------- |
| `<type>`        | Change type, aligned with conventional commit types (feat, fix, docs, etc.) |
| `<scope>`       | Affected module, folder, or context (e.g., `cli`, `core`, `git`, `ci`)       |
| `<description>` | Brief, clear description of the change intention, in kebab-case             |

### Examples

```text
docs/ssh-agent-setup-guide
feat/devcontainer-add-java-support
fix/ci-docker-tag-suffix-conflict
refactor/image-generation-unify-script
chore/root-remove-image-tag-file
```

## 📖 Recommended Types (`<type>`)

Use the same categories as in your semantic commit messages:

- `feat/` – New feature
- `fix/` – Bug fix
- `docs/` – Documentation only
- `refactor/` – Code refactoring with no behavior change
- `chore/` – Maintenance tasks or cleanup
- `ci/` – CI/CD configuration or workflow changes
- `build/` – Build process or dependency updates
- `test/` – Test structure or logic changes

## ✍️ Best Practices

- Always use **kebab-case** for the description part
- Be specific with the scope without being overly verbose
- The description should express **intent**, not just the result:
  - 👍 `add-ssh-agent-setup`
  - 👎 `ssh-docs`
- Avoid vague names like:
  - `fix-bug`, `update-stuff`, `docs-readme`
- Aim for a total length of around 5 words or fewer

## 🔄 Integration with PRs and Commits

When opening a Pull Request, match the scope and type of the branch in your PR title or merge commit message. Example:

**Branch:**

```text
docs/ssh-agent-setup-guide
```

**PR / Merge Commit Title:**

```text
📚 docs: add SSH agent setup guide and link in README (#2)
```

## 🚨 Reserved Branches

Avoid committing directly to this branch:

- `master` — Stable production branch

All contributions must go through Pull Requests from named feature branches following this convention.

## 🧠 Benefits

- Improves automation and changelog generation
- Enables filtering via `git log`, `--grep`, or GitHub APIs
- Standardizes communication across code, PRs, and CI
- Eases onboarding for new contributors

> For merge commit and PR message conventions, see: `project-docs/merge-commit-guidelines.md`
