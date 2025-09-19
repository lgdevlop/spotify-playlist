# Commit Message Conventions

This project uses **semantic commits with Gitmoji prefixes** to improve clarity, consistency, and automation in version control.

We follow a format inspired by [Conventional Commits](https://www.conventionalcommits.org/) and [Gitmoji](https://gitmoji.dev), with the emoji placed **at the beginning** of the message.

---

## 🧩 Format

```bash
<emoji> type(scope): message
```

### ✅ Example

```bash
✨ feat(frontend): add playlist preview feature
```

---

## 🔠 Type Reference

| Type      | Purpose                                      | Emoji | Example                                                |
|-----------|----------------------------------------------|--------|---------------------------------------------------------|
| `feat`    | Add a new feature                            | ✨     | `✨ feat(ai): improve playlist recommendation`         |
| `fix`     | Bug fix                                      | 🐛     | `🐛 fix(auth): handle token refresh error`             |
| `docs`    | Documentation update                         | 📝     | `📝 docs(README): update setup instructions`           |
| `style`   | Code style change (no logic impact)          | 🎨     | `🎨 style(ui): adjust button spacing`                   |
| `refactor`| Code refactor (no feature/bug fix)           | ♻️     | `♻️ refactor(backend): simplify API route handlers`    |
| `perf`    | Performance improvement                      | ⚡     | `⚡ perf(spotify-api): optimize playlist fetch`         |
| `test`    | Add or update tests                          | ✅     | `✅ test(frontend): add unit tests for playlist component` |
| `build`   | Build-related changes                        | 📦     | `📦 build(ci): update Node.js version`                  |
| `ci`      | CI/CD changes (pipelines, workflows)         | 👷     | `👷 ci(actions): add lint and test stages`              |
| `chore`   | Other minor tasks (deps, tooling, cleanup)   | 🔧     | `🔧 chore(deps): update dependencies`                   |
| `revert`  | Revert a previous commit                     | ⏪     | `⏪ revert(frontend): undo playlist preview changes`    |

---

## 📌 Scope Reference

| Scope        | Description                                                  |
|--------------|--------------------------------------------------------------|
| `frontend`   | User interface and client-side code                           |
| `backend`    | Server-side API routes and business logic                     |
| `auth`       | Authentication and authorization mechanisms                   |
| `ai`         | AI service integration and playlist analysis                  |
| `spotify-api`| Interactions with Spotify API                                 |
| `ui`         | UI components and styling                                     |
| `config`     | Configuration files and settings                              |
| `docs`       | Documentation files                                           |
| `ci`         | Continuous integration and deployment pipelines               |
| `tests`      | Test suites and test-related code                             |

---

## 🚨 Breaking Changes

For breaking changes, include a note after the commit body:

```bash
💥 feat(backend): drop support for legacy API

BREAKING CHANGE: This version is no longer compatible with v0 configs.
```

---

## ✅ Tips

- Use present tense: `add`, not `added`; `fix`, not `fixed`
- Keep messages under 100 characters if possible
- Be consistent with emoji and spacing

---

Happy committing! 🚀
