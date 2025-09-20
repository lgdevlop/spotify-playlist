# 📝 Commit Message Guidelines

This project is a Next.js web application focused on Spotify playlist management. These commit message guidelines are tailored to support clear, consistent, and automated version control practices aligned with this project's structure and workflows.

This document defines the official rules for writing commit messages in this repository, based on the [Conventional Commits](https://www.conventionalcommits.org/) specification, extended with emojis for readability and context.

## ✅ Format

```text
<emoji> <type>(<scope>): short and meaningful summary
```

### Example

```text
✨ feat(cli): add preview command for Spotify playlist
```

## 🧩 Commit Parts Explained

| Part         | Description                                                                 |
|--------------|-----------------------------------------------------------------------------|
| `<emoji>`    | Adds visual context to the type of change                                    |
| `<type>`     | Describes the category of change (see below)                                 |
| `<scope>`    | Optional: indicates the specific module, file, or concern affected          |
| `summary`    | Required: brief summary of what changed, written in the imperative mood     |

> Commit bodies and footers are allowed (for details, links, BREAKING CHANGES, etc.), but optional.

## 📖 Allowed Types and Emojis

| Type       | Emoji | Description                                |
|------------|--------|-------------------------------------------|
| `feat`     | ✨     | A new feature                             |
| `fix`      | 🐛     | A bug fix                                 |
| `docs`     | 📝     | Documentation only changes                |
| `style`    | 🎨     | Code style changes (formatting, no logic) |
| `refactor` | 🧼     | Code changes that neither fix nor add     |
| `perf`     | ⚡     | Performance improvements                  |
| `test`     | ✅     | Adding or updating tests                  |
| `build`    | 🛠️     | Build system or external deps             |
| `ci`       | 🤖     | CI/CD configuration or scripts            |
| `chore`    | 🔧     | Maintenance, tooling, or cleanup tasks    |
| `revert`   | ⏪     | Reverts a previous commit                 |

## ✍️ Best Practices

- Use **present tense**: `add`, not `added` or `adds`
- Use **imperative mood**: `fix bug`, not `fixes bug` or `fixed bug`
- Start the **summary with lowercase** unless using proper nouns
- Keep subject line under **100 characters**
- Use body section to explain **why**, not just **what**, if relevant

## 🔁 Relation to Branch and PR

- The `<type>` and `<scope>` should usually match the branch naming convention
- The commit message of a squash merge must match the PR title (see `merge-commit-guidelines.md`)
- Example alignment:

```text
Branch: feat/cli-autofill-preview
Commit: ✨ feat(cli): add preview command for PR autofill
PR:     ✨ feat(cli): add preview command for PR autofill
```

## 📚 Additional Resources

- [Conventional Commits](https://www.conventionalcommits.org/)
- [Gitmoji](https://gitmoji.dev/) (emoji reference)

> For merge commit rules, see: `project-docs/merge-commit-guidelines.md`
