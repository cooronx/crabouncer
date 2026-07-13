# AGENTS.md

## Project Guidelines

Keep implementations simple, maintainable, and appropriate for the current stage of the project.

Before making changes:

* Inspect the existing code and project structure.
* Follow existing naming, formatting, and architectural conventions.
* Prefer modifying existing abstractions over introducing unnecessary new ones.
* Avoid unrelated refactors while implementing a focused task.
* Do not modify generated files unless necessary.
* Do not introduce new dependencies without a clear reason.

After making changes:

* Review the final diff.
* Remove temporary logs, debug code, commented-out code, and unused imports.
* Run the relevant formatting, linting, build, and test commands.
* Clearly report any checks that could not be completed.

## Git Commit Guidelines

Use the Conventional Commits specification for all commit messages.

Commit messages must remain readable, consistent, and suitable for automatically generated changelogs.

### Commit Scope

Each commit must contain one logical category of change.

* Keep features, bug fixes, refactors, tests, and documentation changes in separate commits when practical.
* Do not mix unrelated changes in the same commit.
* Avoid including unrelated formatting changes or temporary debugging code.
* Each commit should build and remain in a usable state whenever possible.
* Split large changes into small, focused, and independently reviewable commits.
* Stage only the files related to the current commit.

Before creating a commit, review:

```bash
git status
git diff
git diff --staged
```

Do not create commits unless explicitly requested.

Do not amend, squash, rebase, reset, force-push, or rewrite Git history unless explicitly requested.

### Commit Message Format

Use the following format:

```text
<type>[(scope)]: <summary>

[body]

[footer]
```

Examples:

```text
feat(auth): add authorization code flow
```

```text
fix(token): reject expired refresh tokens
```

```text
docs: document local development setup
```

```text
refactor(policy): simplify Cedar evaluation context
```

### Commit Types

Use one of the following commit types:

| Type       | Purpose                                                   |
| ---------- | --------------------------------------------------------- |
| `init`     | Initial project setup                                     |
| `feat`     | New functionality                                         |
| `fix`      | Bug fix                                                   |
| `docs`     | Documentation changes                                     |
| `style`    | Formatting changes that do not affect behavior            |
| `refactor` | Code changes that neither add functionality nor fix a bug |
| `perf`     | Performance improvements                                  |
| `test`     | Adding or updating tests                                  |
| `build`    | Build system or dependency changes                        |
| `ci`       | Continuous integration configuration                      |
| `chore`    | Maintenance tasks and tooling changes                     |
| `revert`   | Reverting a previous commit                               |

Use additional types only when there is a clear reason.

### Scope

Use a short scope when the affected module or component is clear.

Prefer scopes based on project modules, crates, packages, or directories.

Examples:

```text
feat(auth): add GitHub OAuth callback
fix(oidc): validate redirect URI
refactor(policy): extract Cedar authorization service
test(token): add access token expiration tests
build(core): update sqlx dependency
```

Omit the scope when the change affects the entire project or has no clear module boundary.

Example:

```text
docs: update contribution guidelines
```

### Summary

The commit summary must:

* Be written in English.
* Start with a lowercase imperative verb.
* Describe what the commit does.
* Be concise and specific.
* Preferably remain within 72 characters.
* Not end with a period.

Good examples:

```text
feat(auth): add password login endpoint
fix(oidc): validate authorization code expiration
refactor(db): extract transaction helper
docs: explain local development workflow
```

Avoid vague summaries:

```text
fix: fix bug
chore: update things
feat: add changes
```

### Commit Body

Add a body when the reason, behavior, impact, or migration process is not obvious.

Explain:

* Why the change is necessary.
* What behavior changed.
* Any important design decisions.
* Any compatibility or migration concerns.

Wrap body lines at approximately 72 characters when practical.

Example:

```text
refactor(auth): separate token issuance from login

Move token generation into a dedicated service so that password,
OAuth, and future authentication methods can share the same logic.
```

### Breaking Changes

Mark breaking changes by adding `!` after the type or scope:

```text
feat(api)!: replace legacy authorization endpoint
```

Alternatively, add a footer:

```text
BREAKING CHANGE: clients must use `/oauth/authorize` instead of
`/authorize`.
```

Clearly describe:

* What behavior changed.
* Which users, APIs, or modules are affected.
* How existing integrations should migrate.

### Commit Workflow

Before committing:

1. Check the working tree:

```bash
git status
```

2. Review the changes:

```bash
git diff
```

3. Run relevant project checks.

For Rust changes:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

For Web changes, use the package manager already configured by the project:

```bash
pnpm lint
pnpm build
```

Do not assume `npm`, `pnpm`, or `yarn`; inspect the existing lockfile and project configuration first.

4. Stage only related files:

```bash
git add <files>
```

Avoid using the following command without first reviewing the complete working tree:

```bash
git add .
```

5. Review staged changes:

```bash
git diff --staged
```

6. Create the commit:

```bash
git commit -m "feat(auth): add password login endpoint"
```

For commits that require additional context:

```bash
git commit
```

Then include a body and footer as needed.

## Rust Guidelines

* Follow standard Rust naming conventions.
* Keep modules focused and avoid unnecessary abstractions.
* Prefer explicit error handling over `unwrap()` and `expect()` in production code.
* Use existing project error types when available.
* Keep public APIs minimal.
* Add or update tests when behavior changes.
* Run `cargo fmt` after modifying Rust code.

## Frontend Guidelines

* Use TypeScript for new frontend code.
* Follow the existing component and directory structure.
* Reuse existing components before creating new abstractions.
* Avoid using `any` unless there is a documented reason.
* Keep components focused and move reusable logic into appropriate hooks or modules.
* Use the package manager already configured by the repository.

## Documentation

Update documentation when changing:

* Public APIs.
* Configuration.
* Environment variables.
* Development commands.
* Authentication or authorization behavior.
* Database migration requirements.

Keep examples synchronized with the actual implementation.
