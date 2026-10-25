# Agent Instructions

Persistent repository instructions, not a changelog or task journal.

## Working Rules

- Inspect relevant implementations, call sites, utilities, and tests before
  editing. Prefer codebase-memory MCP graph tools for code discovery; fall back
  to file searches when results are insufficient or for non-code content.
- Check Git status and preserve unrelated changes. Keep fixes focused; follow
  existing Rust conventions and reuse existing utilities before adding
  abstractions or dependencies.
- Do not change public APIs, CLI behavior, or encrypted-file contracts without
  an explicit requirement. Avoid checks for conditions already guaranteed by the
  system.
- Delegate only independent work when it materially improves implementation or
  review; keep file ownership explicit and do not allow nested delegation.

## Repository Constraints

- `src/cli.rs` owns clap parsing and hidden passphrase prompts;
  `src/application.rs` orchestrates streaming; `src/io.rs` owns transactional
  output. Keep cryptographic methods under `src/crypto/algorithms`, registered
  through `src/crypto/registry.rs`.
- Preserve legacy decryption and versioned header compatibility in
  `src/file_format.rs`. Keep header authentication and algorithm dispatch
  covered by `tests/compatibility.rs`.
- Never publish plaintext before authentication succeeds, including stdout.
  Preserve existing destinations on failure, bounded-memory streaming,
  private-key permissions, and explicit authorization for key replacement. Do
  not accept passphrases as CLI arguments.

## Verification and Documentation

- Follow setup and validation commands in [README.md](README.md#development).
  Run checks relevant to the change; put unit tests beside modules and
  integration coverage in `tests/compatibility.rs`.
- Keep README focused on description, setup, installation, usage, development,
  and license. Use dedicated documentation for architectural decisions and Git
  history or CHANGELOG.md for historical changes. Do not create progress reports
  unless requested.
- Do not modify `AGENTS.md` as a side effect of development; edit it only when
  explicitly requested. Keep `CLAUDE.md` as a symlink to this file. Never append
  task summaries, changelogs, or session notes.
- Use Traditional Chinese for explanations and English for code identifiers and
  comments. Keep final responses concise: describe changes, checks actually
  executed, and unresolved limitations. Never claim an unexecuted check passed.
