# Contributing

This repo mirrors an upstream project you don't control directly (an external/academic
repo). Content arrives here via an automated sync from a separate mirror repo -- see
that mirror repo's `.github/workflows/sync-to-org.yml` for how it gets pushed to `main`.
The scaffolding below (labels, project board, templates) lives only in this org repo,
not upstream.

## Issues

- Title: `[Scope] Imperative summary` — scope is a functional module/domain, not `[BUG]`/`[FEAT]`.
  Category (bug/feature/chore) goes in labels, never the title.
- Labels: reuse existing ones first (`gh label list`). Type + scope labels only —
  scope labels are applied automatically by the `auto-scope-label` workflow from the
  title's `[Scope]` prefix, no manual creation needed.
- Priority is a **Project field**, not a label. Check `gh project field-list <number> --owner <owner>`
  for a `Priority` single-select field and set it there. Only fall back to a `priority:*` label
  if no project exists.

## Branches & commits

- Branch naming: `type/slug` (`feat`, `fix`, `refacto`, `docs`, `chore`, `test`, `setup`).
- Commit format: `type(scope): description`.
- **No `Co-authored-by` trailers, ever** — enforced by the `reject-co-author` CI check on
  every PR. If a commit already has one, rewrite history before opening the PR.

## Pull requests

- Fill the PR template's `Closes #` field — pairs with the `project-status` workflow, which
  parses `closes|fixes|resolves #N` from the PR body to move the linked issue's board status.

## Verifying the DevOps wiring itself

If you change anything under `.github/workflows/project-status.yml`, `auto-scope-label.yml`,
or the board-setup logic in `dev-templates`, see `dev-templates/docs/SMOKE_TEST.md` to verify
end-to-end against a disposable repo — this repo's own CI can't exercise those workflows in place.
