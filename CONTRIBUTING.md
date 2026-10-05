# Contributing

## Setup

If this project has a `flake.nix` (you opted into Nix when bootstrapping):

```
nix develop
pre-commit install --hook-type commit-msg --hook-type pre-commit
```

Otherwise, install `rustc`/`cargo`/`rustfmt`/`clippy` (e.g. via `rustup`) and `pre-commit`
yourself, then:

```
pre-commit install --hook-type commit-msg --hook-type pre-commit
```

## Code layout

The code is a Cargo workspace: one crate per building block, wired into the binary by
`crates/my_pgp`. The [project guide](docs/guide/README.md#architecture) has the crate table
and dependency graph. A new flag is one more `Arg` in `crates/cli/src/spec.rs`. A new
cryptosystem is a new crate implementing `core::Cipher`, dispatched from
`crates/my_pgp/src/main.rs`.

## Tests

```
cargo test --workspace                                       # everything (make tests_run does the same)
cargo test -p rsa                                            # one crate
cargo test -p rsa matches_subject_ciphertext_for_wf          # one test
cargo test --workspace --release -- --include-ignored        # adds the bigint and prime timing checks
```

- **Unit tests** live next to the code, in a `#[cfg(test)] mod tests` in each crate.
- **Functional tests** run the real binary. Each file in `crates/my_pgp/tests/cases/` has `== ARGS ==`, `== STDIN ==`, `== STDOUT ==`, `== STDERR ==` and `== EXIT ==` sections, so a new CLI case is a new `.txt` file with no Rust. `== THEN ==` pipes the output into a second run, and `== SKIP ==` disables a case with a reason. Run them alone with `cargo test -p my_pgp --test functional`.
- **Property tests** in `crates/my_pgp/tests/roundtrip/` check 1000 random round trips per system, or `PROPERTY_CASES=N`. A failure prints its seed and case count; replay it with `PROPERTY_SEED=0x... PROPERTY_CASES=N cargo test -p my_pgp --test roundtrip`.
- **Subject examples**: `sh tests/xor_pdf.sh` and `sh tests/pgp_aes_pdf.sh` replay the PDF's examples.

Before pushing, run the same lint and format checks as CI:

```
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Benchmarks and constant time

```
cargo run --release --bin bench [samples]   # default: 5 samples
cargo run --release --bin timing
```

`bench` prints one CSV row per measurement, with its median, minimum and maximum: XOR and AES-128/192/256 throughput on 1 MiB, RSA 1024- and 2048-bit operations, and 512- and 1024-bit prime generation.

RSA with the private exponent, AES and X25519 run in constant time with respect to their secrets. `timing` checks it: for each primitive, it times a fixed secret against random secrets and runs a Welch t-test (`|t| > 4.5` means a leak). Re-run it after touching secret-dependent code. [docs/constant-time-audit.md](docs/constant-time-audit.md) covers the audit and the leaks that remain.

## Continuous integration

**GitHub Actions** (`.github/workflows/ci.yml`) is the authoritative CI on pull requests:

- `build-test-lint`: format check, build, `cargo test --workspace` and Clippy.
- `retrocompat`: the functional suite, so every subject example keeps working.
- `delivery`: the delivery tree check (see [README § Delivery](README.md#delivery)).
- `epitest-dump`: `make re` in the Epitech grading image, a check that `./my_pgp -h` runs, then the full and release test suites.

**Jenkins** (`ci/jenkins/`) is an optional self-hosted mirror, defined entirely as code (Docker Compose and JCasC). The `cryptography-dev` and `cryptography-main` jobs run the same checks, plus line coverage with a 70% gate and an archived `my_pgp` binary. The `cryptography-nightly` job runs the benchmarks, plots them build over build, and runs the release suite. Every build posts a report to Discord. To start it locally:

```
cp ci/jenkins/.env.example ci/jenkins/.env   # set JENKINS_ADMIN_PASSWORD and DOCKER_GID
docker compose -f ci/jenkins/docker-compose.yml up -d --build --wait jenkins
sh ci/jenkins/scripts/fetch-agent-secret.sh
docker compose -f ci/jenkins/docker-compose.yml up -d rust-agent
```

[ci/jenkins/README.md](ci/jenkins/README.md) covers the GitHub webhook, commit statuses, notifications and the Jenkins test scripts.

## Issues

- Title: `[Scope] Imperative summary` — scope is a functional module/domain, not `[BUG]`/`[FEAT]`.
  Category (bug/feature/chore) goes in labels, never the title.
- Labels: reuse existing ones first (`gh label list`). Type + scope labels only —
  scope labels are applied automatically by the `auto-scope-label` workflow from the
  title's `[Scope]` prefix, no manual creation needed.
- Priority is a **Project field**, not a label. Check `gh project field-list <number> --owner <owner>`
  for a `Priority` single-select field and set it there. Only fall back to a `priority:*` label
  if no project exists.

## License

Chosen at bootstrap time (or fetched fresh via `gh api licenses/:key` and dropped into
`LICENSE`, or `LICENSE-MIT`/`LICENSE-APACHE` for the MIT OR Apache-2.0 dual-license default).
To change it later, either edit the file directly or re-fetch a different one the same way.

## Branches & commits

- Branch naming: `type/slug` (`feat`, `fix`, `refacto`, `docs`, `chore`, `test`, `setup`).
- Commit format: `type(scope): description`.
- **No `Co-authored-by` trailers, ever** — enforced locally by the `reject-co-authored-by`
  pre-commit hook (bypassable with `--no-verify`) and by the `reject-co-author` CI check on
  every PR (not bypassable). If a commit already has one, rewrite history before opening the PR.

## Pull requests

- Fill the PR template's `Closes #` field — pairs with the `project-status` workflow, which
  parses `closes|fixes|resolves #N` from the PR body to move the linked issue's board status.

## Verifying the DevOps wiring itself

If you change anything under `.github/workflows/project-status.yml`, `auto-scope-label.yml`,
or the board-setup logic in `dev-templates`, see `dev-templates/docs/SMOKE_TEST.md` to verify
end-to-end against a disposable repo — this repo's own CI can't exercise those workflows in place.
