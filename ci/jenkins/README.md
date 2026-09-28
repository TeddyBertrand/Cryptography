# Jenkins bootstrap (JCasC)

Self-hosted Jenkins controller + a Rust-capable inbound agent, fully defined
as code (JCasC — Jenkins Configuration as Code) so there is no click-ops:
security, plugins, the agent node and the `cryptography-dev`/`cryptography-main`
pipeline jobs are all
baked into the controller image and re-applied on every boot. This mirrors
the checks of `.github/workflows/ci.yml` (see [Parity with GitHub
Actions](#parity-with-github-actions)). GitHub Actions stays the
authoritative CI on PRs; this is an optional self-hosted mirror.

## Parity with GitHub Actions

| Check | GitHub Actions (`ci.yml`) | Jenkins (`cryptography.Jenkinsfile`) |
|---|---|---|
| `cargo fmt --all -- --check` | `build-test-lint` / Format check | Format |
| `cargo clippy --workspace -- -D warnings` | `build-test-lint` / Clippy | Lint |
| Debug build | `build-test-lint` / Build (`cargo build`) | Build (`make re`, release) |
| `cargo test --workspace` | `build-test-lint` / Test | Test (`cargo nextest`, JUnit report) |
| `make re` in grading image | `epitest-dump` / Build (make re) | Epitech dump check |
| `test -x ./my_pgp && ./my_pgp -h` | `epitest-dump` / Delivery check | Delivery check + Epitech dump check |
| Functional suite in grading image | `epitest-dump` / Functional suite | Epitech dump check |
| `cargo test --release -- --include-ignored` | `epitest-dump` / Release suite | Epitech dump check |
| Coverage (`cargo llvm-cov`, 70% gate) | — | Coverage |
| Archive `my_pgp` artifact | — | Archive artifact |

Coverage and artifact archiving are Jenkins-only; everything else fails the
build on both sides.

## Prerequisites

- Docker with the Compose plugin (`docker compose version`).
- `python3` with PyYAML, for `tests/basic/validate-casc.sh` and the
  JSON parsing used by the other test scripts (`python3 -c "import yaml"`
  should succeed; install via your distro/venv if not — e.g. on Nix:
  `nix-shell -p python3Packages.pyyaml`).

## First-time setup

1. Copy the env template and choose an admin password:
   ```
   cp ci/jenkins/.env.example ci/jenkins/.env
   ```
   Edit `JENKINS_ADMIN_PASSWORD` (and optionally `JENKINS_ADMIN_ID`,
   `JENKINS_ADMIN_EMAIL`) and `DOCKER_GID` in `ci/jenkins/.env`.

2. Bring the controller up. JCasC applies automatically — no setup wizard,
   no manual node/job creation:
   ```
   docker compose -f ci/jenkins/docker-compose.yml up -d --build --wait jenkins
   ```

3. (Optional) Confirm it booted clean:
   ```
   sh ci/jenkins/tests/basic/boot-health.sh
   sh ci/jenkins/tests/basic/plugins-installed.sh
   ```

4. Fetch the rust-agent's JNLP secret. Jenkins computes this per-node
   internally, so JCasC can't pre-set it — this is the one step that can't
   be eliminated, but it's fully scripted:
   ```
   sh ci/jenkins/scripts/fetch-agent-secret.sh
   ```

5. Start the agent:
   ```
   docker compose -f ci/jenkins/docker-compose.yml up -d rust-agent
   ```

## Verify the agent is online

- **Manage Jenkins > Nodes** should show `rust-agent` online (no red X), or
- `docker logs jenkins-rust-agent` should show a "Connected" message.

## GitHub webhook trigger and commit status

This controller runs locally, so GitHub can't reach it directly. A
`smee-client` service forwards a public smee.io channel's webhook deliveries
to `http://jenkins:8080/github-webhook/` inside the compose network, and the
`cryptography-dev`/`cryptography-main` jobs are configured (via JCasC) with
a `githubPush` trigger and post their result back to GitHub as the
`continuous-integration/jenkins` commit status.

Two manual, one-time steps (external services, can't be scripted from here):

1. **Create a smee.io channel:** visit https://smee.io/new, copy the
   generated URL into `ci/jenkins/.env` as `WEBHOOK_PROXY_URL`. Then, in the
   repo's GitHub settings (**Settings > Webhooks > Add webhook**), set the
   payload URL to that *same* smee.io URL, content type
   `application/json`, event `Just the push event`.
2. **Create a GitHub PAT** with `repo:status` scope
   (https://github.com/settings/tokens), put it in `ci/jenkins/.env` as
   `GITHUB_TOKEN`. This is consumed by the `github-status-token` Jenkins
   credential (`casc/projects/cryptography/credentials.yaml`).

Then start the forwarder:
```
docker compose -f ci/jenkins/docker-compose.yml up -d smee-client
```

**Verify:** open a PR against `dev` or push to `main` — a build should start
within a minute (`docker logs jenkins-smee-client` shows a forwarded
delivery), and the PR should show a `continuous-integration/jenkins` status
check reflecting the build result.

**Optional:** make that check a required status check under **Settings >
Branches > Branch protection rules** — a GitHub repo setting, not something
this config can set.

## Coverage and build artifact

The `cryptography.Jenkinsfile` pipeline runs `cargo llvm-cov` (installed in
the agent image, a tool not a crate dependency) to produce a Cobertura
report, published via the Coverage plugin's `recordCoverage` step. The build
turns unstable if line coverage drops below 70%. The `my_pgp` binary is then
archived with `archiveArtifacts` and downloadable from each build's page.
## Epitech dump check

Both `.github/workflows/ci.yml` (`epitest-dump` job) and the
`cryptography.Jenkinsfile` (`Epitech dump check` stage) rebuild and run the
functional suite inside `epitechcontent/epitest-docker`, the actual grading
environment, catching toolchain drift (Fedora, `make`) that the Nix/rust-agent
checks wouldn't see. The Jenkins stage runs in a `docker { image ... }`
agent (`docker-workflow` plugin) on the same `rust-agent` node
(`reuseNode true`). `rust-agent` ships the Docker CLI and talks to the host
daemon through the mounted `/var/run/docker.sock`; set `DOCKER_GID` in
`ci/jenkins/.env` to the host's docker group id
(`getent group docker | cut -d: -f3`) so the `jenkins` user can use it. The
agent workspace lives in the `rust_agent_workspace` volume so docker-workflow
can share it with the grading container via `--volumes-from`.

## Nightly benchmarks and stress tests

`cryptography-nightly` runs `ci/jenkins/jenkinsfiles/cryptography-nightly.Jenkinsfile`
on `dev` every night (cron `H 3 * * *`, set in `seed-job.yaml`), work too
slow for every push:

- **Benchmark:** `cargo run --release --bin bench 10` (see `bench/`), whose
  CSV is archived as `target/bench/bench.csv` on each build.
- **Plot:** the per-benchmark medians are split by unit (MB/s, ops/s, ms)
  and drawn by the Plot plugin (`plot` in `plugins.txt`). The trend graphs
  are on the job page under **Plots**, group *Benchmarks*; their history
  lives in the job directory, so it outlives the 30 kept builds.
- **Stress tests:** `cargo test --workspace --release -- --include-ignored`,
  the release suite including the ignored `bigint`/`prime` timing checks.

Benchmarks run on the shared `rust-agent`, so numbers drift with whatever
else the host is doing — read the trend, not single points. To run it
without waiting for the night: **cryptography-nightly > Build Now**.

## Running the tests

Two tiers, under `ci/jenkins/tests/`:

- **Basic** (`tests/basic/`): the JCasC yaml is well-formed, the controller
  boots healthy with no CasC load errors, and the configured security realm
  and plugin set are actually live.
- **Project** (`tests/project/`): the `cryptography-dev`,
  `cryptography-main` and `cryptography-nightly` seed jobs exist and are
  buildable, the nightly one has its cron trigger, every Jenkinsfile passes
  Jenkins' built-in Declarative Pipeline validator, the dev/main
  jobs have a `githubPush` trigger configured, and the
  `github-status-token` credential is present. A real end-to-end webhook
  delivery and status check can't be scripted here (needs a live smee.io
  channel and a real GitHub push) — verify that manually per the webhook
  section above.

Run everything hermetically (brings the stack up, tests it, tears it down):
```
sh ci/jenkins/tests/run-all.sh
```

## Adding a new project

Config is split into a generic `casc/core/` layer (security, plugins, tool
config — reusable as-is) and a per-project overlay under `casc/projects/`.
JCasC merges every yaml file found under the config directory, so a new
project needs no changes to `core/`:

1. `cp -r ci/jenkins/casc/projects/cryptography ci/jenkins/casc/projects/<name>`
2. Edit the copy's `agent.yaml` (node name/label) and `seed-job.yaml`
   (repo URL, branch, Jenkinsfile path). Add a `credentials.yaml` next to it
   only if the repo isn't publicly clonable — give it its own domain name
   (not `"_"`), since JCasC concatenates `domainCredentials` lists across
   files rather than merging them by domain name; a second `"_"` entry
   collides with `core/credentials.yaml`'s and silently drops credentials.
3. Add a matching `<name>.Jenkinsfile` under `ci/jenkins/jenkinsfiles/`.
4. Rebuild the controller image — the new overlay is picked up automatically
   since `controller.Dockerfile` copies all of `casc/`.

Keep each core file owning one disjoint top-level JCasC section (security,
system, tools, credentials, unclassified) and let overlays only *add* list
items (a node, a job, a credential) — this avoids merge collisions between
files.

## Teardown

```
docker compose -f ci/jenkins/docker-compose.yml down
```

Add `-v` to also wipe the persistent `jenkins_home` volume (build history,
workspaces, plugin cache — not config, which is always re-read from the
image on every boot).

## Secrets

`ci/jenkins/.env` is git-ignored (see repo-root `.gitignore`) and must never
be committed. `.env.example` is the only tracked template — always fill in
real values in your own local `.env`.
