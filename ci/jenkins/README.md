# Jenkins bootstrap (JCasC)

Self-hosted Jenkins controller + a Rust-capable inbound agent, fully defined
as code (JCasC — Jenkins Configuration as Code) so there is no click-ops:
security, plugins, the agent node and the `cryptography` pipeline job are all
baked into the controller image and re-applied on every boot. This mirrors
the same checks as `.github/workflows/ci.yml`: `cargo fmt --all -- --check`,
`cargo build --workspace`, `cargo test --workspace`,
`cargo clippy --workspace -- -D warnings`. GitHub Actions stays the
authoritative CI on PRs; this is an optional self-hosted mirror.

## Prerequisites

Docker with the Compose plugin (`docker compose version`).

## First-time setup

1. Copy the env template and choose an admin password:
   ```
   cp ci/jenkins/.env.example ci/jenkins/.env
   ```
   Edit `JENKINS_ADMIN_PASSWORD` (and optionally `JENKINS_ADMIN_ID`,
   `JENKINS_ADMIN_EMAIL`) in `ci/jenkins/.env`.

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

## Running the tests

Two tiers, under `ci/jenkins/tests/`:

- **Basic** (`tests/basic/`): the JCasC yaml is well-formed, the controller
  boots healthy with no CasC load errors, and the configured security realm
  and plugin set are actually live.
- **Project** (`tests/project/`): the `cryptography` seed job exists and is
  buildable, and its Jenkinsfile passes Jenkins' built-in Declarative
  Pipeline validator.

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
   only if the repo isn't publicly clonable.
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
