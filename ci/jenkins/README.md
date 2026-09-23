# Jenkins bootstrap

Self-hosted Jenkins controller + a Rust-capable inbound agent, so this
workspace's build/test/lint checks can also run on self-hosted CI. The
agent reproduces the same commands as `.github/workflows/ci.yml`:
`cargo fmt --all -- --check`, `cargo build --workspace`,
`cargo test --workspace`, `cargo clippy --workspace -- -D warnings`.

## Prerequisites

Docker with the Compose plugin (`docker compose version`).

## First-time setup

1. Copy the env template:
   ```
   cp ci/jenkins/.env.example ci/jenkins/.env
   ```
2. Start the controller alone first (the agent secret doesn't exist yet):
   ```
   docker compose -f ci/jenkins/docker-compose.yml up -d jenkins
   ```
3. Read the initial admin password:
   ```
   docker exec jenkins-controller cat /var/jenkins_home/secrets/initialAdminPassword
   ```
4. Open `http://localhost:8080` and complete the setup wizard.
5. Create the agent node: **Manage Jenkins > Nodes > New Node**, name it
   `rust-agent`, type "Permanent Agent", launch method "Launch agent via
   inbound (Java Web Start/TCP)". Save, then open the node page and copy its
   `-secret` value.
6. Put that secret into `ci/jenkins/.env` as `JENKINS_AGENT_SECRET`.

## Start everything

```
docker compose -f ci/jenkins/docker-compose.yml up -d
```

Starts (and rebuilds, if needed) both the controller and the Rust agent.

## Verify the agent is online

- **Manage Jenkins > Nodes** should show `rust-agent` online (no red X), or
- `docker logs jenkins-rust-agent` should show a "Connected" message.

## Verify `cargo --version` works

Create a Freestyle job restricted to the `rust-agent` node/label with a
single "Execute shell" build step:

```
cargo --version && rustc --version
```

Run it and confirm the console output prints real version strings and the
build succeeds.

## Teardown

```
docker compose -f ci/jenkins/docker-compose.yml down
```

Add `-v` to also wipe the persistent `jenkins_home` volume.

## Secrets

`ci/jenkins/.env` is git-ignored (see repo-root `.gitignore`) and must never
be committed. `.env.example` is the only tracked template — always fill in
real values in your own local `.env`.
