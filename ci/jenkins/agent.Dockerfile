# Pinned by digest: jenkins/inbound-agent:latest-jdk21 resolved at authoring
# time (tag itself is not stable across rebuilds upstream).
FROM jenkins/inbound-agent@sha256:6a31d728c22ad74adbb6b9a1a210eb9ec2599f644b95edd7f8a3b8a71d20772c

USER root

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        build-essential \
        make \
        pkg-config \
        docker-cli \
    && rm -rf /var/lib/apt/lists/*

USER jenkins

ENV RUSTUP_HOME=/home/jenkins/.rustup \
    CARGO_HOME=/home/jenkins/.cargo \
    PATH=/home/jenkins/.cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --default-toolchain stable --profile default \
    && rustup component add rustfmt clippy llvm-tools-preview \
    && rustc --version && cargo --version

# cargo-nextest: runs on stable and writes JUnit XML natively (unlike
# `cargo test`'s own JSON output, which needs a nightly-only `-Z` flag).
RUN curl -LsSf https://get.nexte.st/latest/linux | tar zxf - -C "${CARGO_HOME}/bin" \
    && cargo nextest --version

# cargo-llvm-cov: a tool, not a workspace crate dependency. Uses the
# llvm-tools-preview component installed above to instrument coverage.
RUN curl -LsSf https://github.com/taiki-e/cargo-llvm-cov/releases/latest/download/cargo-llvm-cov-x86_64-unknown-linux-gnu.tar.gz | \
        tar xzf - -C "${CARGO_HOME}/bin" \
    && cargo llvm-cov --version
