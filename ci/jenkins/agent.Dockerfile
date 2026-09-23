# Pinned by digest: jenkins/inbound-agent:latest-jdk21 resolved at authoring
# time (tag itself is not stable across rebuilds upstream).
FROM jenkins/inbound-agent@sha256:6a31d728c22ad74adbb6b9a1a210eb9ec2599f644b95edd7f8a3b8a71d20772c

USER root

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        build-essential \
        make \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

USER jenkins

ENV RUSTUP_HOME=/home/jenkins/.rustup \
    CARGO_HOME=/home/jenkins/.cargo \
    PATH=/home/jenkins/.cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --default-toolchain stable --profile default \
    && rustup component add rustfmt clippy \
    && rustc --version && cargo --version
