# Native source build. Buildx can build this for either amd64 or arm64.
FROM rust:1.97.1-bookworm AS build
WORKDIR /src
COPY . .
ARG TAILCAT_VERSION=dev
ENV TAILCAT_VERSION=$TAILCAT_VERSION
RUN cargo build --locked --release --bin tailcat

FROM debian:bookworm-slim
LABEL org.opencontainers.image.source="https://github.com/spullara/tailcat-rs"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 65532 tailcat
COPY --from=build /src/target/release/tailcat /usr/local/bin/tailcat
COPY LICENSE THIRD_PARTY_NOTICES.md /usr/share/doc/tailcat/
COPY third_party/boringtun/LICENSE /usr/share/doc/tailcat/boringtun/LICENSE
USER 65532:65532
ENV HOME=/home/tailcat
WORKDIR /home/tailcat
ENTRYPOINT ["/usr/local/bin/tailcat"]
