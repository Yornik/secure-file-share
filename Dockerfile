# The builder is the official Rust image on Alpine, pinned by digest as well
# as by tag for the same reason every action in the workflows is: a tag
# names a line of releases rather than one of them, and it moves. Renovate
# moves the tag and the digest in one pull request.
#
# Alpine, not Debian: the image's own toolchain is musl, so the binary is
# statically linked against musl by default and the final stage below can
# be scratch.
FROM rust:1.100-alpine@sha256:8d0e82abfdf9a38071e07cabc5afba4ddbe077631a80e4e742a760c38beadc33 AS build

# aws-lc-rs (the rustls provider reqwest pulls) builds with cmake; perl and
# make are its other prerequisites. ca-certificates because the URL importer
# makes outbound TLS connections and the final image copies this trust
# store. All of this stays in the builder.
RUN apk add --no-cache ca-certificates cmake make perl

WORKDIR /src

# Dependencies first: a dummy crate compiles them, so source edits do not
# invalidate the expensive dependency layer. An empty lib.rs plus a stub
# main.rs satisfies both targets the manifest declares.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
 && printf '' > src/lib.rs \
 && printf 'fn main() {}' > src/main.rs \
 && cargo build --release --locked \
 && rm -rf src

COPY . .

# Stamped into the OCI labels of the final image, so a running pod can be
# traced back to a release and a commit.
ARG VERSION=dev
ARG COMMIT=none
ENV SFS_BUILD_COMMIT=${COMMIT}

RUN cargo build --release --locked

FROM scratch

# Inbound traffic is plain HTTP behind a TLS-terminating proxy, but the URL
# importer makes outbound TLS connections of its own, so it needs a trust
# store. On scratch there is none, and the failure is an unhelpful
# "certificate signed by unknown authority" long after deploy.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

COPY --from=build /src/target/release/secure-file-share /secure-file-share

# A copy of the image is a copy of everything it redistributes. Whoever
# holds the image has no way back to this repository, so the licence comes
# along; /licenses is where a reader and a licence scanner look for it.
COPY LICENSE /licenses/LICENSE

# An ARG does not cross a FROM, so the two the build stage took are declared
# again here. Without this the labels below would not fail — they would
# expand to empty strings, which is worse.
ARG VERSION=dev
ARG COMMIT=none

# Without these a `docker inspect` on what is running says nothing about
# where it came from, and Renovate cannot find the release notes behind an
# image bump.
LABEL org.opencontainers.image.title="secure-file-share" \
      org.opencontainers.image.source="https://github.com/Yornik/secure-file-share" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}"

# Unprivileged, and nothing in the image is writable: every byte this
# service keeps lives in Postgres, which is the point of the whole design.
USER 65532:65532

# 8080 serves the public; 9090 is the metrics listener and nothing outside
# the cluster routes to it.
EXPOSE 8080 9090
ENV SFS_LISTEN_ADDR=0.0.0.0:8080 \
    SFS_METRICS_ADDR=0.0.0.0:9090

ENTRYPOINT ["/secure-file-share"]
