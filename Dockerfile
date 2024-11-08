FROM golang:1.23.1 AS builder

# Install cli tools for building and final image
RUN apt-get update && apt-get install --no-install-recommends -y make=4.3-4.1 git=1:2.39.5-0+deb12u1 bash=5.2.15-2+b7 gcc=4:12.2.0-3 curl=7.88.1-10+deb12u7 jq=1.6-2.1 && rm -rf /var/lib/apt/lists/*

# Build
WORKDIR /go/src/github.com/babylonlabs-io/btc-staker
# Cache dependencies
COPY go.mod go.sum /go/src/github.com/babylonlabs-io/btc-staker/
RUN go mod download

# Copy the rest of the files
COPY ./ /go/src/github.com/babylonlabs-io/btc-staker/

RUN BUILD_TAGS=netgo \
    LDFLAGS="-w -s" \
    make build

# FINAL IMAGE
FROM debian:bookworm-slim AS run
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN addgroup --gid 1138 --system btcstaker && adduser --uid 1138 --system --home /home/btcstaker btcstaker
RUN apt-get update && apt-get install --no-install-recommends -y bash=5.2.15-2+b7 curl=7.88.1-10+deb12u7 jq=1.6-2.1 wget=1.21.3-1+b2 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /go/src/github.com/babylonlabs-io/btc-staker/go.mod /tmp
RUN WASMVM_VERSION=$(grep github.com/CosmWasm/wasmvm /tmp/go.mod | cut -d' ' -f2) && \
    wget -nv https://github.com/CosmWasm/wasmvm/releases/download/"$WASMVM_VERSION"/libwasmvm."$(uname -m)".so \
    -O /lib/libwasmvm."$(uname -m)".so && \
    # verify checksum
    wget -nv https://github.com/CosmWasm/wasmvm/releases/download/"$WASMVM_VERSION"/checksums.txt -O /tmp/checksums.txt && \
    sha256sum /lib/libwasmvm."$(uname -m)".so | grep "$(cat /tmp/checksums.txt | grep libwasmvm."$(uname -m)" | cut -d ' ' -f 1)"
RUN rm -f /tmp/go.mod

COPY --from=builder /go/src/github.com/babylonlabs-io/btc-staker/build/stakerd /bin/stakerd
COPY --from=builder /go/src/github.com/babylonlabs-io/btc-staker/build/stakercli /bin/stakercli

WORKDIR /home/btcstaker
RUN chown -R btcstaker /home/btcstaker
USER btcstaker

ENTRYPOINT ["/bin/stakerd"]
CMD []
STOPSIGNAL SIGTERM
