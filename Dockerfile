FROM golang:1.24.13 AS builder

# Install cli tools for building and final image
RUN apt-get update && apt-get install -y --no-install-recommends make git bash gcc curl jq && rm -rf /var/lib/apt/lists/*

# Allow Go to download and use newer toolchain versions
ENV GOTOOLCHAIN=auto

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

RUN addgroup --gid 1138 --system btcstaker && adduser --uid 1138 --system --home /home/btcstaker btcstaker
RUN apt-get update && apt-get install -y --no-install-recommends bash curl jq wget ca-certificates && rm -rf /var/lib/apt/lists/*

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
COPY --from=builder /go/src/github.com/babylonlabs-io/btc-staker/go.mod /tmp
RUN WASMVM_VERSION=$(grep github.com/CosmWasm/wasmvm /tmp/go.mod | cut -d' ' -f2) && \
    wget -q "https://github.com/CosmWasm/wasmvm/releases/download/${WASMVM_VERSION}/libwasmvm.$(uname -m).so" \
    -O "/lib/libwasmvm.$(uname -m).so" && \
    # verify checksum
    wget -q "https://github.com/CosmWasm/wasmvm/releases/download/${WASMVM_VERSION}/checksums.txt" -O /tmp/checksums.txt && \
    sha256sum "/lib/libwasmvm.$(uname -m).so" | grep "$(grep "libwasmvm.$(uname -m)" /tmp/checksums.txt | cut -d ' ' -f 1)"
RUN rm -f /tmp/go.mod

COPY --from=builder /go/src/github.com/babylonlabs-io/btc-staker/build/stakerd /bin/stakerd
COPY --from=builder /go/src/github.com/babylonlabs-io/btc-staker/build/stakercli /bin/stakercli

WORKDIR /home/btcstaker
RUN chown -R btcstaker /home/btcstaker
USER btcstaker

ENTRYPOINT ["/bin/stakerd"]
CMD []
STOPSIGNAL SIGTERM
