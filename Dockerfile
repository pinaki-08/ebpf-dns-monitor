# syntax=docker/dockerfile:1

# --- build stage: compile the eBPF object + static Go binary ----------------
FROM golang:1.22-bookworm AS build

# bpf2go needs clang (compiles bpf/dns.bpf.c) and llvm (provides llvm-strip).
# clang with -target bpf doesn't add Debian's multiarch include path, so symlink
# asm/ where <linux/types.h> expects it (fixes "asm/types.h file not found").
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang llvm libbpf-dev linux-libc-dev \
    && ln -sf "/usr/include/$(uname -m)-linux-gnu/asm" /usr/include/asm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# CGO off -> fully static binary (the eBPF library is pure Go, no libbpf at runtime).
# -mod=mod lets the build resolve modules even if go.sum wasn't committed yet.
ENV CGO_ENABLED=0 GOFLAGS=-mod=mod
RUN go mod download
RUN go generate ./...
RUN go build -trimpath -ldflags="-s -w" -o /out/dnsmon .

# --- runtime stage: minimal static image (runs privileged in-cluster) -------
FROM gcr.io/distroless/static-debian12
COPY --from=build /out/dnsmon /usr/local/bin/dnsmon
ENTRYPOINT ["/usr/local/bin/dnsmon"]
