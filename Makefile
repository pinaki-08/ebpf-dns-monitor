# dnsmon — passive eBPF DNS monitor
#
# Run these targets *inside the Linux VM* (see lima.yaml). eBPF needs a Linux
# kernel; nothing here builds on macOS directly.

IFACE ?= $(shell ip route 2>/dev/null | awk '/default/ {print $$5; exit}')
METRICS_ADDR ?= :2112

.PHONY: deps generate build run clean

# One-time system dependencies (Debian/Ubuntu).
deps:
	sudo apt-get update
	sudo apt-get install -y clang llvm libbpf-dev linux-tools-generic build-essential
	# clang -target bpf needs asm/ on the default include path.
	sudo ln -sf "/usr/include/$$(uname -m)-linux-gnu/asm" /usr/include/asm

# Compile the eBPF C and generate Go bindings.
generate:
	go generate ./...

build: generate
	mkdir -p bin
	go build -o bin/dnsmon .

# Requires root (loading BPF + attaching to tc).
run: build
	sudo ./bin/dnsmon -iface $(IFACE) -metrics-addr $(METRICS_ADDR) -v

clean:
	rm -rf bin
	rm -f dnsmon_bpfel.go dnsmon_bpfel.o

# --- Docker + kind ----------------------------------------------------------
# These build and test the containerised DaemonSet. The image build also
# compiles the eBPF object, so clang/Go are not needed on the host.

IMG ?= dnsmon:dev
KIND_CLUSTER ?= dnsmon

.PHONY: docker-build kind-up kind-load deploy logs kind-down

docker-build:
	docker build -t $(IMG) .

kind-up:
	kind create cluster --name $(KIND_CLUSTER) --config deploy/kind-config.yaml

kind-load: docker-build
	kind load docker-image $(IMG) --name $(KIND_CLUSTER)

deploy: kind-load
	kubectl apply -f deploy/daemonset.yaml
	kubectl -n dnsmon rollout status ds/dnsmon --timeout=90s

logs:
	kubectl -n dnsmon logs -l app=dnsmon -f --prefix

kind-down:
	kind delete cluster --name $(KIND_CLUSTER)
