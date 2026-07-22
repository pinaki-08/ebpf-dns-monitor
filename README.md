# dnsmon

A passive **eBPF DNS monitor** — full DNS visibility without a userspace proxy.

It attaches a passive `cgroup/skb` program at the node's root cgroup, copies DNS
packets into a ring buffer, decodes them in Go userspace, and exposes Prometheus
metrics. One attach point sees DNS for every process on the node — pod↔CoreDNS on
the CNI veths, node-local lookups on `lo`, and egress to external resolvers —
regardless of interface.

## Why this exists

Most DNS-aware network-policy systems do **not** parse DNS in eBPF. To enforce
domain-based rules (e.g. "allow `api.github.com`") they redirect port-53 traffic
to a **userspace DNS proxy** that decodes the query and response, learns the
domain→IP mapping, updates policy, and forwards the packet:

| Layer | Component | Job |
| --- | --- | --- |
| Interception | eBPF datapath (tc + tproxy) | Redirect port-53 traffic to the proxy |
| DNS parsing / visibility / enforcement | **userspace DNS proxy** | Decode query + response, learn domain→IP, update policy, forward |

That split exists because fully decoding DNS inside the eBPF verifier is hard
(compression pointers, EDNS0, TCP reassembly, bounded loops) — and to *block* a
lookup you have to sit inline anyway. The cost is that the proxy is in the data
path (an extra hop + latency) and only runs when policy/visibility is on.

**dnsmon takes the opposite trade-off.** It is observe-only, so it can be
passive:

- The **kernel** program only validates "this is DNS-over-UDP" and copies the raw
  bytes to a ring buffer. It returns `1` (pass) at the `cgroup/skb` hook and never
  touches the packet.
- **Userspace (Go)** does the hard part — name decompression — where loops and
  pointers are free.

Result: near-zero added latency, no proxy, not in the enforcement path. The
trade-off is that dnsmon *observes* but does not *block* (see Roadmap). This is
the same design space as Inspektor Gadget's `trace dns` and Pixie.

## Architecture

```mermaid
flowchart LR
    app[Any process on the node] -->|DNS query :53| hook["eBPF cgroup/skb program\n(egress + ingress: validate + copy raw DNS)"]
    hook -->|ring buffer| agent["Go agent\n(decode names, correlate, de-dup)"]
    agent --> prom["/metrics (Prometheus)"]
    agent --> logs[stderr logs]
    hook -.packet passes untouched.-> net[(veth / lo / eth0)]
```

## Requirements

- Linux kernel **>= 5.8** — ring buffer (5.8) and bpf_link-based `cgroup/skb`
  attach (5.7). BTF is **not** required (no CO-RE).
- A cgroup v2 unified hierarchy mounted at `/sys/fs/cgroup`.
- `clang`, `llvm`, `libbpf-dev`, Go **>= 1.22**.
- Root, or `CAP_BPF` + `CAP_NET_ADMIN` (to load BPF and attach to the cgroup).

On macOS, either use the bundled Lima VM (bare-host workflow) or the
[kind cluster workflow](#run-on-a-kind-cluster-docker) below — both run Linux
with a recent kernel.

## Quick start (macOS via Lima)

```bash
brew install lima            # if needed
limactl start --name=dnsmon ./lima.yaml
limactl shell dnsmon

cd /Users/$USER/ebpf-dns-monitor
go mod tidy                  # fetch deps, write go.sum
make run                     # generate + build + attach at /sys/fs/cgroup
```

In another shell, generate some traffic and scrape metrics:

```bash
limactl shell dnsmon -- bash -lc 'dig +short github.com; dig AAAA cloudflare.com'
curl -s localhost:2112/metrics | grep dnsmon_
```

Sample log output (`-v`):

```
QUERY  10.0.2.15:41234 -> 10.0.2.3:53 id=0x1a2b A     github.com
RESP   10.0.2.3:53 -> 10.0.2.15:41234 id=0x1a2b NOERROR  github.com [140.82.121.4] (12.34ms)
```

## Run on a kind cluster (Docker)

This is the natural way to exercise the DaemonSet path. Understand the trade-offs
first:

- **kind nodes share one kernel** (the Docker VM's), so this validates
  *packaging, privileges, and deployment* — not true multi-node kernels.
- **The pod is privileged** and mounts the node's `/sys/fs/cgroup`, so it can
  attach the `cgroup/skb` program at the node's root cgroup and observe DNS for
  every pod and host process on the node. (`hostNetwork` is kept only so the
  metrics endpoint lands on the node IP.)
- **Kernel must be >= 5.8** (ring buffer; `cgroup/skb` bpf_link needs 5.7). Check
  the Docker VM kernel: `docker run --rm alpine uname -r`. Recent Docker Desktop /
  Colima are fine.
- **BTF is *not* required** — the program does no CO-RE (no `vmlinux.h`,
  no `BPF_CORE_READ`), so the classic "Docker Desktop has no
  `/sys/kernel/btf/vmlinux`" problem does not apply. The image build also
  compiles the eBPF object, so you need neither clang nor Go on the host.

```bash
make kind-up        # create the cluster
make deploy         # build image -> load into kind -> apply the DaemonSet
make logs           # follow DNS events

# Generate DNS from a pod. Because dnsmon hooks the root cgroup, it now sees the
# pod->CoreDNS leg directly -- an ordinary in-cluster lookup is enough:
kubectl run dnsprobe --image=busybox --restart=Never -- sh -c "sleep 3600"
kubectl exec dnsprobe -- nslookup github.com

# Scrape metrics from a node:
POD=$(kubectl -n dnsmon get pod -l app=dnsmon -o name | head -1)
kubectl -n dnsmon port-forward "$POD" 2112:2112 &
curl -s localhost:2112/metrics | grep dnsmon_
```

The DaemonSet attaches the `cgroup/skb` program at the node's root cgroup, so a
single program sees **all** DNS on the node: pod↔CoreDNS on the CNI veths,
CoreDNS's own upstream forwards, and the node's `127.0.0.11` / external lookups.
Node-local traffic legitimately appears on both the sender's egress and the
receiver's ingress hook, so the agent de-dups on the DNS payload. Tear down with
`make kind-down`.

## Metrics

| Metric | Type | Labels |
| --- | --- | --- |
| `dnsmon_queries_total` | counter | `qtype` |
| `dnsmon_responses_total` | counter | `rcode` |
| `dnsmon_query_duration_seconds` | histogram | — |
| `dnsmon_events_total` | counter | — |
| `dnsmon_parse_errors_total` | counter | — |
| `dnsmon_queries_by_domain_total` | counter | `domain`, `qtype` (only with `-per-domain-metrics`) |

## Scraping with Prometheus

The DaemonSet pods carry `prometheus.io/scrape` annotations, so any Prometheus
using pod service-discovery picks them up automatically. A ready-to-apply
Prometheus (RBAC + scrape config + Deployment + Service) is included for the kind
setup:

```bash
kubectl apply -f deploy/prometheus.yaml
kubectl -n monitoring rollout status deploy/prometheus
kubectl -n monitoring port-forward svc/prometheus 9090:9090
# browse http://localhost:9090/graph?g0.expr=dnsmon_responses_total&g0.tab=0
```

Example — `dnsmon_responses_total` by `rcode`, scraped live from the kind cluster:

![Prometheus graph of dnsmon_responses_total by rcode](examples/prometheus-snapshot.png)

A raw text snapshot of the exposition format is also included at
[examples/metrics-snapshot.txt](examples/metrics-snapshot.txt).

## Flags

| Flag | Default | Description |
| --- | --- | --- |
| `-cgroup` | `/sys/fs/cgroup` | Root cgroup v2 path to attach to |
| `-metrics-addr` | `:2112` | Prometheus listen address |
| `-v` | `false` | Log every DNS event |
| `-per-domain-metrics` | `false` | Per-domain counters (high cardinality) |

## Known limitations (v1)

- **UDP only.** TCP DNS (and its 2-byte length prefix / multi-segment
  reassembly) is not decoded yet.
- **IPv4 only** on the wire (it still records AAAA answer records).
- **Node-scoped.** One agent covers a whole node via the root cgroup; it does not
  see other nodes' traffic (run it as the DaemonSet, one agent per node).
- **Observe-only** — no blocking.

## Roadmap

- IPv6 + TCP DNS parsing.
- Process attribution (PID/comm) — on the `cgroup/skb` egress hook the query runs
  in the sending process's context, so `bpf_get_current_pid_tgid()` /
  `bpf_get_current_comm()` are available.
- Optional inline enforcement (allow/deny list) — moving toward domain/FQDN-based
  policy, which is where a proxy or an inline verdict becomes necessary.
- Pod metadata enrichment for the Kubernetes DaemonSet (see "Run on a kind
  cluster" — the DaemonSet itself is already included).
- `PROG_ATTACH` fallback for kernels without bpf_link cgroup attach (< 5.7).

## Layout

```
bpf/dns.bpf.c            eBPF program (cgroup/skb): validate + copy raw DNS
gen.go                   go:generate directive for bpf2go
main.go                  loader, cgroup attach, ring buffer loop, de-dup, metrics
internal/dns/parse.go    DNS wire-format decoder (name decompression)
internal/metrics/        Prometheus collectors
Dockerfile               multi-stage build (compiles eBPF + static binary)
deploy/kind-config.yaml  kind cluster definition
deploy/daemonset.yaml    privileged, hostNetwork DaemonSet + metrics Service
deploy/prometheus.yaml   in-cluster Prometheus (RBAC + scrape config + UI)
examples/                captured /metrics text + Prometheus UI screenshot
lima.yaml                Linux VM for macOS (bare-host workflow)
Makefile                 deps / generate / build / run / docker / kind
```
