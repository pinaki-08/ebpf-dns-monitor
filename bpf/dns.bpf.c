// SPDX-License-Identifier: GPL-2.0
//
// Passive DNS monitor attached at the cgroup/skb egress + ingress hooks.
//
// Design note (the whole point of this project):
//   DNS-policy systems typically parse DNS in a *userspace proxy* because fully
//   decoding DNS names (compression pointers, EDNS0, TCP reassembly) inside the
//   eBPF verifier is painful. Here we take the opposite trade-off: the kernel
//   program only validates that a packet is DNS-over-UDP and copies the raw DNS
//   message into a ring buffer. All name decompression happens in Go userspace,
//   where loops and pointers are free. We never redirect or proxy the packet, so
//   we add almost no latency and are not in the enforcement data path.
//
//   The hook is cgroup/skb (not tc), so a single program attached to the root
//   cgroup observes DNS for every process on the node regardless of interface:
//   pod->CoreDNS on the CNI veths, node-local lookups on lo, and egress to
//   external resolvers. Because it runs at the socket layer, skb->data starts at
//   the IP header -- there is no Ethernet header to skip.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IPPROTO_UDP 17
#define DNS_PORT 53
#define MAX_DNS 512
// cgroup/skb runs at L3, so skb->data starts at the IP header (no Ethernet).
#define IP_OFF 0
// cgroup/skb verdict: 1 lets the packet pass, 0 DROPS it. We are observe-only,
// so every return path must be CG_ALLOW -- returning 0 anywhere would black-hole
// that DNS packet for the whole node.
#define CG_ALLOW 1

char LICENSE[] SEC("license") = "GPL";

// Layout is shared with Go via bpf2go's `-type dns_event`.
// All multi-byte scalars are stored in HOST byte order so Go can read them with
// binary.LittleEndian. IP addresses are stored as raw octets (network order),
// which is already the human-readable a.b.c.d ordering.
struct dns_event {
	__u64 timestamp_ns;
	__u8  saddr[4];
	__u8  daddr[4];
	__u16 sport;
	__u16 dport;
	__u16 dns_id;
	__u16 flags;      // raw DNS flags word (QR/opcode/rcode live here)
	__u16 qdcount;
	__u16 ancount;
	__u8  is_response; // derived from the QR bit
	__u8  ip_proto;
	__u16 payload_len; // number of valid bytes in payload[]
	__u8  payload[MAX_DNS];
};

// Force the struct into the object's BTF so bpf2go's `-type dns_event` can
// extract it. Without a global reference, -O2 may keep it out of BTF.
const struct dns_event *unused_dns_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // 16 MiB
} events SEC(".maps");

static __always_inline int handle(struct __sk_buff *skb)
{
	// cgroup/skb starts at the IP header. First byte is version(4) + IHL(4).
	__u8 verihl;
	if (bpf_skb_load_bytes(skb, IP_OFF, &verihl, 1) < 0)
		return CG_ALLOW;
	if ((verihl >> 4) != 4)
		return CG_ALLOW; // IPv4 only for now; IPv6 is a roadmap item
	__u8 ihl = (verihl & 0x0F) * 4;
	if (ihl < 20)
		return CG_ALLOW;

	__u8 proto;
	if (bpf_skb_load_bytes(skb, IP_OFF + 9, &proto, 1) < 0)
		return CG_ALLOW;
	if (proto != IPPROTO_UDP)
		return CG_ALLOW; // UDP only; TCP DNS is a roadmap item

	// Skip fragmented datagrams (MF bit or non-zero fragment offset).
	__u16 frag;
	if (bpf_skb_load_bytes(skb, IP_OFF + 6, &frag, sizeof(frag)) < 0)
		return CG_ALLOW;
	if (frag & bpf_htons(0x2000 | 0x1FFF))
		return CG_ALLOW;

	__u8 saddr[4], daddr[4];
	if (bpf_skb_load_bytes(skb, IP_OFF + 12, saddr, 4) < 0)
		return CG_ALLOW;
	if (bpf_skb_load_bytes(skb, IP_OFF + 16, daddr, 4) < 0)
		return CG_ALLOW;

	__u32 l4 = IP_OFF + ihl;

	__be16 sport_n, dport_n;
	if (bpf_skb_load_bytes(skb, l4, &sport_n, sizeof(sport_n)) < 0)
		return CG_ALLOW;
	if (bpf_skb_load_bytes(skb, l4 + 2, &dport_n, sizeof(dport_n)) < 0)
		return CG_ALLOW;
	if (sport_n != bpf_htons(DNS_PORT) && dport_n != bpf_htons(DNS_PORT))
		return CG_ALLOW;

	__u32 dns_off = l4 + 8; // UDP header is 8 bytes
	// Need at least a full 12-byte DNS header; guards against len underflow.
	if (skb->len < dns_off + 12)
		return CG_ALLOW;

	struct {
		__be16 id, flags, qd, an, ns, ar;
	} dnsh;
	if (bpf_skb_load_bytes(skb, dns_off, &dnsh, sizeof(dnsh)) < 0)
		return CG_ALLOW;

	// Bound the copy length for the verifier. The mask must come FIRST (before
	// any clamp) or clang folds it away, leaving the length register tainted
	// and triggering "R4 min value is negative". MAX_DNS is a power of two, so
	// this yields a provable range of [0, MAX_DNS-1]; for the common case
	// (payload < 512 bytes) copy_len equals the real payload length.
	__u32 copy_len = (skb->len - dns_off) & (MAX_DNS - 1);
	// Exclude zero so bpf_skb_load_bytes gets a provable [1, MAX_DNS-1] length
	// (the verifier rejects a possibly zero-sized read).
	if (copy_len == 0)
		return CG_ALLOW;

	struct dns_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return CG_ALLOW;

	e->timestamp_ns = bpf_ktime_get_ns();
	__builtin_memcpy(e->saddr, saddr, 4);
	__builtin_memcpy(e->daddr, daddr, 4);
	e->sport = bpf_ntohs(sport_n);
	e->dport = bpf_ntohs(dport_n);
	e->dns_id = bpf_ntohs(dnsh.id);
	e->flags = bpf_ntohs(dnsh.flags);
	e->qdcount = bpf_ntohs(dnsh.qd);
	e->ancount = bpf_ntohs(dnsh.an);
	e->is_response = (bpf_ntohs(dnsh.flags) >> 15) & 1;
	e->ip_proto = proto;
	e->payload_len = (__u16)copy_len;

	// Zero the buffer so we never leak stale ring-buffer bytes to userspace.
	__builtin_memset(e->payload, 0, sizeof(e->payload));
	if (bpf_skb_load_bytes(skb, dns_off, e->payload, copy_len) < 0) {
		bpf_ringbuf_discard(e, 0);
		return CG_ALLOW;
	}

	bpf_ringbuf_submit(e, 0);
	return CG_ALLOW;
}

// One program per direction, both calling the same handler. Egress catches
// queries leaving a process (and node-local responses from CoreDNS); ingress
// catches responses arriving from off-node resolvers. Userspace de-dups the
// node-local packets that legitimately appear on both hooks.
SEC("cgroup_skb/egress")
int dns_egress(struct __sk_buff *skb)
{
	return handle(skb);
}

SEC("cgroup_skb/ingress")
int dns_ingress(struct __sk_buff *skb)
{
	return handle(skb);
}
