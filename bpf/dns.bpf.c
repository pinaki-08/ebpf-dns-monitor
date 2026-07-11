// SPDX-License-Identifier: GPL-2.0
//
// Passive DNS monitor attached at the tc (TCX) egress + ingress hooks.
//
// Design note (the whole point of this project):
//   Cilium parses DNS in a *userspace proxy* because fully decoding DNS names
//   (compression pointers, EDNS0, TCP reassembly) inside the eBPF verifier is
//   painful. Here we do the opposite trade-off: the kernel program only
//   validates that a packet is DNS-over-UDP and copies the raw DNS message into
//   a ring buffer. All name decompression happens in Go userspace, where loops
//   and pointers are free. We never redirect or proxy the packet, so we add
//   almost no latency and are not in the enforcement data path.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17
#define DNS_PORT 53
#define MAX_DNS 512
#define TC_ACT_OK 0

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
	__u16 h_proto;
	// EtherType lives at offset 12 in the Ethernet header.
	if (bpf_skb_load_bytes(skb, 12, &h_proto, sizeof(h_proto)) < 0)
		return TC_ACT_OK;
	if (h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	// IPv4: first byte holds version(4) + IHL(4). IHL is in 32-bit words.
	__u8 verihl;
	if (bpf_skb_load_bytes(skb, ETH_HLEN, &verihl, 1) < 0)
		return TC_ACT_OK;
	__u8 ihl = (verihl & 0x0F) * 4;
	if (ihl < 20)
		return TC_ACT_OK;

	__u8 proto;
	if (bpf_skb_load_bytes(skb, ETH_HLEN + 9, &proto, 1) < 0)
		return TC_ACT_OK;
	if (proto != IPPROTO_UDP)
		return TC_ACT_OK; // v1 handles UDP only; TCP DNS is a roadmap item

	// Skip fragmented datagrams (MF bit or non-zero fragment offset).
	__u16 frag;
	if (bpf_skb_load_bytes(skb, ETH_HLEN + 6, &frag, sizeof(frag)) < 0)
		return TC_ACT_OK;
	if (frag & bpf_htons(0x2000 | 0x1FFF))
		return TC_ACT_OK;

	__u8 saddr[4], daddr[4];
	if (bpf_skb_load_bytes(skb, ETH_HLEN + 12, saddr, 4) < 0)
		return TC_ACT_OK;
	if (bpf_skb_load_bytes(skb, ETH_HLEN + 16, daddr, 4) < 0)
		return TC_ACT_OK;

	__u32 l4 = ETH_HLEN + ihl;

	__be16 sport_n, dport_n;
	if (bpf_skb_load_bytes(skb, l4, &sport_n, sizeof(sport_n)) < 0)
		return TC_ACT_OK;
	if (bpf_skb_load_bytes(skb, l4 + 2, &dport_n, sizeof(dport_n)) < 0)
		return TC_ACT_OK;
	if (sport_n != bpf_htons(DNS_PORT) && dport_n != bpf_htons(DNS_PORT))
		return TC_ACT_OK;

	__u32 dns_off = l4 + 8; // UDP header is 8 bytes
	// Need at least a full 12-byte DNS header; guards against len underflow.
	if (skb->len < dns_off + 12)
		return TC_ACT_OK;

	struct {
		__be16 id, flags, qd, an, ns, ar;
	} dnsh;
	if (bpf_skb_load_bytes(skb, dns_off, &dnsh, sizeof(dnsh)) < 0)
		return TC_ACT_OK;

	__u32 copy_len = skb->len - dns_off;
	if (copy_len > MAX_DNS - 1)
		copy_len = MAX_DNS - 1; // bound for the verifier: copy_len in [12, 511]

	struct dns_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return TC_ACT_OK;

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
		return TC_ACT_OK;
	}

	bpf_ringbuf_submit(e, 0);
	return TC_ACT_OK;
}

SEC("tc")
int dns_monitor(struct __sk_buff *skb)
{
	return handle(skb);
}
