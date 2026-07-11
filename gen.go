package main

// bpf2go compiles bpf/dns.bpf.c with clang and generates Go bindings
// (dnsmon_bpfel.go + dnsmon_bpfel.o). The `-type dns_event` flag emits a
// matching Go struct (dnsmonDnsEvent) from the C type via BTF.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -type dns_event dnsmon ./bpf/dns.bpf.c -- -I./bpf
