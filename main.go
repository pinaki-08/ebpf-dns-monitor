// Command dnsmon is a passive, eBPF-based DNS monitor.
//
// Unlike DNS-policy systems that redirect port-53 traffic to a userspace proxy
// for parsing and enforcement, dnsmon attaches passive cgroup/skb programs at
// the root cgroup that copy DNS packets into a ring buffer. The kernel side
// never proxies or blocks; all name decompression happens here in userspace.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"hash/fnv"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/example/dnsmon/internal/dns"
	appmetrics "github.com/example/dnsmon/internal/metrics"
)

func main() {
	cgroupPath := flag.String("cgroup", "/sys/fs/cgroup", "root cgroup v2 path to attach the cgroup/skb programs to")
	metricsAddr := flag.String("metrics-addr", ":2112", "listen address for the Prometheus /metrics endpoint")
	verbose := flag.Bool("v", false, "log every DNS event to stderr")
	perDomain := flag.Bool("per-domain-metrics", false, "emit per-domain query counters (WARNING: high cardinality)")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock rlimit: %v", err)
	}

	var objs dnsmonObjects
	if err := loadDnsmonObjects(&objs, nil); err != nil {
		log.Fatalf("load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Attach at the root cgroup so one program sees DNS for every process on the
	// node, on any interface: pod->CoreDNS on the CNI veths, node-local lookups
	// on lo, and egress to external resolvers. cgroup/skb needs a Linux kernel
	// >= 5.7 for bpf_link-based attach.
	egress, err := link.AttachCgroup(link.CgroupOptions{
		Path:    *cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.DnsEgress,
	})
	if err != nil {
		log.Fatalf("attach cgroup egress at %s: %v", *cgroupPath, err)
	}
	defer egress.Close()

	ingress, err := link.AttachCgroup(link.CgroupOptions{
		Path:    *cgroupPath,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: objs.DnsIngress,
	})
	if err != nil {
		log.Fatalf("attach cgroup ingress at %s: %v", *cgroupPath, err)
	}
	defer ingress.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("open ring buffer: %v", err)
	}
	defer rd.Close()

	reg := prometheus.NewRegistry()
	m := appmetrics.New(reg, *perDomain)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	srv := &http.Server{Addr: *metricsAddr, Handler: mux}
	go func() {
		log.Printf("serving metrics at %s/metrics", *metricsAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("metrics server: %v", err)
		}
	}()

	trk := newTracker()
	go trk.reap()

	dd := newDedup()
	go dd.reap()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopper
		log.Println("shutting down...")
		_ = rd.Close()
		_ = srv.Close()
	}()

	log.Printf("monitoring DNS via cgroup/skb at %s", *cgroupPath)
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("ringbuf read: %v", err)
			continue
		}

		var ev dnsmonDnsEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			m.ParseErrors.Inc()
			continue
		}
		handleEvent(&ev, m, trk, dd, *verbose)
	}
}

func handleEvent(ev *dnsmonDnsEvent, m *appmetrics.Metrics, trk *tracker, dd *dedup, verbose bool) {
	m.Events.Inc()

	plen := int(ev.PayloadLen)
	if plen > len(ev.Payload) {
		plen = len(ev.Payload)
	}
	if plen < 12 {
		m.ParseErrors.Inc()
		return
	}

	// cgroup/skb fires on both the sender's egress and the receiver's ingress,
	// so node-local DNS (pod<->CoreDNS) arrives twice. The DNS payload is
	// byte-identical on both copies (NAT rewrites L3 addresses, not the DNS
	// message), so collapse duplicates seen within a short window before we
	// touch any counters.
	if dd.duplicate(ev.IsResponse, ev.Payload[:plen]) {
		return
	}

	msg, _ := dns.Decode(ev.Payload[:plen]) // partial decode is tolerated
	if msg == nil {
		m.ParseErrors.Inc()
		return
	}

	src := net.IPv4(ev.Saddr[0], ev.Saddr[1], ev.Saddr[2], ev.Saddr[3])
	dst := net.IPv4(ev.Daddr[0], ev.Daddr[1], ev.Daddr[2], ev.Daddr[3])
	qtype := dns.TypeString(msg.QType)

	if ev.IsResponse == 0 {
		m.RecordQuery(qtype, msg.QName)

		var ip [4]byte
		copy(ip[:], ev.Saddr[:]) // client == source of the query
		trk.put(flowKey{id: ev.DnsId, ip: ip, port: ev.Sport}, qinfo{
			tsNs:  ev.TimestampNs,
			wall:  time.Now(),
			qname: msg.QName,
		})

		if verbose {
			log.Printf("QUERY  %s:%d -> %s:%d id=0x%04x %-5s %s",
				src, ev.Sport, dst, ev.Dport, ev.DnsId, qtype, msg.QName)
		}
		return
	}

	rcode := dns.RcodeString(msg.Rcode)
	m.RecordResponse(rcode)

	var ip [4]byte
	copy(ip[:], ev.Daddr[:]) // client == destination of the response
	q, ok := trk.take(flowKey{id: ev.DnsId, ip: ip, port: ev.Dport})

	if verbose {
		name := msg.QName
		if ok {
			name = q.qname
		}
		if ok {
			dur := float64(ev.TimestampNs-q.tsNs) / 1e6 // ms
			log.Printf("RESP   %s:%d -> %s:%d id=0x%04x %-8s %s %v (%.2fms)",
				src, ev.Sport, dst, ev.Dport, ev.DnsId, rcode, name, msg.Answers, dur)
		} else {
			log.Printf("RESP   %s:%d -> %s:%d id=0x%04x %-8s %s %v",
				src, ev.Sport, dst, ev.Dport, ev.DnsId, rcode, name, msg.Answers)
		}
	}

	if ok {
		if dur := float64(ev.TimestampNs-q.tsNs) / 1e9; dur >= 0 && dur < 3600 {
			m.Duration.Observe(dur)
		}
	}
}

// --- query/response correlation for latency ---------------------------------

type flowKey struct {
	id   uint16
	ip   [4]byte
	port uint16
}

type qinfo struct {
	tsNs  uint64
	wall  time.Time
	qname string
}

type tracker struct {
	mu sync.Mutex
	m  map[flowKey]qinfo
}

func newTracker() *tracker { return &tracker{m: make(map[flowKey]qinfo)} }

func (t *tracker) put(k flowKey, q qinfo) {
	t.mu.Lock()
	t.m[k] = q
	t.mu.Unlock()
}

func (t *tracker) take(k flowKey) (qinfo, bool) {
	t.mu.Lock()
	q, ok := t.m[k]
	if ok {
		delete(t.m, k)
	}
	t.mu.Unlock()
	return q, ok
}

// reap drops unmatched queries so the map cannot grow without bound.
func (t *tracker) reap() {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for range tick.C {
		cutoff := time.Now().Add(-15 * time.Second)
		t.mu.Lock()
		for k, v := range t.m {
			if v.wall.Before(cutoff) {
				delete(t.m, k)
			}
		}
		t.mu.Unlock()
	}
}

// --- de-duplication of the egress/ingress double-observation ---------------
//
// A node-local DNS datagram (e.g. pod<->CoreDNS on the same node) is seen once
// as the sender's cgroup egress and once as the receiver's cgroup ingress. Both
// copies carry an identical DNS payload, so we hash (is_response, payload) and
// drop a repeat seen within dedupTTL.

const dedupTTL = 2 * time.Second

type dedup struct {
	mu sync.Mutex
	m  map[uint64]time.Time
}

func newDedup() *dedup { return &dedup{m: make(map[uint64]time.Time)} }

func (d *dedup) duplicate(isResponse uint8, payload []byte) bool {
	h := fnv.New64a()
	_, _ = h.Write([]byte{isResponse})
	_, _ = h.Write(payload)
	key := h.Sum64()

	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.m[key]; ok && now.Sub(t) < dedupTTL {
		return true
	}
	d.m[key] = now
	return false
}

// reap keeps the dedup map from growing without bound.
func (d *dedup) reap() {
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for range tick.C {
		cutoff := time.Now().Add(-dedupTTL)
		d.mu.Lock()
		for k, t := range d.m {
			if t.Before(cutoff) {
				delete(d.m, k)
			}
		}
		d.mu.Unlock()
	}
}
