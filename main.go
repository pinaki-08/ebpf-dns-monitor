// Command dnsmon is a passive, eBPF-based DNS monitor.
//
// Unlike Cilium's DNS-based policy path (which redirects port-53 traffic to a
// userspace proxy for parsing and enforcement), dnsmon attaches passive tc/TCX
// programs that copy DNS packets into a ring buffer. The kernel side never
// proxies or blocks; all name decompression happens here in userspace.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
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
	iface := flag.String("iface", "", "network interface to attach to (default: auto-detect)")
	metricsAddr := flag.String("metrics-addr", ":2112", "listen address for the Prometheus /metrics endpoint")
	verbose := flag.Bool("v", false, "log every DNS event to stderr")
	perDomain := flag.Bool("per-domain-metrics", false, "emit per-domain query counters (WARNING: high cardinality)")
	flag.Parse()

	ifaceName := *iface
	if ifaceName == "" {
		ifaceName = defaultIface()
	}
	if ifaceName == "" {
		log.Fatal("could not auto-detect an interface; pass -iface")
	}
	nic, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("interface %q: %v", ifaceName, err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock rlimit: %v", err)
	}

	var objs dnsmonObjects
	if err := loadDnsmonObjects(&objs, nil); err != nil {
		log.Fatalf("load eBPF objects: %v", err)
	}
	defer objs.Close()

	// TCX requires a Linux kernel >= 6.6.
	egress, err := link.AttachTCX(link.TCXOptions{
		Interface: nic.Index,
		Program:   objs.DnsMonitor,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Fatalf("attach tc egress (needs kernel >= 6.6): %v", err)
	}
	defer egress.Close()

	ingress, err := link.AttachTCX(link.TCXOptions{
		Interface: nic.Index,
		Program:   objs.DnsMonitor,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Fatalf("attach tc ingress (needs kernel >= 6.6): %v", err)
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

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopper
		log.Println("shutting down...")
		_ = rd.Close()
		_ = srv.Close()
	}()

	log.Printf("monitoring DNS on %s (ifindex %d)", ifaceName, nic.Index)
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
		handleEvent(&ev, m, trk, *verbose)
	}
}

func handleEvent(ev *dnsmonDnsEvent, m *appmetrics.Metrics, trk *tracker, verbose bool) {
	m.Events.Inc()

	plen := int(ev.PayloadLen)
	if plen > len(ev.Payload) {
		plen = len(ev.Payload)
	}
	if plen < 12 {
		m.ParseErrors.Inc()
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

// defaultIface returns the interface backing the default IPv4 route.
func defaultIface() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	if !sc.Scan() { // header
		return ""
	}
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[1] == "00000000" { // destination 0.0.0.0
			return fields[0]
		}
	}
	return ""
}
