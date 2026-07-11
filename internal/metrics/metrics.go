// Package metrics holds the Prometheus collectors exposed on /metrics.
package metrics

import "github.com/prometheus/client_golang/prometheus"

// Metrics bundles every collector the monitor updates.
type Metrics struct {
	Queries     *prometheus.CounterVec // by qtype
	Responses   *prometheus.CounterVec // by rcode
	Duration    prometheus.Histogram   // query -> response latency
	Events      prometheus.Counter     // raw events read from the ring buffer
	ParseErrors prometheus.Counter

	perDomain *prometheus.CounterVec
	domainOn  bool
}

// New builds and registers all collectors. When perDomain is true an extra,
// high-cardinality counter labelled by domain name is exposed.
func New(reg prometheus.Registerer, perDomain bool) *Metrics {
	m := &Metrics{
		Queries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "dnsmon", Name: "queries_total",
			Help: "DNS queries observed, by query type.",
		}, []string{"qtype"}),
		Responses: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "dnsmon", Name: "responses_total",
			Help: "DNS responses observed, by response code.",
		}, []string{"rcode"}),
		Duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "dnsmon", Name: "query_duration_seconds",
			Help:    "Latency between a DNS query and its matching response.",
			Buckets: prometheus.ExponentialBuckets(0.0005, 2, 12), // 0.5ms .. ~2s
		}),
		Events: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "dnsmon", Name: "events_total",
			Help: "Raw DNS events received from the kernel ring buffer.",
		}),
		ParseErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "dnsmon", Name: "parse_errors_total",
			Help: "Events that could not be decoded.",
		}),
	}
	reg.MustRegister(m.Queries, m.Responses, m.Duration, m.Events, m.ParseErrors)

	if perDomain {
		m.perDomain = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "dnsmon", Name: "queries_by_domain_total",
			Help: "DNS queries by domain name (WARNING: high cardinality).",
		}, []string{"domain", "qtype"})
		reg.MustRegister(m.perDomain)
		m.domainOn = true
	}
	return m
}

// RecordQuery accounts for a single observed DNS query.
func (m *Metrics) RecordQuery(qtype, name string) {
	m.Queries.WithLabelValues(qtype).Inc()
	if m.domainOn {
		m.perDomain.WithLabelValues(name, qtype).Inc()
	}
}

// RecordResponse accounts for a single observed DNS response.
func (m *Metrics) RecordResponse(rcode string) {
	m.Responses.WithLabelValues(rcode).Inc()
}
