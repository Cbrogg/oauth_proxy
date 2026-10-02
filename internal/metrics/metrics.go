package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type Registry struct {
	requests       *prometheus.CounterVec
	authFailures   *prometheus.CounterVec
	proxyDuration  *prometheus.HistogramVec
	userinfoHits   prometheus.Counter
	userinfoMisses prometheus.Counter
}

var (
	global     *Registry
	globalOnce sync.Once
)

func Global() *Registry {
	globalOnce.Do(func() {
		global = New()
	})
	return global
}

func New() *Registry {
	return &Registry{
		requests: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "facade_http_requests_total",
			Help: "Total HTTP requests",
		}, []string{"route", "method", "status"}),
		authFailures: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "facade_auth_failures_total",
			Help: "Authentication failures by reason",
		}, []string{"reason"}),
		proxyDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "facade_proxy_duration_seconds",
			Help:    "LiteLLM proxy duration",
			Buckets: prometheus.DefBuckets,
		}, []string{"toolset"}),
		userinfoHits: promauto.NewCounter(prometheus.CounterOpts{
			Name: "facade_userinfo_cache_hits_total",
			Help: "Userinfo cache hits",
		}),
		userinfoMisses: promauto.NewCounter(prometheus.CounterOpts{
			Name: "facade_userinfo_cache_misses_total",
			Help: "Userinfo cache misses",
		}),
	}
}

func (r *Registry) AuthFailure(reason string) {
	r.authFailures.WithLabelValues(reason).Inc()
}

func (r *Registry) ObserveProxy(toolset string, d time.Duration) {
	r.proxyDuration.WithLabelValues(toolset).Observe(d.Seconds())
}

func (r *Registry) IncRequest(route, method, status string) {
	r.requests.WithLabelValues(route, method, status).Inc()
}

func (r *Registry) UserinfoHit()  { r.userinfoHits.Inc() }
func (r *Registry) UserinfoMiss() { r.userinfoMisses.Inc() }
