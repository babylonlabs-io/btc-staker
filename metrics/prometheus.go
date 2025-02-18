package metrics

import (
	"errors"
	"net/http"

	//nolint:revive
	_ "net/http/pprof"
	"regexp"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

const EnvSecretJWT = "JWT_SECRET"

func Start(logger *logrus.Logger, addr string, reg *prometheus.Registry) {
	svr := Server(logger, addr, reg)

	go func() {
		err := svr.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Errorf("prometheus server got err: %v", err)
		}
	}()
}

func Server(logger *logrus.Logger, addr string, reg *prometheus.Registry) *http.Server {
	// Add Go module build info.
	reg.MustRegister(collectors.NewBuildInfoCollector())
	reg.MustRegister(collectors.NewGoCollector(
		collectors.WithGoCollectorRuntimeMetrics(collectors.GoRuntimeMetricsRule{Matcher: regexp.MustCompile("/.*")})),
	)

	mux := http.NewServeMux()

	// Expose the registered metrics via HTTP.
	mux.Handle("/metrics", promhttp.HandlerFor(
		reg,
		promhttp.HandlerOpts{
			// Opt into OpenMetrics to support exemplars.
			EnableOpenMetrics: true,
		},
	))

	logger.Infof("Successfully started Prometheus metrics server at %s", addr)

	return &http.Server{Addr: addr, Handler: mux}
}
