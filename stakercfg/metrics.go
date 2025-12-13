package stakercfg

import (
	"fmt"
	"net"
)

const (
	defaultMetricsServerPort = 2112
	defaultMetricsHost       = "127.0.0.1"
)

// MetricsConfig defines the server's basic configuration
type MetricsConfig struct {
	// Enalbed if the prometheus server should be enabled
	Enabled bool `long:"enabled" description:"if it should be enabled."`
	// IP of the prometheus server
	Host string `long:"host" description:"host of prometheus server."`
	// Port of the prometheus server
	ServerPort int `long:"server-pornt" description:"port of prometheus server."`
}

// Validate validates the metrics configuration.
func (cfg *MetricsConfig) Validate() error {
	if cfg.ServerPort < 0 || cfg.ServerPort > 65535 {
		return fmt.Errorf("invalid port: %d", cfg.ServerPort)
	}

	ip := net.ParseIP(cfg.Host)
	if ip == nil {
		return fmt.Errorf("invalid host: %v", cfg.Host)
	}

	return nil
}

// DefaultMetricsConfig returns a default metrics configuration.
func DefaultMetricsConfig() MetricsConfig {
	return MetricsConfig{
		Enabled:    false,
		ServerPort: defaultMetricsServerPort,
		Host:       defaultMetricsHost,
	}
}
