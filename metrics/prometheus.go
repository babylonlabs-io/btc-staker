package metrics

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	//nolint:revive
	_ "net/http/pprof"
	"regexp"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"

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
	mux.Handle("/metrics", jwtAuth(logger, promhttp.HandlerFor(
		reg,
		promhttp.HandlerOpts{
			// Opt into OpenMetrics to support exemplars.
			EnableOpenMetrics: true,
		},
	)))

	logger.Infof("Successfully started Prometheus metrics server at %s", addr)

	return &http.Server{Addr: addr, Handler: mux}
}

func jwtSecret(logger *logrus.Logger) ([]byte, error) {
	err := godotenv.Load()
	if err != nil {
		logger.Warnf("Error loading .env file to get metrics: %v", err)
	}

	secret := os.Getenv(EnvSecretJWT)
	if len(secret) == 0 {
		return nil, fmt.Errorf("failed to load env %s", EnvSecretJWT)
	}

	return []byte(secret), nil
}

// GenerateToken a JWT token
func GenerateToken(timeValid time.Duration, secret string) (string, error) {
	claims := jwt.MapClaims{
		"exp": time.Now().Add(timeValid).Unix(), // Expiry time
		"iat": time.Now().Unix(),                // Issued at
		"sub": "prometheus",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// jwtAuth JWT Middleware for authentication
func jwtAuth(logger *logrus.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		// Expect "Bearer <token>"
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			http.Error(w, "Invalid Authorization format", http.StatusUnauthorized)
			return
		}

		// Parse and validate JWT
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret(logger)
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
