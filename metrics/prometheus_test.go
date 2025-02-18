package metrics_test

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"testing"
	"time"

	//nolint:revive

	"net/http"
	"net/http/httptest"
	_ "net/http/pprof"

	"github.com/stretchr/testify/require"

	"github.com/babylonlabs-io/babylon/testutil/datagen"
	"github.com/babylonlabs-io/btc-staker/itest/testutil"
	"github.com/babylonlabs-io/btc-staker/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

func TestJWTAuthMiddleware(t *testing.T) {
	r := rand.New(rand.NewSource(time.Now().Unix()))
	jwtSecret := datagen.GenRandomHexStr(r, 10)

	t.Setenv(metrics.EnvSecretJWT, jwtSecret)
	addr := fmt.Sprintf("127.0.0.1:%d", testutil.AllocateUniquePort(t))
	testRegistry := prometheus.NewRegistry()

	server := metrics.Server(logrus.New(), addr, testRegistry)

	// Use httptest to simulate a real HTTP server
	testServer := httptest.NewServer(server.Handler)
	defer testServer.Close()

	validToken, err := metrics.GenerateToken(time.Hour, jwtSecret)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, testServer.URL+"/metrics", nil)
	require.NoError(t, err)

	// Add the JWT Bearer token in Authorization header
	req.Header.Set("Authorization", "Bearer "+validToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()

	fullBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	bodyString := string(fullBody)
	require.True(t, strings.Contains(bodyString, "metrics"))
}
