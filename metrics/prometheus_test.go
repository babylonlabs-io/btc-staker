package metrics_test

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	//nolint:revive

	"net/http"
	"net/http/httptest"
	_ "net/http/pprof"

	"github.com/stretchr/testify/require"

	"github.com/babylonlabs-io/btc-staker/itest/testutil"
	"github.com/babylonlabs-io/btc-staker/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

func TestMetrics(t *testing.T) {
	t.Parallel()
	addr := fmt.Sprintf("127.0.0.1:%d", testutil.AllocateUniquePort(t))
	testRegistry := prometheus.NewRegistry()

	server := metrics.Server(logrus.New(), addr, testRegistry)

	// Use httptest to simulate a real HTTP server
	testServer := httptest.NewServer(server.Handler)
	defer testServer.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, testServer.URL+"/metrics", nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()

	fullBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	bodyString := string(fullBody)
	require.True(t, strings.Contains(bodyString, "metrics"))
}
